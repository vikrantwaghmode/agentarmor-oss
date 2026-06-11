package main

// MCP server registry & credential brokering — Zero-Trust MCP Brokering, v1.
//
// AgentArmor's tool-call protocol is {"tool": "...", "args": {...}} (see the
// risk-scoring block in scanPayload). When a tool call targets a tool that's
// registered to an MCP server in policy, AgentArmor resolves that server's
// credential and injects it into args as _mcp_auth_header_name /
// _mcp_auth_header_value (+ _mcp_server_id) — so the agent never has to hold,
// store, or leak the MCP server's actual API key. Credentials are read from
// the process environment (populated via AgentArmor's secrets vault
// integration — see secrets.go), never from policy.yaml itself.
//
// This is "tagging only": AgentArmor stays a single-target reverse proxy. The
// mcp_servers registry maps tool names to credential metadata; it does not
// change where requests are forwarded.
//
// If require_scope is enabled, a session must hold the mcp:any scope (or the
// per-server mcp:<server-id> scope) to invoke a tool registered to an MCP
// server — sessions without it are blocked before the call is forwarded.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// ─── Policy section ───────────────────────────────────────────────────────────

// MCPServersConfig is the mcp_servers policy block.
type MCPServersConfig struct {
	Enabled      bool        `yaml:"enabled" json:"enabled"`
	RequireScope bool        `yaml:"require_scope" json:"require_scope"`
	Servers      []MCPServer `yaml:"servers" json:"servers"`
}

// MCPServer is one registered MCP server: which tools it owns, and how
// AgentArmor authenticates to it on the agent's behalf.
type MCPServer struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	URL         string   `yaml:"url" json:"url"`
	Tools       []string `yaml:"tools" json:"tools"`
	Auth        MCPAuth  `yaml:"auth" json:"auth"`
}

// MCPAuth describes the credential header AgentArmor injects into tool calls
// routed to this server. Only the names of environment variables holding
// secret values are stored in policy — never the secrets themselves.
type MCPAuth struct {
	Type        string `yaml:"type" json:"type"` // bearer | basic | header
	HeaderName  string `yaml:"header_name" json:"header_name"`
	TokenEnv    string `yaml:"token_env" json:"token_env"`
	UsernameEnv string `yaml:"username_env" json:"username_env"`
	PasswordEnv string `yaml:"password_env" json:"password_env"`
	ValueEnv    string `yaml:"value_env" json:"value_env"`
	ValuePrefix string `yaml:"value_prefix" json:"value_prefix"`
}

// ─── lookup & scope ───────────────────────────────────────────────────────────

// findMCPServerForTool returns the registered server that owns toolName, or nil.
func findMCPServerForTool(cfg MCPServersConfig, toolName string) *MCPServer {
	for i := range cfg.Servers {
		for _, t := range cfg.Servers[i].Tools {
			if t == toolName {
				return &cfg.Servers[i]
			}
		}
	}
	return nil
}

// sessionHasMCPAccess returns true when the session holds mcp:any or the
// per-server mcp:<server-id> scope.
func sessionHasMCPAccess(tnt *Tenant, sessionKey, serverID string) bool {
	return sessionHasAnyScope(tnt, sessionKey, []string{ScopeMCPAny, "mcp:" + serverID})
}

// ─── credential resolution ─────────────────────────────────────────────────────

// resolveMCPCredential turns an MCPAuth block into an HTTP header name/value
// pair, reading secret values from the process environment. Returns
// ok=false if the referenced env var(s) aren't set, so callers can skip
// injection rather than attach an empty credential.
func resolveMCPCredential(auth MCPAuth) (headerName, headerValue string, ok bool) {
	switch strings.ToLower(auth.Type) {
	case "bearer":
		token := os.Getenv(auth.TokenEnv)
		if token == "" {
			return "", "", false
		}
		name := auth.HeaderName
		if name == "" {
			name = "Authorization"
		}
		prefix := auth.ValuePrefix
		if prefix == "" {
			prefix = "Bearer "
		}
		return name, prefix + token, true

	case "basic":
		user := os.Getenv(auth.UsernameEnv)
		pass := os.Getenv(auth.PasswordEnv)
		if user == "" && pass == "" {
			return "", "", false
		}
		name := auth.HeaderName
		if name == "" {
			name = "Authorization"
		}
		return name, "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)), true

	case "header":
		if auth.HeaderName == "" {
			return "", "", false
		}
		val := os.Getenv(auth.ValueEnv)
		if val == "" {
			return "", "", false
		}
		return auth.HeaderName, auth.ValuePrefix + val, true
	}
	return "", "", false
}

// ─── reachability probe (scanner status) ───────────────────────────────────────

// probeMCPServers reports the registry's overall health for the dashboard /
// scanner-status badge. A single unreachable server only ever degrades this
// scanner — it never returns "down", so it can't trip scannerGateReady() and
// block all chat traffic.
func probeMCPServers(cfg MCPServersConfig) (status, detail string) {
	if !cfg.Enabled {
		return "disabled", "enable mcp_servers in policy to broker credentials for registered tool calls"
	}
	if len(cfg.Servers) == 0 {
		return "disabled", "no servers registered — add entries under mcp_servers.servers"
	}

	client := &http.Client{Timeout: 800 * time.Millisecond}
	checked, reachable := 0, 0
	var unreachable []string
	for _, s := range cfg.Servers {
		if s.URL == "" {
			continue
		}
		checked++
		resp, err := client.Get(s.URL)
		if err != nil {
			unreachable = append(unreachable, s.ID)
			continue
		}
		resp.Body.Close()
		reachable++
	}

	if checked == 0 {
		return "active", fmt.Sprintf("%d server(s) registered", len(cfg.Servers))
	}
	if len(unreachable) == 0 {
		return "active", fmt.Sprintf("%d/%d server(s) reachable", reachable, checked)
	}
	return "degraded", fmt.Sprintf("%d/%d reachable — unreachable: %s", reachable, checked, strings.Join(unreachable, ", "))
}

// ─── credential injection ──────────────────────────────────────────────────────

// mcpToolCallEnvelope mirrors the {"tool":"...","args":{...}} shape used by
// AgentArmor's internal tool-call protocol.
type mcpToolCallEnvelope struct {
	Tool string          `json:"tool"`
	Args json.RawMessage `json:"args"`
}

// buildMCPInjectedToolCall returns the JSON for a tool-call envelope with the
// resolved MCP credential merged into args, or ok=false if the credential
// isn't configured (env var unset) or the envelope can't be re-marshalled.
func buildMCPInjectedToolCall(tool string, args json.RawMessage, server *MCPServer) (string, bool) {
	headerName, headerValue, ok := resolveMCPCredential(server.Auth)
	if !ok {
		return "", false
	}

	var argsMap map[string]interface{}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &argsMap); err != nil {
			argsMap = nil
		}
	}
	if argsMap == nil {
		argsMap = make(map[string]interface{})
	}
	argsMap["_mcp_server_id"] = server.ID
	argsMap["_mcp_auth_header_name"] = headerName
	argsMap["_mcp_auth_header_value"] = headerValue

	newArgs, err := json.Marshal(argsMap)
	if err != nil {
		return "", false
	}
	rewritten, err := json.Marshal(mcpToolCallEnvelope{Tool: tool, Args: newArgs})
	if err != nil {
		return "", false
	}
	return string(rewritten), true
}
