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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
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
// block all chat traffic. Servers quarantined by the config-hardening audit
// (see auditMCPServers) also degrade this scanner rather than blocking it.
func probeMCPServers(cfg MCPServersConfig, quarantined map[string]string) (status, detail string) {
	if !cfg.Enabled {
		return "disabled", "enable mcp_servers in policy to broker credentials for registered tool calls"
	}
	if len(cfg.Servers) == 0 {
		return "disabled", "no servers registered — add entries under mcp_servers.servers"
	}

	if len(quarantined) > 0 {
		ids := make([]string, 0, len(quarantined))
		for id := range quarantined {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return "degraded", fmt.Sprintf("%d server(s) quarantined by config-hardening scan: %s", len(quarantined), strings.Join(ids, ", "))
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
// resolved MCP credential and a context-binding token (see "context binding"
// below) merged into args, or ok=false if the credential isn't configured
// (env var unset) or the envelope can't be re-marshalled. contextToken is
// omitted from args if empty.
func buildMCPInjectedToolCall(tool string, args json.RawMessage, server *MCPServer, contextToken string) (string, bool) {
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
	if contextToken != "" {
		argsMap["_mcp_context_token"] = contextToken
	}

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

// ─── configuration hardening audit ─────────────────────────────────────────────
//
// Phase 1.3 of zero-trust MCP brokering: registered servers are checked for
// known-insecure configuration patterns (NeighborJack-style binds to all
// interfaces, path traversal in the server URL, plaintext credentials over
// http to a non-private host, and brokering setups that can never actually
// inject a credential). "critical" findings quarantine the server — scanPayload
// blocks tool calls routed to it until the policy is corrected and reloaded.

// MCPServerFinding describes one configuration-hardening issue found on a
// registered MCP server.
type MCPServerFinding struct {
	ServerID string `json:"server_id"`
	Severity string `json:"severity"` // critical | high | medium | low
	Issue    string `json:"issue"`
}

// auditMCPServerConfig inspects a single registered MCP server and returns
// every configuration-hardening finding for it.
func auditMCPServerConfig(s MCPServer) []MCPServerFinding {
	var findings []MCPServerFinding
	add := func(severity, format string, args ...interface{}) {
		findings = append(findings, MCPServerFinding{ServerID: s.ID, Severity: severity, Issue: fmt.Sprintf(format, args...)})
	}

	if s.ID == "" {
		add("high", "missing 'id' — cannot be targeted by mcp:<id> scopes or quarantined individually")
	}
	if len(s.Tools) == 0 {
		add("low", "no tools registered — this entry has no effect")
	}

	if s.URL == "" {
		add("low", "no url configured — reachability cannot be probed")
	} else if u, err := url.Parse(s.URL); err != nil {
		add("medium", "url %q could not be parsed: %v", s.URL, err)
	} else {
		host := u.Hostname()
		if host == "0.0.0.0" || host == "::" {
			add("critical", "url binds to all interfaces (%s) — exposes the MCP server to the entire local network (NeighborJack-style)", host)
		}
		if u.Scheme == "http" && !isLoopbackOrPrivateHost(host) {
			add("high", "url uses plaintext http:// to a non-private host (%s) — brokered credentials would be sent unencrypted", host)
		}
		if strings.Contains(u.Path, "..") {
			add("critical", "url path %q contains '..' — possible path traversal", u.Path)
		}
	}

	switch strings.ToLower(s.Auth.Type) {
	case "bearer":
		if s.Auth.TokenEnv == "" {
			add("medium", "auth.type=bearer but token_env is not set — credential injection will always be skipped")
		}
	case "basic":
		if s.Auth.UsernameEnv == "" && s.Auth.PasswordEnv == "" {
			add("medium", "auth.type=basic but username_env/password_env are not set — credential injection will always be skipped")
		}
	case "header":
		if s.Auth.HeaderName == "" || s.Auth.ValueEnv == "" {
			add("medium", "auth.type=header requires header_name and value_env — credential injection will always be skipped")
		}
	case "":
		add("medium", "no auth configured — tool calls to this server's tools are forwarded without a brokered credential")
	default:
		add("medium", "unknown auth.type %q — must be bearer, basic, or header", s.Auth.Type)
	}

	return findings
}

// isLoopbackOrPrivateHost reports whether host is localhost or an RFC 1918 /
// loopback / link-local address — i.e. traffic that never leaves the local
// network even over plain http.
func isLoopbackOrPrivateHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // external hostname — treat as non-private
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// auditMCPServers runs auditMCPServerConfig over every registered server and
// returns the full finding list plus the set of server IDs quarantined by a
// "critical" finding (server ID -> first critical issue).
func auditMCPServers(cfg MCPServersConfig) (findings []MCPServerFinding, quarantined map[string]string) {
	quarantined = make(map[string]string)
	for _, s := range cfg.Servers {
		for _, f := range auditMCPServerConfig(s) {
			findings = append(findings, f)
			if f.Severity == "critical" {
				if _, exists := quarantined[f.ServerID]; !exists {
					quarantined[f.ServerID] = f.Issue
				}
			}
		}
	}
	return findings, quarantined
}

// ─── audit cache ────────────────────────────────────────────────────────────────
//
// Recomputed by loadPolicy() on every (re)load, so scanPayload's quarantine
// check and the dashboard's audit panel never need to re-run the audit
// themselves.

var (
	mcpAuditMu       sync.RWMutex
	mcpAuditFindings = []MCPServerFinding{}
	mcpQuarantined   = map[string]string{}
)

// setMCPAudit stores the latest config-hardening audit results.
func setMCPAudit(findings []MCPServerFinding, quarantined map[string]string) {
	mcpAuditMu.Lock()
	mcpAuditFindings = findings
	mcpQuarantined = quarantined
	mcpAuditMu.Unlock()
}

// getMCPAudit returns the latest config-hardening findings and quarantine map.
func getMCPAudit() ([]MCPServerFinding, map[string]string) {
	mcpAuditMu.RLock()
	defer mcpAuditMu.RUnlock()
	return mcpAuditFindings, mcpQuarantined
}

// mcpServerQuarantined reports whether serverID is currently quarantined by
// the config-hardening audit, and why.
func mcpServerQuarantined(serverID string) (reason string, ok bool) {
	mcpAuditMu.RLock()
	defer mcpAuditMu.RUnlock()
	reason, ok = mcpQuarantined[serverID]
	return
}

// ─── context binding (confused-deputy prevention) ──────────────────────────────
//
// Phase 1.2 of zero-trust MCP brokering: every successful credential
// injection also mints a short-lived, HMAC-signed context-binding token
// (_mcp_context_token) that ties the call to the session it was brokered
// for. If a later tool call arrives carrying a _mcp_context_token — e.g. an
// agent forwarding a token from a prior MCP response in order to authorize a
// "chained" call to a different server — AgentArmor verifies the signature,
// expiry, and that the token was issued for THIS session before allowing the
// call, blocking unverified task propagation (Server A autonomously invoking
// Server B using a stolen or forged context).
//
// Signing reuses the same HMAC-HS256 secret as agent JWTs (tokens.go).

const mcpContextTokenTTL = 5 * time.Minute

// mcpContextClaims is the payload of a context-binding token.
type mcpContextClaims struct {
	SessionKey string `json:"sid"`
	TenantID   string `json:"tnt"`
	ServerID   string `json:"srv"`
	ExpiresAt  int64  `json:"exp"`
}

// issueMCPContextToken mints a signed context-binding token for a tool call
// brokered to serverID within the given session/tenant.
func issueMCPContextToken(sessionKey, tenantID, serverID string) string {
	claims := mcpContextClaims{
		SessionKey: sessionKey,
		TenantID:   tenantID,
		ServerID:   serverID,
		ExpiresAt:  time.Now().Add(mcpContextTokenTTL).Unix(),
	}
	pay, _ := json.Marshal(claims)
	p := b64url(pay)
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(p))
	return p + "." + b64url(mac.Sum(nil))
}

// validateMCPContextToken verifies a context-binding token's signature and
// expiry, and that it was issued for the given session and tenant. A non-nil
// error means the token is forged, expired, or bound to a different
// session/tenant — i.e. unverified task propagation.
func validateMCPContextToken(token, sessionKey, tenantID string) error {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("malformed token")
	}
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(parts[0]))
	if !hmac.Equal([]byte(parts[1]), []byte(b64url(mac.Sum(nil)))) {
		return fmt.Errorf("invalid signature")
	}
	payBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	var claims mcpContextClaims
	if err := json.Unmarshal(payBytes, &claims); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}
	if time.Now().Unix() > claims.ExpiresAt {
		return fmt.Errorf("token expired")
	}
	if claims.SessionKey != sessionKey {
		return fmt.Errorf("token was issued for a different session")
	}
	if claims.TenantID != tenantID {
		return fmt.Errorf("token was issued for a different tenant")
	}
	return nil
}

// extractMCPContextToken returns the _mcp_context_token field from a tool
// call's args, if present.
func extractMCPContextToken(args json.RawMessage) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	var m map[string]interface{}
	if err := json.Unmarshal(args, &m); err != nil {
		return "", false
	}
	tok, ok := m["_mcp_context_token"].(string)
	return tok, ok && tok != ""
}
