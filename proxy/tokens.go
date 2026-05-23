package main

// Context-aware agent token system — ABAC layer for AgentArmor.
//
// Admins issue short-lived, signed JWTs (HMAC-SHA256) that carry capability
// scopes. When an agent presents such a token, the scanner pipeline respects
// those capabilities instead of applying blanket policy.
//
// Available scopes:
//
//   pii:read       — agent may receive PII in LLM responses (outbound PII scanner bypassed)
//   pii:process    — agent may send AND receive PII (inbound + outbound PII bypassed)
//   secrets:read   — secret values are not redacted for this session
//   tool:exec      — bypass zero-trust approval for the 'exec' tool
//   tool:browser   — bypass zero-trust approval for the 'browser' tool
//   tool:any       — bypass zero-trust approval for ALL high-risk tools
//
// Scanners that are NEVER bypassable regardless of scope:
//   - Prompt injection (no agent should receive jailbreaks)
//   - GoalLock canary (exfiltration proof, always active)
//   - SSRF / DNS rebinding (network-level, always active)
//   - Blast radius cap (safety net, always active)
//
// JWT format (HMAC-HS256):
//   Header: {"alg":"HS256","typ":"JWT"}
//   Payload: {"iss":"agentarmor","sub":"<agent_id>","jti":"<uuid>",
//             "agentarmor:scopes":["pii:read"],"iat":<unix>,"exp":<unix>}
//
// The server secret is loaded from AGENTARMOR_JWT_SECRET or auto-generated
// on first run and stored in ./data/jwt.secret.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── scope constants ─────────────────────────────────────────────────────────

const (
	// Content / data scopes
	ScopePIIRead     = "pii:read"      // receive PII in responses
	ScopePIIProcess  = "pii:process"   // send and receive PII
	ScopeSecretsRead = "secrets:read"  // secret values not redacted

	// Tool / action scopes
	ScopeToolExec    = "tool:exec"     // bypass ZT approval for exec
	ScopeToolBrowser = "tool:browser"  // bypass ZT approval for browser
	ScopeToolAny     = "tool:any"      // bypass all ZT tool approvals

	// Orchestration scopes — for dynamic multi-agent systems
	ScopeRateLimitExempt  = "rate_limit:exempt"   // bypass rate-limiting (trusted orchestrators)
	ScopeAnomalyExempt    = "anomaly:exempt"       // bypass anomaly scoring (predictable pipelines)
	ScopeBlastRadiusExempt = "blast_radius:exempt" // bypass blast-radius cap (orchestrators do more)
	ScopeAgentSpawn       = "agent:spawn"          // can issue child tokens for downstream agents
)

// AllDefinedScopes is the ordered list shown in the dashboard scope selector.
// Grouped: content → tools → orchestration.
// JSON tags must be lowercase so the browser-side JS can access s.value / s.group etc.
var AllDefinedScopes = []struct {
	Value       string `json:"value"`
	Group       string `json:"group"`
	Description string `json:"description"`
	Danger      bool   `json:"danger"`
}{
	{ScopePIIRead, "content", "Receive PII in LLM responses — outbound PII scanner bypassed", false},
	{ScopePIIProcess, "content", "Send AND receive PII — inbound + outbound PII scanners bypassed", true},
	{ScopeSecretsRead, "content", "Secret values (API keys, tokens) not redacted in this session", true},
	{ScopeToolExec, "tools", "Bypass zero-trust approval queue for the exec tool", true},
	{ScopeToolBrowser, "tools", "Bypass zero-trust approval queue for the browser tool", true},
	{ScopeToolAny, "tools", "Bypass zero-trust approval queue for ALL high-risk tools", true},
	{ScopeRateLimitExempt, "orchestration", "Bypass rate-limiting — for high-throughput orchestrators", true},
	{ScopeAnomalyExempt, "orchestration", "Bypass anomaly scoring — for predictable multi-step pipelines", true},
	{ScopeBlastRadiusExempt, "orchestration", "Bypass blast-radius cap — for orchestrators that legitimately make many tool calls", true},
	{ScopeAgentSpawn, "orchestration", "Issue child tokens for downstream agents (scopes are always a subset of this token's scopes)", false},
}

// ─── JWT secret ──────────────────────────────────────────────────────────────

var jwtSecret []byte

func initJWTSecret() {
	if s := os.Getenv("AGENTARMOR_JWT_SECRET"); s != "" {
		jwtSecret = []byte(s)
		log.Printf("🔑 Agent JWT secret loaded from AGENTARMOR_JWT_SECRET")
		return
	}

	secretPath := filepath.Join("data", "jwt.secret")
	if data, err := os.ReadFile(secretPath); err == nil && len(data) >= 32 {
		jwtSecret = data
		log.Printf("🔑 Agent JWT secret loaded from %s", secretPath)
		return
	}

	// Generate a new 64-byte secret and persist it.
	raw := make([]byte, 64)
	if _, err := rand.Read(raw); err != nil {
		log.Fatalf("❌ Cannot generate JWT secret: %v", err)
	}
	os.MkdirAll("data", 0755) //nolint:errcheck
	if err := os.WriteFile(secretPath, raw, 0600); err != nil {
		log.Printf("⚠️  Could not persist JWT secret to %s: %v", secretPath, err)
	}
	jwtSecret = raw
	log.Printf("🔑 Agent JWT secret generated and saved to %s", secretPath)
}

// ─── JWT encode / decode ─────────────────────────────────────────────────────

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func issueAgentJWT(agentID string, scopes []string, expiresIn time.Duration) (string, string, error) {
	return issueAgentJWTFull(agentID, scopes, expiresIn, "", 0)
}

func issueAgentJWTFull(agentID string, scopes []string, expiresIn time.Duration, parentJTI string, depth int) (string, string, error) {
	jti := make([]byte, 16)
	rand.Read(jti) //nolint:errcheck
	jtiHex := hex.EncodeToString(jti)

	now := time.Now().Unix()

	claims := map[string]interface{}{
		"iss":                  "agentarmor",
		"sub":                  agentID,
		"jti":                  jtiHex,
		"agentarmor:scopes":    scopes,
		"agentarmor:depth":     depth,
		"iat":                  now,
	}
	if parentJTI != "" {
		claims["agentarmor:parent_jti"] = parentJTI
	}
	if expiresIn > 0 {
		claims["exp"] = now + int64(expiresIn.Seconds())
	}

	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	pay, _ := json.Marshal(claims)

	msg := b64url(hdr) + "." + b64url(pay)
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(msg))
	sig := b64url(mac.Sum(nil))

	return msg + "." + sig, jtiHex, nil
}

type agentClaims struct {
	Subject    string
	JTI        string
	Scopes     []string
	ExpiresAt  int64 // 0 = never
	ParentJTI  string
	SpawnDepth int
}

func validateAgentJWT(raw string) (*agentClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT")
	}

	msg := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(msg))
	expected := b64url(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(expected)) {
		return nil, fmt.Errorf("invalid signature")
	}

	payBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var p struct {
		Issuer     string   `json:"iss"`
		Subject    string   `json:"sub"`
		JTI        string   `json:"jti"`
		Scopes     []string `json:"agentarmor:scopes"`
		ParentJTI  string   `json:"agentarmor:parent_jti"`
		Depth      int      `json:"agentarmor:depth"`
		Exp        int64    `json:"exp"`
	}
	if err := json.Unmarshal(payBytes, &p); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	if p.Issuer != "agentarmor" {
		return nil, fmt.Errorf("wrong issuer")
	}
	if p.Exp > 0 && time.Now().Unix() > p.Exp {
		return nil, fmt.Errorf("token expired")
	}
	if isTokenRevoked(p.JTI) {
		return nil, fmt.Errorf("token revoked")
	}
	// If this token was spawned by a parent, check that the parent isn't revoked either.
	if p.ParentJTI != "" && isTokenRevoked(p.ParentJTI) {
		return nil, fmt.Errorf("parent token revoked")
	}

	return &agentClaims{
		Subject:    p.Subject,
		JTI:        p.JTI,
		Scopes:     p.Scopes,
		ExpiresAt:  p.Exp,
		ParentJTI:  p.ParentJTI,
		SpawnDepth: p.Depth,
	}, nil
}

// ─── revocation set ───────────────────────────────────────────────────────────

var (
	revokedJTIs   = make(map[string]struct{})
	revokedJTIsMu sync.RWMutex
)

func isTokenRevoked(jti string) bool {
	revokedJTIsMu.RLock()
	defer revokedJTIsMu.RUnlock()
	_, ok := revokedJTIs[jti]
	return ok
}

func revokeTokenJTI(jti string) {
	revokedJTIsMu.Lock()
	revokedJTIs[jti] = struct{}{}
	revokedJTIsMu.Unlock()
}

// ─── scope subsetting helpers ────────────────────────────────────────────────

// scopesAreSubset returns true when every scope in child is present in parent.
func scopesAreSubset(parent, child []string) bool {
	parentSet := make(map[string]bool, len(parent))
	for _, s := range parent {
		parentSet[s] = true
	}
	for _, s := range child {
		if !parentSet[s] {
			return false
		}
	}
	return true
}

// ─── agent routing ────────────────────────────────────────────────────────────

// matchAgentPattern supports exact match and trailing-wildcard (worker-*).
func matchAgentPattern(pattern, agentID string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(agentID, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == agentID
}

// verifySpawnPolicy checks whether parentAgentID is permitted to create a
// child token for childAgentID under the active agent_routing policy.
func verifySpawnPolicy(parentAgentID, childAgentID string) error {
	policyLock.RLock()
	routing := policy.AgentRouting
	policyLock.RUnlock()

	if !routing.Enabled {
		return nil // no routing restrictions
	}

	for _, rule := range routing.Rules {
		if !matchAgentPattern(rule.Parent, parentAgentID) {
			continue
		}
		for _, cp := range rule.Children {
			if matchAgentPattern(cp, childAgentID) {
				return nil
			}
		}
		// Parent matched a rule but no child pattern matched — deny
		return fmt.Errorf("agent_routing: %q is not an approved child of %q", childAgentID, parentAgentID)
	}

	if routing.Strict {
		return fmt.Errorf("agent_routing: no rule permits %q to spawn %q (strict mode)", parentAgentID, childAgentID)
	}
	return nil
}

// ─── DB helpers ───────────────────────────────────────────────────────────────

func initAgentTokensTable() {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS agent_tokens (
		id          TEXT PRIMARY KEY,
		agent_id    TEXT NOT NULL,
		description TEXT,
		scopes      TEXT NOT NULL,
		expires_at  TEXT,
		spawned_by  TEXT,
		spawn_depth INTEGER DEFAULT 0,
		created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
		revoked     INTEGER DEFAULT 0
	)`)
	if err != nil {
		log.Printf("⚠️  Could not create agent_tokens table: %v", err)
		return
	}

	// Load revoked JTIs into the in-memory set.
	rows, err := db.Query(`SELECT id FROM agent_tokens WHERE revoked = 1`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var jti string
		rows.Scan(&jti) //nolint:errcheck
		revokeTokenJTI(jti)
	}
}

// ─── scope check ─────────────────────────────────────────────────────────────

// sessionHasAnyScope returns true when the session for sessionKey in tnt
// carries at least one of the allowScopes.
func sessionHasAnyScope(tnt *Tenant, sessionKey string, allowScopes []string) bool {
	if len(allowScopes) == 0 || sessionKey == "" {
		return false
	}
	tnt.sessLock.RLock()
	sess := tnt.sessions[sessionKey]
	tnt.sessLock.RUnlock()
	if sess == nil {
		return false
	}
	for _, need := range allowScopes {
		for _, have := range sess.AgentScopes {
			if have == need {
				return true
			}
		}
	}
	return false
}

// storeAgentScopes extracts a valid agent JWT from the request Authorization
// header and writes the embedded scopes into the session state.
func storeAgentScopes(authHeader, sessionKey string, tnt *Tenant) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return
	}
	raw := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := validateAgentJWT(raw)
	if err != nil {
		return // not an agent JWT or invalid — ignore silently
	}

	tnt.sessLock.Lock()
	defer tnt.sessLock.Unlock()

	if tnt.sessions == nil {
		tnt.sessions = make(map[string]*SessionState)
	}
	sess, ok := tnt.sessions[sessionKey]
	if !ok {
		sess = &SessionState{FirstSeen: time.Now(), ToolCounts: make(map[string]int)}
		tnt.sessions[sessionKey] = sess
	}
	sess.AgentID = claims.Subject
	sess.AgentScopes = claims.Scopes
	sess.SpawnDepth = claims.SpawnDepth
	sess.LastSeen = time.Now()
}
