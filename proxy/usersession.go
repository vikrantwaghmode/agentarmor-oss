package main

// User session cookies — issued after the OIDC login gate.
//
// A user session is separate from the admin dashboard session:
//   - aa_session  → dashboard access (admin or user role)
//   - aa_user     → chat / proxy access with ABAC scopes
//
// When a user logs in via /armor/user-login they get an aa_user cookie.
// Every request through the proxy checks this cookie before forwarding
// to OpenClaw. Unauthenticated requests are redirected to the login page.
//
// The cookie value is an HMAC-HS256 JWT signed with jwtSecret.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	userSessionCookie = "aa_user"
	userSessionTTL    = 8 * time.Hour
)

// UserSession carries the identity and capability scopes for a logged-in user.
type UserSession struct {
	Sub    string   // subject — email or OIDC sub
	Name   string
	Scopes []string // ABAC scopes derived from OIDC groups via group_scope_mappings
}

// issueUserSession mints a signed session cookie and sets it on the response.
func issueUserSession(w http.ResponseWriter, sub, name string, scopes []string) {
	exp := time.Now().Add(userSessionTTL).Unix()
	pay, _ := json.Marshal(map[string]interface{}{
		"iss":               "agentarmor-user",
		"sub":               sub,
		"name":              name,
		"agentarmor:scopes": scopes,
		"exp":               exp,
	})
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	msg := b64url(hdr) + "." + b64url(pay)
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(msg)) //nolint:errcheck
	token := msg + "." + b64url(mac.Sum(nil))

	http.SetCookie(w, &http.Cookie{
		Name:     userSessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(userSessionTTL.Seconds()),
	})
}

// validateUserSession reads and verifies the aa_user cookie.
func validateUserSession(r *http.Request) (*UserSession, error) {
	cookie, err := r.Cookie(userSessionCookie)
	if err != nil {
		return nil, fmt.Errorf("no session")
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed session")
	}
	msg := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(msg)) //nolint:errcheck
	if !hmac.Equal([]byte(parts[2]), []byte(b64url(mac.Sum(nil)))) {
		return nil, fmt.Errorf("invalid signature")
	}
	payBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	var p struct {
		Sub    string   `json:"sub"`
		Name   string   `json:"name"`
		Scopes []string `json:"agentarmor:scopes"`
		Exp    int64    `json:"exp"`
	}
	if err := json.Unmarshal(payBytes, &p); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if p.Exp > 0 && time.Now().Unix() > p.Exp {
		return nil, fmt.Errorf("expired")
	}
	return &UserSession{Sub: p.Sub, Name: p.Name, Scopes: p.Scopes}, nil
}

// clearUserSession removes the aa_user cookie.
func clearUserSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   userSessionCookie,
		MaxAge: -1,
		Path:   "/",
	})
}

// storeUserSessionScopes writes the user's ABAC scopes into the proxy session state
// so scanPayload can read them via sessionHasAnyScope.
func storeUserSessionScopes(sess *UserSession, sessionKey string, tnt *Tenant) {
	if sess == nil || sessionKey == "" {
		return
	}
	tnt.sessLock.Lock()
	defer tnt.sessLock.Unlock()
	if tnt.sessions == nil {
		tnt.sessions = make(map[string]*SessionState)
	}
	s, ok := tnt.sessions[sessionKey]
	if !ok {
		s = &SessionState{FirstSeen: time.Now(), ToolCounts: make(map[string]int)}
		tnt.sessions[sessionKey] = s
	}
	s.AgentID = sess.Sub
	s.AgentScopes = sess.Scopes
	s.LastSeen = time.Now()
}

// resolveUserScopes maps the user's OIDC group memberships to ABAC capability
// scopes using the group_scope_mappings in policy.yaml.
func resolveUserScopes(claims map[string]interface{}) []string {
	policyLock.RLock()
	mappings := policy.SSO.GroupScopeMappings
	defaults := policy.SSO.DefaultScopes
	policyLock.RUnlock()

	userGroups := extractGroupsFromClaims(claims)

	seen := make(map[string]bool)
	var scopes []string

	for _, mapping := range mappings {
		for _, ruleGroup := range mapping.Groups {
			for _, userGroup := range userGroups {
				if ruleGroup == userGroup {
					for _, s := range mapping.Scopes {
						if !seen[s] {
							seen[s] = true
							scopes = append(scopes, s)
						}
					}
				}
			}
		}
	}
	for _, s := range defaults {
		if !seen[s] {
			seen[s] = true
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// extractGroupsFromClaims pulls group/role memberships from OIDC token claims.
//
// Claim lookup order:
//  1. policy.SSO.GroupsClaim (admin-configured, e.g. "memberOf" for some AD setups)
//  2. Common defaults: "groups", "roles", "cognito:groups"
//
// Supports both string-array values (most providers) and space/comma-separated
// strings (some legacy setups). Azure AD GUIDs are returned as-is; configure
// Azure AD "optional claims" to emit displayNames if you prefer human-readable names.
func extractGroupsFromClaims(claims map[string]interface{}) []string {
	// Determine which claims to check, respecting admin override first.
	policyLock.RLock()
	customClaim := policy.SSO.GroupsClaim
	policyLock.RUnlock()

	claimKeys := []string{"groups", "roles", "cognito:groups"}
	if customClaim != "" {
		// Put the custom claim first so it takes precedence.
		claimKeys = append([]string{customClaim}, claimKeys...)
	}

	seen := make(map[string]bool)
	var groups []string

	addGroup := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			groups = append(groups, s)
		}
	}

	for _, key := range claimKeys {
		v, ok := claims[key]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case []interface{}:
			for _, g := range t {
				if s, ok := g.(string); ok {
					addGroup(s)
				}
			}
		case []string:
			for _, s := range t {
				addGroup(s)
			}
		case string:
			// Some providers return a space- or comma-separated list.
			for _, s := range strings.FieldsFunc(t, func(r rune) bool {
				return r == ',' || r == ' '
			}) {
				addGroup(s)
			}
		}
	}
	return groups
}
