package main

// Login gate — serves the user-facing login page and handles both OIDC and
// token-based authentication before users can reach the OpenClaw chat.
//
// Routes (always active, regardless of OIDC configuration):
//   GET  /armor/user-login          — show login page
//   POST /armor/user-login          — token-based login (fallback when no OIDC)
//   GET  /armor/user-auth           — start OIDC flow for chat users
//   GET  /armor/user-callback       — OIDC callback for chat users (redirects to OpenClaw)
//   GET  /armor/user-logout         — clear chat session cookie, redirect to login

import (
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

//go:embed login.html
var loginPageHTML string

//go:embed loadingpage.html
var loadingPageHTML string

var loginTmpl = template.Must(template.New("login").Parse(loginPageHTML))

// handleLoadingPage serves the server-side scanner initialisation page.
// The page polls /armor/api/scanner-status and redirects to OpenClaw once ready.
func handleLoadingPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(loadingPageHTML)) //nolint:errcheck
}

type loginPageData struct {
	OIDCEnabled  bool
	OIDCOnly     bool
	ProviderName string
	ReturnTo     string
	Error        string
}

// handleUserLoginPage serves GET /armor/user-login
func handleUserLoginPage(w http.ResponseWriter, r *http.Request) {
	// Already logged in? Redirect to destination.
	if _, err := validateUserSession(r); err == nil {
		returnTo := sanitizeReturn(r.URL.Query().Get("return"))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTmpl.Execute(w, loginPageData{ //nolint:errcheck
		OIDCEnabled:  oidcEnabled,
		OIDCOnly:     oidcEnabled && os.Getenv("ARMOR_OIDC_ONLY") == "true",
		ProviderName: resolvedProviderName(),
		ReturnTo:     sanitizeReturn(r.URL.Query().Get("return")),
		Error:        r.URL.Query().Get("error"),
	})
}

// handleUserLoginPost handles POST /armor/user-login — token-based fallback.
func handleUserLoginPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm() //nolint:errcheck
	token := r.FormValue("token")
	returnTo := sanitizeReturn(r.FormValue("return"))

	var sub, name string
	var scopes []string

	switch {
	case token == adminToken:
		sub = "admin"
		name = "Administrator"
		scopes = allDefinedScopeValues()
	case token == userToken:
		sub = "user"
		name = "User"
		scopes = nil // default scopes from policy
		policyLock.RLock()
		scopes = append(scopes, policy.SSO.DefaultScopes...)
		policyLock.RUnlock()
	default:
		errMsg := url.QueryEscape("Invalid access token.")
		http.Redirect(w, r, "/armor/user-login?return="+url.QueryEscape(returnTo)+"&error="+errMsg, http.StatusFound)
		return
	}

	issueUserSession(w, sub, name, scopes)
	log.Printf("✅ Token login: sub=%s returnTo=%s", sub, returnTo)
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// handleUserOIDCAuth starts the OIDC flow for a chat user.
// The returnTo destination is encoded in the state so the callback can redirect there.
func handleUserOIDCAuth(w http.ResponseWriter, r *http.Request) {
	if !oidcEnabled {
		http.Redirect(w, r, "/armor/user-login", http.StatusFound)
		return
	}
	returnTo := sanitizeReturn(r.URL.Query().Get("return"))
	// State = "u:{returnTo}:{nonce}" — the "u:" prefix tells the callback this is a chat-user flow.
	nonce := generateState()
	state := "u:" + returnTo + ":" + nonce
	http.SetCookie(w, &http.Cookie{
		Name:     "armor_oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

// handleUserOIDCCallback handles /armor/callback when the state starts with "u:".
// It derives ABAC scopes from the user's OIDC group membership, issues an aa_user
// cookie, and redirects to OpenClaw (or wherever returnTo points).
func handleUserOIDCCallback(w http.ResponseWriter, r *http.Request, claims map[string]interface{}, returnTo string) {
	email := claimString(claims, "email", "sub")
	name := claimString(claims, "name", "email")
	scopes := resolveUserScopes(claims)

	issueUserSession(w, email, name, scopes)
	log.Printf("✅ OIDC chat login: %s scopes=%v returnTo=%s", email, scopes, returnTo)
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// handleUserLogout clears the aa_user cookie and redirects to the login page.
func handleUserLogout(w http.ResponseWriter, r *http.Request) {
	clearUserSession(w)
	http.Redirect(w, r, "/armor/user-login", http.StatusFound)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// sanitizeReturn ensures the returnTo URL is a safe relative path.
func sanitizeReturn(raw string) string {
	if raw == "" {
		return "/"
	}
	// Decode if query-escaped
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		decoded = raw
	}
	// Only allow relative paths — prevent open redirect
	if strings.HasPrefix(decoded, "//") || strings.Contains(decoded, "://") {
		return "/"
	}
	if !strings.HasPrefix(decoded, "/") {
		return "/"
	}
	return decoded
}

func resolvedProviderName() string {
	if oidcCfg != nil && oidcCfg.ProviderName != "" {
		return oidcCfg.ProviderName
	}
	return "your SSO provider"
}

func allDefinedScopeValues() []string {
	out := make([]string, len(AllDefinedScopes))
	for i, s := range AllDefinedScopes {
		out[i] = s.Value
	}
	return out
}

// isLoginExempt returns true for paths that should pass through without a user session.
// This covers the login flow itself, static armor assets, and the metrics endpoint.
func isLoginExempt(path string) bool {
	exempt := []string{
		"/armor/user-login",
		"/armor/user-auth",
		"/armor/user-callback",
		"/armor/user-logout",
		"/armor/callback",   // dashboard OIDC callback
		"/armor/login",      // dashboard OIDC start
		"/armor/logout",     // dashboard OIDC logout
		"/armor/",           // dashboard itself
		"/armor/metrics",
	}
	for _, e := range exempt {
		if path == e || strings.HasPrefix(path, e) {
			return true
		}
	}
	return false
}

// requireUserSession is called from handleRoot before proxying to OpenClaw.
// It validates the aa_user cookie and stores the scopes in the session state.
// Returns false (and writes the redirect) when the request should be blocked.
func requireUserSession(w http.ResponseWriter, r *http.Request, sessionKey string, tnt *Tenant) bool {
	if isLoginExempt(r.URL.Path) {
		return true
	}

	sess, err := validateUserSession(r)
	if err != nil {
		// WebSocket upgrades can't be redirected — close with 401
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return false
		}
		returnTo := url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, "/armor/user-login?return="+returnTo, http.StatusFound)
		return false
	}

	storeUserSessionScopes(sess, sessionKey, tnt)
	return true
}

// isUserLoginEnabled returns true when the login gate should be enforced.
//
// Logic (in order):
//  1. ARMOR_USER_LOGIN=true  → always on
//  2. ARMOR_USER_LOGIN=false → always off
//  3. Auto: on only when OIDC is configured AND group_scope_mappings is non-empty.
//     That's the only situation where the gate adds real value — it gives each
//     user a different set of ABAC scopes based on their group membership.
//     Without OIDC (or with OIDC but no mappings) the gate is just friction.
func isUserLoginEnabled() bool {
	switch os.Getenv("ARMOR_USER_LOGIN") {
	case "true", "1":
		return true
	case "false", "0":
		return false
	}
	// Auto-detect: activate only when OIDC + scope mappings are both configured.
	if !oidcEnabled {
		return false
	}
	policyLock.RLock()
	hasMappings := len(policy.SSO.GroupScopeMappings) > 0
	policyLock.RUnlock()
	return hasMappings
}

// Silence "declared and not used" for fmt in case template errors are suppressed.
var _ = fmt.Sprintf
