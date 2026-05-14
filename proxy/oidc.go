package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ──────────────────────────────────────────────
// OIDC Configuration
// ──────────────────────────────────────────────

type oidcConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	AdminGroups   []string
	UserGroups    []string
	Scopes        []string
	ProviderName  string
}

var (
	oidcEnabled  bool
	oidcCfg      *oidcConfig
	oidcProvider *gooidc.Provider
	oidcVerifier *gooidc.IDTokenVerifier
	oauth2Config *oauth2.Config
	oidcStateKey []byte // HMAC key for state/CSRF protection
)

// ──────────────────────────────────────────────
// Session Store
// ──────────────────────────────────────────────

type oidcSession struct {
	ID        string
	Email     string
	Name      string
	Role      string    // "admin" | "user"
	ExpiresAt time.Time
}

var (
	oidcSessions     = make(map[string]*oidcSession)
	oidcSessionsLock sync.RWMutex
)

const oidcSessionCookie = "armor_session"
const oidcSessionTTL = 8 * time.Hour

// ──────────────────────────────────────────────
// Initialisation
// ──────────────────────────────────────────────

// ReinitOIDCFromPolicy is called by loadPolicy() whenever the policy file changes.
// It re-initialises OIDC from the SSO section of the loaded config.
// Runs in a goroutine so slow discovery fetches don't block the hot-reload.
func ReinitOIDCFromPolicy(sso struct {
	Enabled      bool
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AdminGroups  []string
	UserGroups   []string
	Scopes       []string
	ProviderName string
}) {
	if !sso.Enabled {
		if oidcEnabled {
			oidcEnabled = false
			log.Printf("🔓 OIDC disabled via policy")
		}
		return
	}
	if sso.Issuer == "" || sso.ClientID == "" || sso.ClientSecret == "" || sso.RedirectURL == "" {
		log.Printf("⚠️  SSO enabled in policy but missing required fields (issuer/client_id/client_secret/redirect_url)")
		return
	}
	cfg := &oidcConfig{
		Issuer:       sso.Issuer,
		ClientID:     sso.ClientID,
		ClientSecret: sso.ClientSecret,
		RedirectURL:  sso.RedirectURL,
		AdminGroups:  sso.AdminGroups,
		UserGroups:   sso.UserGroups,
		Scopes:       sso.Scopes,
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{gooidc.ScopeOpenID, "email", "profile"}
	}
	if err := initOIDCFromConfig(cfg); err != nil {
		log.Printf("⚠️  OIDC re-init failed: %v", err)
	}
}

// initOIDCFromConfig is the shared init function used by both InitOIDC (env vars) and
// ReinitOIDCFromPolicy (policy.yaml SSO section).
func initOIDCFromConfig(cfg *oidcConfig) error {
	if oidcStateKey == nil {
		oidcStateKey = make([]byte, 32)
		rand.Read(oidcStateKey)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	provider, err := gooidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return fmt.Errorf("OIDC provider discovery failed for %s: %w", cfg.Issuer, err)
	}
	oidcCfg = cfg
	oidcProvider = provider
	oidcVerifier = provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID})
	oauth2Config = &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}
	if !oidcEnabled {
		oidcEnabled = true
		go cleanupOIDCSessions()
	}
	log.Printf("✅ OIDC (re-)initialised — issuer: %s", cfg.Issuer)
	return nil
}

// InitOIDC reads env vars and connects to the OIDC provider's discovery endpoint.
// Returns nil without enabling OIDC when OIDC_ENABLED is not "true".
func InitOIDC() error {
	if os.Getenv("OIDC_ENABLED") != "true" {
		return nil
	}

	issuer := os.Getenv("OIDC_ISSUER")
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	redirectURL := os.Getenv("OIDC_REDIRECT_URL")

	if issuer == "" || clientID == "" || clientSecret == "" || redirectURL == "" {
		return fmt.Errorf("OIDC_ENABLED=true but OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URL are all required")
	}

	cfg := &oidcConfig{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
	}

	// Parse group lists
	for _, g := range splitTrimmed(os.Getenv("OIDC_ADMIN_GROUPS")) {
		cfg.AdminGroups = append(cfg.AdminGroups, g)
	}
	for _, g := range splitTrimmed(os.Getenv("OIDC_USER_GROUPS")) {
		cfg.UserGroups = append(cfg.UserGroups, g)
	}

	cfg.Scopes = []string{gooidc.ScopeOpenID, "email", "profile"}
	if ss := os.Getenv("OIDC_SCOPES"); ss != "" {
		cfg.Scopes = splitTrimmed(ss)
	}
	if pn := os.Getenv("OIDC_PROVIDER_NAME"); pn != "" {
		cfg.ProviderName = pn
	}

	return initOIDCFromConfig(cfg)
}

// ──────────────────────────────────────────────
// HTTP Handlers
// ──────────────────────────────────────────────

// HandleOIDCLogin redirects the browser to the OIDC provider's authorisation endpoint.
func HandleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	http.SetCookie(w, &http.Cookie{
		Name:     "armor_oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes to complete the flow
	})
	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

// HandleOIDCCallback processes the authorisation code returned by the provider.
func HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state (CSRF protection)
	stateCookie, err := r.Cookie("armor_oauth_state")
	if err != nil || r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "Invalid OAuth2 state — possible CSRF attempt", http.StatusBadRequest)
		return
	}
	// Clear state cookie
	http.SetCookie(w, &http.Cookie{Name: "armor_oauth_state", MaxAge: -1, Path: "/"})

	// Exchange authorisation code for tokens
	ctx := r.Context()
	token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("⚠️  OIDC code exchange failed: %v", err)
		http.Error(w, "Authentication failed — could not exchange code", http.StatusInternalServerError)
		return
	}

	// Verify and parse ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Authentication failed — no id_token in response", http.StatusInternalServerError)
		return
	}
	idToken, err := oidcVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("⚠️  OIDC ID token verification failed: %v", err)
		http.Error(w, "Authentication failed — invalid id_token", http.StatusUnauthorized)
		return
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Authentication failed — could not parse claims", http.StatusInternalServerError)
		return
	}

	email := claimString(claims, "email", "sub")
	name := claimString(claims, "name", "email")
	role := resolveRole(claims, oidcCfg.AdminGroups, oidcCfg.UserGroups)

	if role == "none" {
		log.Printf("⚠️  OIDC login denied for %s — not in any allowed group", email)
		http.Error(w, fmt.Sprintf("Access denied: %s is not a member of any authorised group.\n\nConfigure OIDC_ADMIN_GROUPS or OIDC_USER_GROUPS.", email), http.StatusForbidden)
		return
	}

	// Create session
	sess := createSession(email, name, role)
	http.SetCookie(w, &http.Cookie{
		Name:     oidcSessionCookie,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oidcSessionTTL.Seconds()),
	})

	log.Printf("✅ OIDC login: %s (%s)", email, role)
	http.Redirect(w, r, "/armor/", http.StatusFound)
}

// HandleOIDCLogout clears the session and redirects to the provider's logout endpoint.
func HandleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(oidcSessionCookie); err == nil {
		deleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: oidcSessionCookie, MaxAge: -1, Path: "/"})

	// Build provider end_session_endpoint URL if available
	var providerData struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if b, err := json.Marshal(oidcProvider); err == nil {
		json.Unmarshal(b, &providerData)
	}
	if providerData.EndSessionEndpoint != "" {
		http.Redirect(w, r, providerData.EndSessionEndpoint, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/armor/", http.StatusFound)
}

// ──────────────────────────────────────────────
// Session helpers
// ──────────────────────────────────────────────

func createSession(email, name, role string) *oidcSession {
	b := make([]byte, 24)
	rand.Read(b)
	sess := &oidcSession{
		ID:        hex.EncodeToString(b),
		Email:     email,
		Name:      name,
		Role:      role,
		ExpiresAt: time.Now().Add(oidcSessionTTL),
	}
	oidcSessionsLock.Lock()
	oidcSessions[sess.ID] = sess
	oidcSessionsLock.Unlock()
	return sess
}

func getSessionFromRequest(r *http.Request) *oidcSession {
	cookie, err := r.Cookie(oidcSessionCookie)
	if err != nil {
		return nil
	}
	oidcSessionsLock.RLock()
	sess, ok := oidcSessions[cookie.Value]
	oidcSessionsLock.RUnlock()
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil
	}
	return sess
}

func deleteSession(id string) {
	oidcSessionsLock.Lock()
	delete(oidcSessions, id)
	oidcSessionsLock.Unlock()
}

func cleanupOIDCSessions() {
	for range time.Tick(30 * time.Minute) {
		oidcSessionsLock.Lock()
		for id, s := range oidcSessions {
			if time.Now().After(s.ExpiresAt) {
				delete(oidcSessions, id)
			}
		}
		oidcSessionsLock.Unlock()
	}
}

// ──────────────────────────────────────────────
// OIDCStatus is returned by GET /armor/api/oidc/status so the dashboard
// knows whether to show the SSO login button or the token field.
// ──────────────────────────────────────────────

type OIDCStatus struct {
	Enabled      bool   `json:"enabled"`
	LoginURL     string `json:"login_url,omitempty"`
	LogoutURL    string `json:"logout_url,omitempty"`
	ProviderName string `json:"provider_name,omitempty"` // e.g. "Google", "Okta", "Microsoft"
	ProviderType string `json:"provider_type,omitempty"` // google | microsoft | okta | auth0 | generic
	Email        string `json:"email,omitempty"`
	Name         string `json:"name,omitempty"`
	Role         string `json:"role,omitempty"`
}

// detectProvider infers a human-readable name and a type slug from the issuer URL.
func detectProvider(issuer string) (name, ptype string) {
	// Allow explicit override via env var
	if n := os.Getenv("OIDC_PROVIDER_NAME"); n != "" {
		return n, "generic"
	}
	switch {
	case strings.Contains(issuer, "accounts.google.com"):
		return "Google", "google"
	case strings.Contains(issuer, "login.microsoftonline.com") || strings.Contains(issuer, "microsoft.com"):
		return "Microsoft", "microsoft"
	case strings.Contains(issuer, ".okta.com"):
		return "Okta", "okta"
	case strings.Contains(issuer, ".auth0.com"):
		return "Auth0", "auth0"
	case strings.Contains(issuer, "github.com"):
		return "GitHub", "github"
	default:
		// Try to extract a human-readable hostname
		parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://"), "/")
		if len(parts) > 0 && parts[0] != "" {
			return parts[0], "generic"
		}
		return "SSO", "generic"
	}
}

func getOIDCStatus(r *http.Request) OIDCStatus {
	if !oidcEnabled {
		return OIDCStatus{Enabled: false}
	}
	providerName, providerType := detectProvider(oidcCfg.Issuer)
	status := OIDCStatus{
		Enabled:      true,
		LoginURL:     "/armor/login",
		LogoutURL:    "/armor/logout",
		ProviderName: providerName,
		ProviderType: providerType,
	}
	if sess := getSessionFromRequest(r); sess != nil {
		status.Email = sess.Email
		status.Name = sess.Name
		status.Role = sess.Role
	}
	return status
}

// ──────────────────────────────────────────────
// Role resolution from OIDC claims
// ──────────────────────────────────────────────

// resolveRole inspects standard group/role claims and returns "admin", "user", or "none".
// Checks: groups, roles, https://*/roles, cognito:groups, resource_access.
func resolveRole(claims map[string]interface{}, adminGroups, userGroups []string) string {
	userMemberships := extractGroups(claims)

	// If no groups configured, grant user role to any authenticated user
	if len(adminGroups) == 0 && len(userGroups) == 0 {
		return "user"
	}

	for _, g := range userMemberships {
		for _, ag := range adminGroups {
			if strings.EqualFold(g, ag) {
				return "admin"
			}
		}
	}
	for _, g := range userMemberships {
		for _, ug := range userGroups {
			if strings.EqualFold(g, ug) {
				return "user"
			}
		}
	}
	return "none"
}

// extractGroups pulls group/role memberships from the most common claim locations.
func extractGroups(claims map[string]interface{}) []string {
	var groups []string
	// Try common claim keys
	for _, key := range []string{"groups", "roles", "cognito:groups", "realm_access.roles"} {
		if v, ok := claims[key]; ok {
			if arr, ok := v.([]interface{}); ok {
				for _, item := range arr {
					if s, ok := item.(string); ok {
						groups = append(groups, s)
					}
				}
			}
		}
	}
	// AWS Cognito and Keycloak nested roles
	if ra, ok := claims["realm_access"].(map[string]interface{}); ok {
		if roles, ok := ra["roles"].([]interface{}); ok {
			for _, r := range roles {
				if s, ok := r.(string); ok {
					groups = append(groups, s)
				}
			}
		}
	}
	// Custom namespace claims (Okta, Auth0)
	for k, v := range claims {
		if strings.HasSuffix(k, "/roles") || strings.HasSuffix(k, "/groups") {
			if arr, ok := v.([]interface{}); ok {
				for _, item := range arr {
					if s, ok := item.(string); ok {
						groups = append(groups, s)
					}
				}
			}
		}
	}
	return groups
}

// ──────────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────────

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	nonce := hex.EncodeToString(b)
	mac := hmac.New(sha256.New, oidcStateKey)
	mac.Write([]byte(nonce))
	return nonce + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func claimString(claims map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := claims[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func splitTrimmed(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
