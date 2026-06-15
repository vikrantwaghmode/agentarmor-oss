//go:build lite

package main

// Lite build flavor: SSO / OIDC (github.com/coreos/go-oidc + go-jose) is
// compiled out. Authentication falls back to the always-available static
// ADMIN_TOKEN / USER_TOKEN bearer tokens. These no-op stubs satisfy the
// references main.go / loginhandler.go make to the OIDC subsystem.

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"golang.org/x/oauth2"
)

var (
	oidcEnabled  = false
	oidcCfg      *oidcConfig    // nil in lite
	oauth2Config *oauth2.Config // nil in lite (x/oauth2 stays; go-oidc/go-jose are what get dropped)
)

// claimString is referenced by loginhandler.go's OIDC user-flow branch (only
// reached when oidcEnabled, which is always false in lite).
func claimString(_ map[string]interface{}, _ ...string) string { return "" }

func InitOIDC() error { return nil }

// ReinitOIDCFromPolicy mirrors the full signature (anonymous struct) so the
// loadPolicy() call site compiles unchanged; it does nothing in the lite build.
func ReinitOIDCFromPolicy(_ struct {
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
}

func HandleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "SSO is not available in the lite build", http.StatusNotImplemented)
}
func HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "SSO is not available in the lite build", http.StatusNotImplemented)
}
func HandleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/armor/", http.StatusFound)
}

func getSessionFromRequest(_ *http.Request) *oidcSession { return nil }

func getOIDCStatus(_ *http.Request) OIDCStatus { return OIDCStatus{Enabled: false} }

// generateState is used by the (OIDC) login flows; harmless to provide.
func generateState() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
