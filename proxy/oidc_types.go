package main

import "time"

// oidcConfig is the resolved SSO configuration (dependency-free). The live
// go-oidc provider/verifier built from it lives in oidc.go (full build only).
type oidcConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AdminGroups  []string
	UserGroups   []string
	Scopes       []string
	ProviderName string
}

// Dependency-free OIDC types, in an untagged file so both the full
// (go-oidc-backed) and lite (stub) flavors share them. The go-oidc /
// oauth2 provider+verifier values live in oidc.go (full build only).

// oidcSession is a logged-in dashboard session (admin/user via SSO).
type oidcSession struct {
	ID        string
	Email     string
	Name      string
	Role      string // "admin" | "user"
	ExpiresAt time.Time
}

// OIDCStatus is the SSO status returned to the dashboard Auth tab.
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
