package main

// ACME / Let's Encrypt TLS certificate automation.
//
// When ACME_DOMAIN is set, the proxy obtains and auto-renews a certificate
// from Let's Encrypt using the HTTP-01 challenge. Port 80 must be publicly
// reachable from the internet for the challenge to succeed.
//
// Required env vars:
//   ACME_DOMAIN  — public hostname, e.g. "proxy.example.com"
//   ACME_EMAIL   — contact email for Let's Encrypt (renewal notices)
//
// Optional:
//   ACME_STAGING=true — use Let's Encrypt staging (no rate limits, untrusted cert)
//
// Cert storage: /app/certs/acme/  (persisted via the ./certs volume mount)
//
// When ACME_DOMAIN is not set, the proxy falls back to TLS_CERT / TLS_KEY
// files (or the auto-generated self-signed cert from docker-entrypoint.sh).

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// startTLS starts the HTTPS server and, if ACME is configured, the HTTP-01
// challenge server on :80. Blocks until the HTTPS server exits.
//
// Returns true if ACME is handling TLS (caller should not start its own server).
func startTLS(mux http.Handler) bool {
	domain := os.Getenv("ACME_DOMAIN")
	if domain == "" {
		return false
	}

	email := os.Getenv("ACME_EMAIL")
	cacheDir := "/app/certs/acme"
	os.MkdirAll(cacheDir, 0700) //nolint:errcheck

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(cacheDir),
		Email:      email,
	}

	if os.Getenv("ACME_STAGING") == "true" {
		m.Client = &acme.Client{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		}
		log.Println("⚠️  ACME staging mode — cert will not be trusted by browsers")
	}

	// HTTP-01 challenge handler on :80 (must be reachable from the internet)
	go func() {
		log.Printf("🔐 ACME HTTP-01 challenge server listening on :80 for domain %s", domain)
		if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
			log.Printf("⚠️  ACME challenge server: %v", err)
		}
	}()

	// HTTP→HTTPS redirect on :8080 (for backwards compat with existing port mapping)
	go func() {
		log.Printf("↪  HTTP→HTTPS redirect on :8080")
		http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { //nolint:errcheck
			http.Redirect(w, r, "https://"+domain+r.RequestURI, http.StatusMovedPermanently)
		}))
	}()

	tlsConf := m.TLSConfig()
	tlsConf.MinVersion = tls.VersionTLS12

	ln, err := tls.Listen("tcp", ":8443", tlsConf)
	if err != nil {
		log.Fatalf("❌ ACME TLS listen: %v", err)
	}

	log.Printf("🔐 ACME TLS active — certificate for %s via Let's Encrypt", domain)
	log.Printf("📊 Dashboard: https://%s/armor/", domain)

	srv := &http.Server{Handler: mux, BaseContext: func(net.Listener) context.Context { return context.Background() }}
	if err := srv.Serve(ln); err != nil {
		log.Fatalf("❌ ACME server: %v", err)
	}
	return true
}
