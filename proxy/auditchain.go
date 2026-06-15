//go:build !lite

package main

// Wiring for the cryptographic audit logging engine (Compliance Phase 1).
//
// This bridges AgentArmor's existing logAuditEvent() into the tamper-evident,
// BLAKE3 + Merkle + HMAC sealed log implemented in compliance/audit. It is
// deliberately fail-safe: any error (or a disabled engine) degrades to the
// existing SQLite/webhook behavior without affecting the request path.

import (
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"agentarmor/compliance/audit"
)

var (
	complianceAudit     *audit.Engine
	complianceAuditOnce sync.Once
	// Exposed for the Phase-4 reporter so it can re-open & verify the same log.
	complianceSigner   audit.SealSigner
	complianceAuditDir string
)

// complianceAuditEnabled reports whether the sealed audit log is active.
// Default ON; set COMPLIANCE_AUDIT_ENABLED=false to fall back to plain logging.
func complianceAuditEnabled() bool {
	return !strings.EqualFold(os.Getenv("COMPLIANCE_AUDIT_ENABLED"), "false")
}

// initComplianceAudit opens the sealed audit log and starts a periodic sealer.
// Must run after initJWTSecret() (it may derive the signing key from jwtSecret).
func initComplianceAudit() {
	if !complianceAuditEnabled() {
		log.Println("ℹ️  Compliance audit log disabled (COMPLIANCE_AUDIT_ENABLED=false)")
		return
	}
	complianceAuditOnce.Do(func() {
		// Signing key: prefer a dedicated secret, else reuse the (already-secret,
		// ≥32-byte) JWT secret so the engine works out of the box.
		key := []byte(os.Getenv("COMPLIANCE_AUDIT_HMAC_KEY"))
		keySource := "COMPLIANCE_AUDIT_HMAC_KEY"
		if len(key) < 16 {
			key = jwtSecret
			keySource = "jwt-secret (set COMPLIANCE_AUDIT_HMAC_KEY to separate)"
		}
		signer, err := audit.NewHMACSigner(key, "audit-hmac-v1")
		if err != nil {
			log.Printf("⚠️  Compliance audit disabled — signer init failed: %v", err)
			return
		}

		dir := os.Getenv("COMPLIANCE_AUDIT_DIR")
		if dir == "" {
			dir = "data/compliance"
		}
		eng, err := audit.New(dir, signer)
		if err != nil {
			log.Printf("⚠️  Compliance audit disabled — engine init failed: %v", err)
			return
		}
		complianceAudit = eng
		complianceSigner = signer
		complianceAuditDir = dir
		log.Printf("🔏 Compliance audit log active — %s (key: %s)", dir, keySource)
		go sealComplianceLoop()

		// Phase 2: the HITL escalation matrix reuses the same signer so audit
		// seals and operator-bound approvals share one key/rotation policy.
		initComplianceHITL(signer)
	})
}

// sealComplianceLoop periodically seals pending events into a signed Merkle
// quote, bounding the window of as-yet-unsealed (but still hash-chained) events.
func sealComplianceLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if complianceAudit == nil {
			return
		}
		if q, err := complianceAudit.Seal(); err != nil {
			log.Printf("⚠️  Compliance audit seal failed: %v", err)
		} else if q != nil {
			log.Printf("🔏 Compliance audit sealed batch #%d (events %d–%d)", q.SealID, q.SeqStart, q.SeqEnd)
		}
	}
}

// layerForDirection maps AgentArmor's traffic direction onto the conceptual
// L1–L8 boundary for the compliance control mapping.
func layerForDirection(direction string) audit.Layer {
	if strings.Contains(direction, "Response") {
		return audit.LayerOutput // L6 — output filtration / DLP
	}
	if strings.Contains(direction, "Request") {
		return audit.LayerExecution // L5 — tool execution / ingress
	}
	return audit.LayerUnspecified
}

// recordComplianceEvent appends one logAuditEvent occurrence to the sealed log.
// Fully fail-safe: never panics out, never blocks the caller meaningfully
// beyond a fast hash + buffered append. payloadSnippet is already sanitized by
// logAuditEvent (secrets redacted, PII masked) before it reaches here.
func recordComplianceEvent(clientIP, sessionKey, direction, action, ruleMatched, payloadSnippet string) {
	if complianceAudit == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("⚠️  Compliance audit append panic recovered: %v", r)
		}
	}()

	ev := audit.NewEvent(layerForDirection(direction), "audit_event", action).WithSource(clientIP)
	ev.SessionID = sessionKey
	ev.RuleMatched = ruleMatched
	ev.Output = payloadSnippet
	ev.Labels = map[string]string{"direction": direction}

	if _, err := complianceAudit.Append(ev); err != nil {
		log.Printf("⚠️  Compliance audit append failed: %v", err)
	}
}

// closeComplianceAudit seals and closes the log (call on graceful shutdown).
func closeComplianceAudit() {
	if complianceAudit != nil {
		_ = complianceAudit.Close()
	}
}

// complianceAuditActive reports whether the sealed audit log is running
// (consumed by the module registry; stubbed in the lite flavor).
func complianceAuditActive() bool { return complianceAudit != nil }
