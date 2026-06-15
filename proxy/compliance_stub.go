//go:build lite

package main

// Lite build flavor: the entire compliance engine (sealed audit log, HITL,
// PCI deep inspection, reporting) is compiled OUT. This drops the blake3 and
// fpdf dependencies and the compliance/* subpackages from the binary, shrinking
// it and reducing attack surface for latency-sensitive / minimal deployments.
//
// These no-op facades satisfy the references main.go / profiles.go make to the
// compliance wiring (which lives behind `//go:build !lite`), so the core L7
// firewall builds and runs identically without the enterprise compliance layer.
// Build the full flavor by omitting the `lite` tag (the default).

import "net/http"

// ── audit log (Phase 1) ──
func recordComplianceEvent(_, _, _, _, _, _ string) {}
func initComplianceAudit()                          {}
func complianceAuditActive() bool                   { return false }

// ── PCI deep inspection (Phase 3) ──
func initComplianceDLP()                    {}
func complianceDLPActive() bool             { return false }
func pciEnabled() bool                      { return false }
func pciScan(string) (bool, string)         { return false, "" }
func maskPaymentData(content string) string { return content }

// ── HITL (Phase 2) ──
func hitlEscalate(_, _, _, _ string) string              { return "" }
func hitlEnrichEscalation(_ string, _ []byte, _ string)  {}
func escalationIDForApproval(string) string              { return "" }
func recordHITLDecision(_, _, _ string, _ *http.Request) {}

// ── reporting + verify API (Phase 4) ──
func handleComplianceVerify(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"enabled":false,"flavor":"lite"}`))
}

func handleComplianceReport(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, `{"error":"compliance reporting is not built into the lite flavor"}`, http.StatusNotImplemented)
}
