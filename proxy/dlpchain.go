//go:build !lite

package main

// Wiring for deep data inspection / payment-data masking (Compliance Phase 3,
// PCI DSS Requirement 3). The detection + masking core lives in
// compliance/datainspect; this file gates it and formats audit reasons. It is
// invoked from scanPayload, which runs on both request (L1 ingestion) and
// response (L6 output) directions, so PANs/SAD are masked before the content is
// forwarded, written to disk, logged, or appended to the LLM context window.

import (
	"fmt"
	"log"
	"os"
	"strings"

	"agentarmor/compliance/datainspect"
)

var (
	complianceInspector  = datainspect.New()
	complianceDLPEnabled = true
)

// initComplianceDLP resolves the enable flag and logs OCR availability.
// Default ON; set COMPLIANCE_PCI_DLP_ENABLED=false to disable.
func initComplianceDLP() {
	if strings.EqualFold(os.Getenv("COMPLIANCE_PCI_DLP_ENABLED"), "false") {
		complianceDLPEnabled = false
		log.Println("ℹ️  PCI deep-data inspection disabled (COMPLIANCE_PCI_DLP_ENABLED=false)")
		return
	}
	if datainspect.OCRAvailable() {
		log.Println("🔎 PCI deep-data inspection active — PAN/SAD masking (OCR: tesseract detected)")
	} else {
		log.Println("🔎 PCI deep-data inspection active — PAN/SAD masking (OCR: tesseract not installed; text-layer only)")
	}
}

// dlpReason builds the audit rule string for a masking event. It reports COUNTS
// and brands only — never the masked values themselves (PCI Req. 3/10: log the
// action, not the cardholder data).
func dlpReason(r datainspect.Result) string {
	var parts []string
	if len(r.PANs) > 0 {
		brands := map[datainspect.Brand]int{}
		for _, p := range r.PANs {
			brands[p.Brand]++
		}
		var bs []string
		for b, n := range brands {
			bs = append(bs, fmt.Sprintf("%d×%s", n, b))
		}
		parts = append(parts, "PAN["+strings.Join(bs, ",")+"]")
	}
	if len(r.SAD) > 0 {
		kinds := map[datainspect.SADKind]int{}
		for _, s := range r.SAD {
			kinds[s.Kind]++
		}
		var ks []string
		for k, n := range kinds {
			ks = append(ks, fmt.Sprintf("%d×%s", n, k))
		}
		parts = append(parts, "SAD["+strings.Join(ks, ",")+"]")
	}
	return "Payment Data Masked (PCI DSS Req.3): " + strings.Join(parts, " ")
}

// maskPaymentData masks PAN/SAD in a single content string (used per-message).
func maskPaymentData(content string) string {
	return complianceInspector.Inspect(content).Masked
}

// ── Facade consumed by main.go / profiles.go (stubbed in the lite flavor) ──

// pciEnabled reports whether deep data inspection is active.
func pciEnabled() bool { return complianceDLPEnabled }

// complianceDLPActive mirrors pciEnabled for the module registry.
func complianceDLPActive() bool { return complianceDLPEnabled }

// pciScan inspects content for payment data, returning whether any was found
// and a count/brand audit reason (never the values).
func pciScan(content string) (bool, string) {
	det := complianceInspector.Inspect(content)
	if !det.Found() {
		return false, ""
	}
	return true, dlpReason(det)
}
