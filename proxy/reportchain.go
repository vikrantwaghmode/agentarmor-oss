//go:build !lite

package main

// Wiring for the Autonomous Compliance Reporting engine (Compliance Phase 4 —
// ISO/IEC 42001 & SOC 2). Exposes admin-only, read-only endpoints that build a
// control-mapped report from the Phase-1 sealed audit log and stream it as PDF
// or Word, plus a JSON integrity-verification endpoint.

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"agentarmor/compliance/audit"
	"agentarmor/compliance/report"
)

// frameworksFromQuery maps the ?framework= query value to the catalog filter.
func frameworksFromQuery(v string) []report.Framework {
	switch strings.ToLower(v) {
	case "iso42001", "iso-42001", "aims":
		return []report.Framework{report.ISO42001}
	case "soc2", "soc-2", "soc":
		return []report.Framework{report.SOC2}
	case "gdpr":
		return []report.Framework{report.GDPR}
	case "hipaa":
		return []report.Framework{report.HIPAA}
	case "pci", "pcidss", "pci-dss":
		return []report.Framework{report.PCIDSS}
	case "iso27001", "iso-27001", "isms":
		return []report.Framework{report.ISO27001}
	case "nist", "nistairmf", "nist-ai-rmf", "airmf":
		return []report.Framework{report.NISTAIRMF}
	case "euaiact", "eu-ai-act", "aiact":
		return []report.Framework{report.EUAIAct}
	default:
		return nil // all frameworks
	}
}

// handleComplianceReport streams a generated compliance report.
// GET /armor/api/compliance/report?format=pdf|docx&framework=iso42001|soc2
func handleComplianceReport(w http.ResponseWriter, r *http.Request) {
	if complianceAudit == nil || complianceSigner == nil {
		http.Error(w, `{"error":"compliance audit log is disabled"}`, http.StatusServiceUnavailable)
		return
	}
	// Seal any pending events so the report covers the very latest activity.
	_, _ = complianceAudit.Seal()

	q := r.URL.Query()
	model, err := report.Build(complianceAuditDir, complianceSigner, frameworksFromQuery(q.Get("framework"))...)
	if err != nil {
		http.Error(w, `{"error":"failed to build report"}`, http.StatusInternalServerError)
		return
	}

	stamp := time.Now().UTC().Format("20060102-150405")
	switch strings.ToLower(q.Get("format")) {
	case "docx", "word":
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		w.Header().Set("Content-Disposition", `attachment; filename="agentarmor-compliance-`+stamp+`.docx"`)
		_ = report.WriteDOCX(model, w)
	case "json":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model)
	default: // pdf
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="agentarmor-compliance-`+stamp+`.pdf"`)
		_ = report.WritePDF(model, w)
	}
}

// handleComplianceVerify returns the cryptographic integrity status of the log.
// GET /armor/api/compliance/verify
func handleComplianceVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if complianceAudit == nil || complianceSigner == nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"enabled": false})
		return
	}
	_, _ = complianceAudit.Seal()
	rep, err := audit.Verify(complianceAuditDir, complianceSigner)
	if err != nil {
		http.Error(w, `{"error":"verification failed to run"}`, http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":        true,
		"verified":       rep.OK,
		"records":        rep.Records,
		"seals":          rep.Seals,
		"sealed_records": rep.SealedRecords,
		"problems":       rep.Problems,
	})
}
