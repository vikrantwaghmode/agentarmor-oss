// Package report implements AgentArmor's autonomous compliance reporting
// engine (Compliance Phase 4 — ISO/IEC 42001 & SOC 2). It is a read-only
// consumer of the Phase-1 tamper-evident audit log: it loads the sealed
// records, verifies their cryptographic integrity, maps each runtime event onto
// the relevant regulatory control, and renders an auditor-ready PDF or Word
// report whose statistics are backed by BLAKE3 evidence hashes.
//
// The mapping is deterministic (rule-based), which is the right choice for
// compliance evidence — an auditor can reproduce exactly why an event counts
// toward a control. An LLM summary could be layered on top, but the underlying
// attribution stays verifiable.
package report

import (
	"strings"

	"agentarmor/compliance/audit"
)

// Framework identifies a regulatory standard.
type Framework string

const (
	ISO42001 Framework = "ISO/IEC 42001"
	SOC2     Framework = "SOC 2"
)

// Control is one regulatory control and the predicate that decides whether an
// audit event constitutes operating evidence for it.
type Control struct {
	ID          string
	Framework   Framework
	Title       string
	Description string
	Match       func(audit.AuditEvent) bool
}

// ── small predicate helpers ──────────────────────────────────────────────────

func ruleHas(e audit.AuditEvent, subs ...string) bool {
	rm := strings.ToLower(e.RuleMatched)
	for _, s := range subs {
		if strings.Contains(rm, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func actionIs(e audit.AuditEvent, actions ...string) bool {
	for _, a := range actions {
		if e.Action == a {
			return true
		}
	}
	return false
}

func outcomeIs(e audit.AuditEvent, outcomes ...string) bool {
	for _, o := range outcomes {
		if e.Outcome == o {
			return true
		}
	}
	return false
}

func layerIs(e audit.AuditEvent, layers ...audit.Layer) bool {
	for _, l := range layers {
		if e.Layer == l {
			return true
		}
	}
	return false
}

// Catalog returns the control set AgentArmor maps runtime evidence onto. It is
// intentionally focused: each control corresponds to a capability AgentArmor
// actually enforces and logs, so "evidence count > 0" is a meaningful signal.
func Catalog() []Control {
	return []Control{
		// ── ISO/IEC 42001 Annex A ──
		{
			ID: "A.3", Framework: ISO42001, Title: "Internal Organization & Accountability",
			Description: "Every action is linked to an authenticated identity; high-risk actions carry an operator-signed human decision.",
			Match: func(e audit.AuditEvent) bool {
				return layerIs(e, audit.LayerIdentity) || actionIs(e, "hitl_decision")
			},
		},
		{
			ID: "A.4", Framework: ISO42001, Title: "Resources for AI Systems",
			Description: "Hard resource budgets — token-bucket rate limits and blast-radius caps — prevent unbounded consumption and cascading failure.",
			Match: func(e audit.AuditEvent) bool {
				return ruleHas(e, "Blast Radius", "Rate Limit")
			},
		},
		{
			ID: "A.5", Framework: ISO42001, Title: "Assessing AI System Impacts",
			Description: "Semantic risk scoring evaluates intent before irreversible actions; escalations record the assessed risk.",
			Match: func(e audit.AuditEvent) bool {
				return ruleHas(e, "High-Risk Sequence", "Anomaly", "Zero-Trust") || actionIs(e, "hitl_escalation")
			},
		},
		{
			ID: "A.7", Framework: ISO42001, Title: "Data for AI Systems",
			Description: "Ingestion and output data is integrity-checked; secrets/PII/payment data are masked before storage or context use.",
			Match: func(e audit.AuditEvent) bool {
				return outcomeIs(e, "REDACTED") || layerIs(e, audit.LayerIngestion, audit.LayerStorage)
			},
		},
		{
			ID: "A.9", Framework: ISO42001, Title: "Responsible Use of AI Systems",
			Description: "GoalLock anchoring and the output filter prevent goal hijacking, prompt injection, and semantic exfiltration.",
			Match: func(e audit.AuditEvent) bool {
				return layerIs(e, audit.LayerOutput, audit.LayerContext) || ruleHas(e, "Prompt Injection", "Canary", "Malicious", "GoalLock")
			},
		},

		// ── SOC 2 Trust Services Criteria ──
		{
			ID: "CC6.1", Framework: SOC2, Title: "Logical Access Controls",
			Description: "Scoped agent identities and Zero-Trust tool approval restrict access to least privilege.",
			Match: func(e audit.AuditEvent) bool {
				return layerIs(e, audit.LayerIdentity, audit.LayerInterAgent) || actionIs(e, "hitl_decision") || ruleHas(e, "Zero-Trust")
			},
		},
		{
			ID: "CC7.2", Framework: SOC2, Title: "System Monitoring & Anomaly Detection",
			Description: "Security events are detected and responded to in real time; every event is captured in the tamper-evident log.",
			Match: func(e audit.AuditEvent) bool {
				return outcomeIs(e, "BLOCKED", "ALERTED")
			},
		},
		{
			ID: "A1.2", Framework: SOC2, Title: "Availability — Capacity & Throttling",
			Description: "Rate limiting and blast-radius caps protect availability against resource-exhaustion and denial-of-wallet attacks.",
			Match: func(e audit.AuditEvent) bool {
				return ruleHas(e, "Blast Radius", "Rate Limit")
			},
		},
		{
			ID: "PI1.4", Framework: SOC2, Title: "Processing Integrity",
			Description: "Tool executions are governed and recorded with cryptographic integrity; human approvals gate high-risk actions.",
			Match: func(e audit.AuditEvent) bool {
				return e.Tool != nil || actionIs(e, "hitl_decision") || layerIs(e, audit.LayerExecution)
			},
		},
		{
			ID: "C1.1", Framework: SOC2, Title: "Confidentiality — Output Protection",
			Description: "Secrets, PII, and payment data are stripped from outputs before transmission or persistence.",
			Match: func(e audit.AuditEvent) bool {
				return outcomeIs(e, "REDACTED")
			},
		},
	}
}
