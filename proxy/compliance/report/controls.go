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
	ISO42001  Framework = "ISO/IEC 42001"
	SOC2      Framework = "SOC 2"
	GDPR      Framework = "GDPR"
	HIPAA     Framework = "HIPAA"
	PCIDSS    Framework = "PCI DSS v4.0"
	ISO27001  Framework = "ISO/IEC 27001"
	NISTAIRMF Framework = "NIST AI RMF"
	EUAIAct   Framework = "EU AI Act"
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

// anyEvent matches every audit record — used for "record-keeping / logging"
// controls where the immutable log's mere existence and completeness is the
// evidence (the log captures every action).
func anyEvent(audit.AuditEvent) bool { return true }

// ── reusable capability predicates (shared across frameworks) ──
func human(e audit.AuditEvent) bool {
	return actionIs(e, "hitl_decision", "hitl_escalation") || layerIs(e, audit.LayerIdentity)
}
func access(e audit.AuditEvent) bool {
	return layerIs(e, audit.LayerIdentity, audit.LayerInterAgent) || ruleHas(e, "Zero-Trust") || actionIs(e, "hitl_decision")
}
func dataProtection(e audit.AuditEvent) bool { return outcomeIs(e, "REDACTED") }
func paymentData(e audit.AuditEvent) bool    { return ruleHas(e, "Payment Data Masked", "PAN", "SAD") }
func monitoring(e audit.AuditEvent) bool     { return outcomeIs(e, "BLOCKED", "ALERTED") }
func riskAssessment(e audit.AuditEvent) bool {
	return ruleHas(e, "High-Risk Sequence", "Anomaly", "Zero-Trust") || actionIs(e, "hitl_escalation")
}
func egress(e audit.AuditEvent) bool {
	return layerIs(e, audit.LayerExecution) || ruleHas(e, "SSRF", "Internal IP", "DNS Rebinding", "Firewall", "Rate Limit", "Blast Radius")
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

		// ── GDPR (General Data Protection Regulation) ──
		{ID: "Art. 22", Framework: GDPR, Title: "Automated Decisions & Human Oversight",
			Description: "High-risk autonomous actions are suspended and routed to an operator-signed human decision, so significant decisions are not based solely on automated processing.",
			Match:       human},
		{ID: "Art. 32", Framework: GDPR, Title: "Security of Processing",
			Description: "Personal data is masked in transit/at rest, and every action is recorded in a tamper-evident log providing integrity and confidentiality of processing.",
			Match:       dataProtection},
		{ID: "Art. 25", Framework: GDPR, Title: "Data Protection by Design & Least Privilege",
			Description: "Scoped, just-in-time agent identities enforce data minimization and purpose limitation.",
			Match:       access},
		{ID: "Art. 30", Framework: GDPR, Title: "Records of Processing Activities",
			Description: "The immutable audit log is a complete, cryptographically-sealed record of every processing activity.",
			Match:       anyEvent},

		// ── HIPAA Security Rule ──
		{ID: "164.312(a)", Framework: HIPAA, Title: "Access Control",
			Description: "Unique, scoped agent identities and Zero-Trust tool approval restrict access to ePHI to the minimum necessary.",
			Match:       access},
		{ID: "164.312(b)", Framework: HIPAA, Title: "Audit Controls",
			Description: "Hardware/software mechanisms record and examine activity in systems that contain ePHI (the sealed audit log).",
			Match:       anyEvent},
		{ID: "164.312(c)", Framework: HIPAA, Title: "Integrity",
			Description: "ePHI is protected from improper alteration; the BLAKE3/Merkle chain makes any tampering detectable.",
			Match:       monitoring},
		{ID: "164.312(e)", Framework: HIPAA, Title: "Transmission Security",
			Description: "Egress controls (SSRF/DNS-rebinding/firewall) guard ePHI against transmission to unauthorized endpoints.",
			Match:       egress},

		// ── PCI DSS v4.0 ──
		{ID: "Req. 3", Framework: PCIDSS, Title: "Protect Stored Account Data",
			Description: "Primary Account Numbers are masked to last-4 and Sensitive Authentication Data is purged before any persistence.",
			Match:       paymentData},
		{ID: "Req. 4", Framework: PCIDSS, Title: "Protect Cardholder Data in Transit",
			Description: "Strict egress allow-listing routes payment traffic only to approved processors over TLS.",
			Match:       egress},
		{ID: "Req. 7", Framework: PCIDSS, Title: "Restrict Access by Need-to-Know",
			Description: "Only specific agents under verified sessions may invoke payment tools.",
			Match:       access},
		{ID: "Req. 10", Framework: PCIDSS, Title: "Log & Monitor All Access",
			Description: "Every access to system components and cardholder data is tracked in the tamper-evident log.",
			Match:       anyEvent},

		// ── ISO/IEC 27001:2022 Annex A ──
		{ID: "A.5.15", Framework: ISO27001, Title: "Access Control",
			Description: "Role-based, least-privilege access is enforced for agent identities and tools.",
			Match:       access},
		{ID: "A.8.12", Framework: ISO27001, Title: "Data Leakage Prevention",
			Description: "Secrets, PII, and payment data are detected and redacted before leaving the boundary.",
			Match:       dataProtection},
		{ID: "A.8.15", Framework: ISO27001, Title: "Logging",
			Description: "Activity, exceptions, and security events are recorded in an immutable log.",
			Match:       anyEvent},
		{ID: "A.8.16", Framework: ISO27001, Title: "Monitoring Activities",
			Description: "Anomalous behavior and policy violations are detected and responded to in real time.",
			Match:       monitoring},

		// ── NIST AI Risk Management Framework (AI RMF 1.0) ──
		{ID: "GOVERN", Framework: NISTAIRMF, Title: "Accountability & Human Oversight",
			Description: "Authenticated identities and operator-signed approvals establish accountability over agent actions.",
			Match:       human},
		{ID: "MAP", Framework: NISTAIRMF, Title: "Context & Risk Identification",
			Description: "Semantic risk scoring identifies the intent and potential impact of an action before execution.",
			Match:       riskAssessment},
		{ID: "MEASURE", Framework: NISTAIRMF, Title: "Risk Measurement & Monitoring",
			Description: "Threats are continuously detected and quantified against configured thresholds.",
			Match:       monitoring},
		{ID: "MANAGE", Framework: NISTAIRMF, Title: "Risk Response & Mitigation",
			Description: "High-risk actions are blocked, escalated to humans, or redacted to mitigate impact.",
			Match: func(e audit.AuditEvent) bool {
				return monitoring(e) || dataProtection(e) || human(e)
			}},

		// ── EU AI Act (high-risk system obligations) ──
		{ID: "Art. 14", Framework: EUAIAct, Title: "Human Oversight",
			Description: "High-risk actions are intercepted for meaningful human review with a bound operator identity.",
			Match:       human},
		{ID: "Art. 12", Framework: EUAIAct, Title: "Record-Keeping (Logging)",
			Description: "Automatic, tamper-evident logging captures events over the system's lifetime.",
			Match:       anyEvent},
		{ID: "Art. 15", Framework: EUAIAct, Title: "Accuracy, Robustness & Cybersecurity",
			Description: "Prompt-injection, malicious-content, and exfiltration defenses harden the system against manipulation.",
			Match: func(e audit.AuditEvent) bool {
				return monitoring(e) || ruleHas(e, "Prompt Injection", "Malicious", "Canary")
			}},
	}
}
