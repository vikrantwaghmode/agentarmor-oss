// Package audit implements AgentArmor's cryptographically immutable audit
// logging engine (Compliance Phase 1 — SOC 2 Processing Integrity & ISO 27001).
//
// It turns AgentArmor's mutable operational events into a tamper-evident,
// SIEM-ready log: every event is serialized to a canonical JSON form, hashed
// with BLAKE3, hash-chained to its predecessor, and periodically sealed into a
// Merkle root that is signed (HMAC-SHA256 or Ed25519) into an attestation
// quote. Any later edit, deletion, or reordering of the log breaks the chain,
// the Merkle root, or the signature during Verify().
//
// The package is self-contained (no dependency on AgentArmor's package main),
// so it is imported by main and exercised by its own tests.
package audit

import (
	"net"
	"time"
)

// SchemaVersion is bumped whenever the on-disk AuditEvent shape changes. It is
// part of the hashed body, so verifiers can detect a schema downgrade attack.
const SchemaVersion = "1.0"

// Layer identifies which defense-in-depth boundary emitted the event. These map
// to AgentArmor's conceptual L1–L8 model and to the compliance control mapping
// used by the Phase 4 reporting engine.
type Layer string

const (
	LayerIngestion   Layer = "L1"          // input scanning
	LayerStorage     Layer = "L2"          // data at rest
	LayerContext     Layer = "L3"          // context assembly / GoalLock
	LayerPlanning    Layer = "L4"          // risk scoring / action chains
	LayerExecution   Layer = "L5"          // tool execution / egress
	LayerOutput      Layer = "L6"          // output filtration / DLP
	LayerInterAgent  Layer = "L7"          // inter-agent auth
	LayerIdentity    Layer = "L8"          // identity / IAM
	LayerUnspecified Layer = "unspecified" // generic / bridged events
)

// Tool captures the exact tool invocation parameters at an execution boundary.
type Tool struct {
	Name       string                 `json:"name"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// AuditEvent is the SIEM-ready event body. The field set is deliberately
// flat-ish and stable so it maps cleanly onto Datadog/Splunk/OpenTelemetry
// pipelines. This struct is the *hashed body*: integrity metadata lives in
// SealedRecord and is never folded back into the event before hashing.
//
// NOTE: never put plaintext cardholder data, secrets, or full PII in here — the
// Phase 3 inspection layer masks those before an event reaches the log, which
// is exactly what PCI DSS Req. 3/10 require (log the action, not the PAN).
type AuditEvent struct {
	SchemaVersion string `json:"schema_version"`
	EventID       string `json:"event_id"`   // unique per event (UUID-ish)
	Timestamp     string `json:"@timestamp"` // RFC3339Nano, UTC — ECS/OTel friendly
	AgentID       string `json:"agent_id"`   // actor (the agent / token subject)
	SessionID     string `json:"session_id"` // session key
	TenantID      string `json:"tenant_id,omitempty"`
	SourceIP      string `json:"source_ip,omitempty"` // IPv4 or IPv6 of the originating request
	Layer         Layer  `json:"layer"`               // L1–L8

	Action  string `json:"action"`  // e.g. "tool_call", "scan", "approval"
	Outcome string `json:"outcome"` // ALLOWED | BLOCKED | ALERTED | APPROVED | DENIED

	Tool           *Tool  `json:"tool,omitempty"`            // executed tool + parameters
	ReasoningTrace string `json:"reasoning_trace,omitempty"` // non-deterministic agent rationale
	Output         string `json:"output,omitempty"`          // deterministic tool/scan output
	RuleMatched    string `json:"rule_matched,omitempty"`    // scanner/policy that fired

	// Labels carries arbitrary structured context (compliance tags, control
	// hints, request metadata). Map keys are sorted during canonicalization.
	Labels map[string]string `json:"labels,omitempty"`
}

// NewEvent stamps the schema version and a UTC RFC3339Nano timestamp, returning
// a partially-populated event the caller fills in. Timestamp can be overridden.
func NewEvent(layer Layer, action, outcome string) AuditEvent {
	return AuditEvent{
		SchemaVersion: SchemaVersion,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Layer:         layer,
		Action:        action,
		Outcome:       outcome,
	}
}

// normalizeIP returns a canonical textual form of an IP (collapsing IPv6 zero
// groups, stripping ports), or the input unchanged if it isn't a bare IP. This
// keeps the hashed representation stable regardless of how the caller formatted
// the address.
func normalizeIP(s string) string {
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// WithSource sets a normalized source IP and returns the event for chaining.
func (e AuditEvent) WithSource(ip string) AuditEvent {
	e.SourceIP = normalizeIP(ip)
	return e
}
