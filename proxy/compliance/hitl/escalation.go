// Package hitl implements AgentArmor's Verifiable Human-in-the-Loop escalation
// matrix (Compliance Phase 2 — GDPR Article 22 & the EU AI Act).
//
// When the L4 planning / L5 execution layers flag a tool call whose risk
// exceeds the configured threshold, the call is suspended and packaged into a
// signed EscalationRequest routed to a human operator. On resolution the
// operator's verified identity is cryptographically bound to the decision via a
// SignedApproval — an unbroken accountability chain proving a real human (not
// "solely automated processing") authorized the resumed execution.
//
// Signing reuses Phase 1's audit.SealSigner so one key policy covers both the
// audit log and HITL approvals. The package is self-contained and tested in
// isolation; main wires it into the existing tool-approval flow.
package hitl

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

	"lukechampine.com/blake3"
)

// SchemaVersion guards the on-the-wire escalation shape.
const SchemaVersion = "1.0"

// Decision is the operator's verdict on an escalation.
type Decision string

const (
	Approved Decision = "approved"
	Denied   Decision = "denied"
)

// Domain-separation prefixes for the two digests this package produces.
const (
	prefixPayload  byte = 0x10 // EscalationRequest payload digest
	prefixDecision byte = 0x11 // SignedApproval signing digest
)

// EscalationRequest is the secure payload handed to a human reviewer. It
// captures everything a reviewer (and later an auditor) needs to judge the
// action: the agent's reasoning, the originating prompt, the exact tool
// parameters, and why the system escalated.
type EscalationRequest struct {
	SchemaVersion  string                 `json:"schema_version"`
	ID             string                 `json:"id"`
	CreatedAt      string                 `json:"created_at"` // RFC3339Nano UTC
	AgentID        string                 `json:"agent_id,omitempty"`
	SessionID      string                 `json:"session_id"`
	TenantID       string                 `json:"tenant_id,omitempty"`
	Layer          string                 `json:"layer"` // L4 | L5
	Tool           string                 `json:"tool"`  // tool awaiting authorization
	Parameters     map[string]interface{} `json:"parameters,omitempty"`
	InputPrompt    string                 `json:"input_prompt,omitempty"`
	ReasoningTrace string                 `json:"reasoning_trace,omitempty"`
	RiskScore      float64                `json:"risk_score"`
	RiskReason     string                 `json:"risk_reason,omitempty"` // why it escalated (rule/threshold/sensitivity)
}

// payloadCanonical returns deterministic JSON of the request fields that the
// operator is attesting to. (All fields are immutable once created, so the
// whole struct is canonicalized.)
func (e EscalationRequest) payloadCanonical() []byte {
	b, _ := json.Marshal(e)
	return b
}

// PayloadDigest is the BLAKE3 digest of the escalation payload — the value the
// operator's signature is ultimately bound to.
func (e EscalationRequest) PayloadDigest() string {
	h := blake3.New(32, nil)
	h.Write([]byte{prefixPayload})
	h.Write(e.payloadCanonical())
	return hex.EncodeToString(h.Sum(nil))
}

// Operator is the verified human identity authorizing (or rejecting) an action.
// Identity is sourced from AgentArmor's auth context (OIDC subject/email, or a
// named service token) — never self-asserted by the agent.
type Operator struct {
	ID        string `json:"id"`             // OIDC subject / email / token label
	Name      string `json:"name,omitempty"` // display name when available
	Method    string `json:"method"`         // oidc | token
	SourceIP  string `json:"source_ip,omitempty"`
	SessionID string `json:"session_id,omitempty"` // operator's dashboard session
}

// newID returns a random hex id for an escalation.
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
