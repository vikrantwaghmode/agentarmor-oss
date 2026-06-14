package hitl

import (
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"lukechampine.com/blake3"

	"agentarmor/compliance/audit"
)

// SignedApproval is the verifiable record of a human decision. Its signature
// binds the operator's identity, the decision, and the exact escalation payload
// digest together — so the resumed (or rejected) execution path is provably
// attributable to a specific human, satisfying GDPR Art. 22 "meaningful human
// review". Reusing audit.SealSigner means HITL approvals and the audit log
// share one key/rotation policy.
type SignedApproval struct {
	Type          string   `json:"type"` // "agentarmor.hitl.approval"
	EscalationID  string   `json:"escalation_id"`
	PayloadDigest string   `json:"payload_digest"` // hex, ties decision to the exact request
	Decision      Decision `json:"decision"`
	Operator      Operator `json:"operator"`
	DecidedAt     string   `json:"decided_at"` // RFC3339Nano UTC
	SigAlgo       string   `json:"sig_algo"`
	KeyID         string   `json:"key_id"`
	Signature     string   `json:"signature"` // hex over signingDigest()
}

// signingDigest binds every accountability-relevant field. The signature field
// itself is excluded (it is the output).
func (a SignedApproval) signingDigest() []byte {
	h := blake3.New(32, nil)
	h.Write([]byte{prefixDecision})
	for _, s := range []string{
		a.Type, a.EscalationID, a.PayloadDigest, string(a.Decision),
		a.Operator.ID, a.Operator.Method, a.Operator.SessionID, a.DecidedAt,
	} {
		h.Write([]byte{0x1f}) // field separator so concatenation is unambiguous
		h.Write([]byte(s))
	}
	return h.Sum(nil)
}

// VerifySignature recomputes the digest and checks the operator-bound signature.
func (a SignedApproval) VerifySignature(signer audit.SealSigner) bool {
	sig, err := hex.DecodeString(a.Signature)
	if err != nil {
		return false
	}
	return signer.Verify(a.signingDigest(), sig)
}

// Sink receives an escalation payload for delivery to a human (dashboard queue,
// enterprise ticketing system, webhook, …). Routing failures are non-fatal: the
// escalation is still recorded and visible in the dashboard queue.
type Sink interface {
	Route(EscalationRequest) error
}

// pending pairs a live escalation with its resolution (nil until decided).
type pending struct {
	Req      EscalationRequest
	Approval *SignedApproval
}

// Matrix is the escalation broker: it records escalations, routes them to
// sinks, and produces operator-bound signed decisions. Safe for concurrent use.
type Matrix struct {
	mu     sync.RWMutex
	signer audit.SealSigner
	sinks  []Sink
	items  map[string]*pending
}

// NewMatrix builds an escalation matrix backed by the given signer and sinks.
func NewMatrix(signer audit.SealSigner, sinks ...Sink) (*Matrix, error) {
	if signer == nil {
		return nil, errors.New("hitl: signer is required")
	}
	return &Matrix{signer: signer, sinks: sinks, items: map[string]*pending{}}, nil
}

// Escalate stamps, stores, and routes a new escalation, returning the populated
// request (with ID/timestamp). Routing errors are swallowed (best-effort
// delivery) — the escalation is always queued regardless.
func (m *Matrix) Escalate(req EscalationRequest) EscalationRequest {
	if req.SchemaVersion == "" {
		req.SchemaVersion = SchemaVersion
	}
	if req.ID == "" {
		req.ID = newID()
	}
	if req.CreatedAt == "" {
		req.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	m.mu.Lock()
	m.items[req.ID] = &pending{Req: req}
	m.mu.Unlock()

	for _, s := range m.sinks {
		_ = s.Route(req)
	}
	return req
}

// Resolve binds an operator's identity to a decision and returns a signed
// approval. It is idempotent-safe: a second resolve of the same escalation
// returns the existing approval. Returns an error if the escalation is unknown.
func (m *Matrix) Resolve(escalationID string, decision Decision, op Operator) (*SignedApproval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.items[escalationID]
	if !ok {
		return nil, errors.New("hitl: unknown escalation id")
	}
	if p.Approval != nil {
		return p.Approval, nil
	}
	if decision != Approved && decision != Denied {
		return nil, errors.New("hitl: invalid decision")
	}
	a := &SignedApproval{
		Type:          "agentarmor.hitl.approval",
		EscalationID:  escalationID,
		PayloadDigest: p.Req.PayloadDigest(),
		Decision:      decision,
		Operator:      op,
		DecidedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	sig, algo, keyID := m.signer.Sign(a.signingDigest())
	a.SigAlgo = algo
	a.KeyID = keyID
	a.Signature = hex.EncodeToString(sig)
	p.Approval = a
	return a, nil
}

// Enrich augments a still-pending escalation with richer reviewer context
// (tool parameters, the input prompt, the reasoning trace) discovered after the
// escalation was first raised. It is a no-op once the escalation has been
// resolved, so it can never mutate a payload an operator has already signed.
// Parameters are merged (existing keys preserved).
func (m *Matrix) Enrich(escalationID string, params map[string]interface{}, prompt, reasoning string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.items[escalationID]
	if !ok || p.Approval != nil {
		return false
	}
	if len(params) > 0 {
		if p.Req.Parameters == nil {
			p.Req.Parameters = map[string]interface{}{}
		}
		for k, v := range params {
			p.Req.Parameters[k] = v
		}
	}
	if prompt != "" {
		p.Req.InputPrompt = prompt
	}
	if reasoning != "" {
		p.Req.ReasoningTrace = reasoning
	}
	return true
}

// Get returns the escalation and its approval (approval is nil while pending).
func (m *Matrix) Get(escalationID string) (EscalationRequest, *SignedApproval, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.items[escalationID]
	if !ok {
		return EscalationRequest{}, nil, false
	}
	return p.Req, p.Approval, true
}

// Verify rechecks that an approval's signature is valid AND that it actually
// corresponds to the stored escalation payload (defending against an approval
// being replayed onto a different request). Used by the Phase 4 reporter and by
// the execution gate before resuming a held action.
func (m *Matrix) Verify(a *SignedApproval) bool {
	if a == nil || !a.VerifySignature(m.signer) {
		return false
	}
	m.mu.RLock()
	p, ok := m.items[a.EscalationID]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	return p.Req.PayloadDigest() == a.PayloadDigest
}
