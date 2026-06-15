//go:build !lite

package main

// Wiring for the Verifiable Human-in-the-Loop escalation matrix (Compliance
// Phase 2). Bridges AgentArmor's existing Zero-Trust tool-approval queue into
// compliance/hitl: when a high-risk tool call is suspended for approval we
// raise a signed EscalationRequest; when an admin approves/denies, the
// operator's verified identity is cryptographically bound to the decision and
// the signed approval is written into the Phase-1 sealed audit log.
//
// Fail-safe: when the matrix is disabled/uninitialized every helper is a no-op
// and the existing approval flow is unchanged.

import (
	"encoding/json"
	"log"
	"net/http"

	"agentarmor/compliance/audit"
	"agentarmor/compliance/hitl"
)

var complianceHITL *hitl.Matrix

// hitlAuditSink delivers each escalation into the tamper-evident audit log, so
// the moment of escalation (not just the decision) is itself non-repudiable.
type hitlAuditSink struct{}

func (hitlAuditSink) Route(req hitl.EscalationRequest) error {
	if complianceAudit == nil {
		return nil
	}
	ev := audit.NewEvent(audit.Layer(req.Layer), "hitl_escalation", "ESCALATED")
	ev.SessionID = req.SessionID
	ev.AgentID = req.AgentID
	ev.TenantID = req.TenantID
	ev.Tool = &audit.Tool{Name: req.Tool, Parameters: req.Parameters}
	ev.RuleMatched = req.RiskReason
	ev.Labels = map[string]string{
		"escalation_id":  req.ID,
		"payload_digest": req.PayloadDigest(),
	}
	_, err := complianceAudit.Append(ev)
	return err
}

// initComplianceHITL builds the escalation matrix with the shared signer.
func initComplianceHITL(signer audit.SealSigner) {
	m, err := hitl.NewMatrix(signer, hitlAuditSink{})
	if err != nil {
		log.Printf("⚠️  HITL matrix init failed: %v", err)
		return
	}
	complianceHITL = m
	log.Println("🧑‍⚖️  HITL escalation matrix active — approvals are operator-signed")
}

// hitlEscalate raises an escalation for a suspended tool call and returns its
// id (empty when HITL is disabled). Called from requestToolApproval.
func hitlEscalate(sessionKey, tool, fingerprint, issue string) string {
	if complianceHITL == nil {
		return ""
	}
	reason := issue
	if reason == "" {
		reason = "high-risk tool requires Zero-Trust approval"
	}
	req := hitl.EscalationRequest{
		SessionID:  sessionKey,
		Layer:      "L5",
		Tool:       tool,
		RiskReason: reason,
		RiskScore:  1.0, // suspended high-risk action; refined scoring can replace this
	}
	if fingerprint != "" {
		req.Parameters = map[string]interface{}{"target_fingerprint": fingerprint}
	}
	return complianceHITL.Escalate(req).ID
}

// hitlEnrichEscalation attaches the full tool parameters and the originating
// input prompt to a pending escalation, so the human reviewer sees exactly what
// the agent intended to run. Called from scanPayload where this context is in
// scope. No-op once the escalation is resolved.
func hitlEnrichEscalation(approvalID string, args []byte, prompt string) {
	if complianceHITL == nil {
		return
	}
	escID := escalationIDForApproval(approvalID)
	if escID == "" {
		return
	}
	var params map[string]interface{}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &params); err != nil {
			params = map[string]interface{}{"raw": string(args)}
		}
	}
	const maxPrompt = 600
	if len(prompt) > maxPrompt {
		prompt = prompt[:maxPrompt] + "…"
	}
	complianceHITL.Enrich(escID, params, prompt, "")
}

// operatorFromRequest derives the verified human identity from the auth context
// of an approval HTTP request — OIDC session when available, else the static
// admin token. The agent can never assert this itself.
func operatorFromRequest(r *http.Request) hitl.Operator {
	if oidcEnabled {
		if sess := getSessionFromRequest(r); sess != nil {
			id := sess.Email
			if id == "" {
				id = sess.ID
			}
			return hitl.Operator{
				ID:        id,
				Name:      sess.Name,
				Method:    "oidc",
				SourceIP:  getClientIP(r),
				SessionID: sess.ID,
			}
		}
	}
	return hitl.Operator{ID: "admin-token", Method: "token", SourceIP: getClientIP(r)}
}

// escalationIDForApproval returns the HITL escalation id linked to a tool
// approval request (empty if none / not found). Reads under the approvals lock.
func escalationIDForApproval(approvalID string) string {
	toolApprovalsLock.RLock()
	defer toolApprovalsLock.RUnlock()
	if req, ok := toolApprovals[approvalID]; ok {
		return req.EscalationID
	}
	return ""
}

// recordHITLDecision binds the operator to an approve/deny decision, producing a
// signed, verifiable approval that is written into the sealed audit log. No-op
// when HITL is disabled or the approval carries no escalation id. decision is
// "approved" or "denied".
func recordHITLDecision(approvalID, escalationID, decision string, r *http.Request) {
	if complianceHITL == nil || escalationID == "" {
		return
	}
	op := operatorFromRequest(r)
	appr, err := complianceHITL.Resolve(escalationID, hitl.Decision(decision), op)
	if err != nil {
		log.Printf("⚠️  HITL resolve failed (escalation %s): %v", escalationID, err)
		return
	}
	// Surface the operator-bound signature on the approval record so the Repave
	// dashboard can show who authorized it and the verifiable signature.
	toolApprovalsLock.Lock()
	if req, ok := toolApprovals[approvalID]; ok {
		req.OperatorID = op.ID
		req.SigAlgo = appr.SigAlgo
		req.Signature = appr.Signature
	}
	toolApprovalsLock.Unlock()
	if complianceAudit != nil {
		ev := audit.NewEvent(audit.LayerIdentity, "hitl_decision", string(decision)).WithSource(op.SourceIP)
		ev.AgentID = op.ID // the authorizing human is the actor for this record
		ev.RuleMatched = "operator-signed HITL decision"
		ev.Output = "signature=" + appr.Signature
		ev.Labels = map[string]string{
			"escalation_id":   appr.EscalationID,
			"payload_digest":  appr.PayloadDigest,
			"operator_id":     op.ID,
			"operator_method": op.Method,
			"sig_algo":        appr.SigAlgo,
			"key_id":          appr.KeyID,
		}
		if _, err := complianceAudit.Append(ev); err != nil {
			log.Printf("⚠️  HITL decision audit append failed: %v", err)
		}
	}
	log.Printf("🧑‍⚖️  HITL %s by %s (escalation %s) — signature bound", decision, op.ID, escalationID)
}
