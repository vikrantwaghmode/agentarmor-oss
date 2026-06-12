package main

// Execution Containment Scanner — Phase 3.1.
//
// AgentArmor is a JSON-level reverse proxy: it never spawns or executes
// agent code itself (that happens entirely inside the gateway process that
// fronts the LLM). What it CAN do — and what this scanner does — is inspect
// the `args` of `exec`-type tool calls (the already-parsed
// mcpToolCallEnvelope, `{"tool":"...","args":{...}}`) for container-escape,
// destructive-filesystem, and firewall-tampering patterns BEFORE the call
// reaches the gateway.
//
// This is deliberately independent of the Zero-Trust Tool Approval gate: a
// session that holds tool:exec approval is trusted to run shell commands at
// all, but a "critical" finding here (e.g. `rm -rf /`, mounting
// /proc/1/root, flushing AgentArmor's own egress firewall) hard-blocks the
// call regardless of that approval — closing the gap between "may run exec"
// and "may run THIS command". High/medium findings are surfaced as alerts
// without blocking.

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ─── Policy section ───────────────────────────────────────────────────────────

// ExecutionScanningConfig is the execution_scanning policy block.
type ExecutionScanningConfig struct {
	Enabled  bool           `yaml:"enabled" json:"enabled"`
	Tools    []string       `yaml:"tools" json:"tools"`
	Patterns []ExecScanRule `yaml:"patterns" json:"patterns"`
}

// ExecScanRule is one containment pattern checked against the raw `args`
// JSON of a scanned tool call.
type ExecScanRule struct {
	ID          string `yaml:"id" json:"id"`
	Severity    string `yaml:"severity" json:"severity"` // critical | high | medium | low
	Regex       string `yaml:"regex" json:"regex"`
	Description string `yaml:"description" json:"description"`
	Enabled     bool   `yaml:"enabled" json:"enabled"`
}

// ─── findings ───────────────────────────────────────────────────────────────

// ExecFinding describes one containment issue found in a tool call's args.
type ExecFinding struct {
	Tool     string `json:"tool"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"` // critical | high | medium | low
	Issue    string `json:"issue"`
	Snippet  string `json:"snippet"`
}

// isExecScanTarget reports whether tool is one of the configured
// execution_scanning.tools (case-insensitive).
func isExecScanTarget(tool string, tools []string) bool {
	for _, t := range tools {
		if strings.EqualFold(tool, t) {
			return true
		}
	}
	return false
}

// auditExecArgs runs every enabled, precompiled pattern in regexes against
// the raw `args` JSON of a tool call and returns one finding per matching
// rule. regexes and rules are index-aligned, mirroring
// compiledMaliciousRegexes / policy.Scanners.MaliciousContent.BlockPatterns.
func auditExecArgs(tool string, args json.RawMessage, regexes []*regexp.Regexp, rules []ExecScanRule) []ExecFinding {
	text := string(args)
	var findings []ExecFinding
	for i, rule := range rules {
		if !rule.Enabled || i >= len(regexes) || regexes[i] == nil {
			continue
		}
		if loc := regexes[i].FindStringIndex(text); loc != nil {
			findings = append(findings, ExecFinding{
				Tool:     tool,
				RuleID:   rule.ID,
				Severity: rule.Severity,
				Issue:    rule.Description,
				Snippet:  snippetAround(text, loc[0], loc[1]),
			})
		}
	}
	return findings
}
