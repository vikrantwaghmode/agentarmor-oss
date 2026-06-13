package main

// Data-Sensitivity-Aware Governed Execution Grants — Phase 4.1.
//
// Zero-Trust Tool Approval (main.go) is per (session, tool): once an admin
// approves "exec" once, every future exec call for that session is approved,
// regardless of what it targets. This file adds target-data-sensitivity
// classification of a tool call's `args` so that a match narrows the
// approval from "this tool, forever this session" to "this tool against
// THIS target, for grant_ttl_minutes" — the realistic equivalent of a
// short-lived, target-bound execution grant.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
)

// ─── Policy section ───────────────────────────────────────────────────────────

// DataSensitivityConfig is the data_sensitivity policy block.
type DataSensitivityConfig struct {
	Enabled         bool              `yaml:"enabled" json:"enabled"`
	GrantTTLMinutes int               `yaml:"grant_ttl_minutes" json:"grant_ttl_minutes"`
	Patterns        []SensitivityRule `yaml:"patterns" json:"patterns"`
}

// SensitivityRule is one target-classification pattern checked against the
// raw `args` JSON of a tool call.
type SensitivityRule struct {
	ID          string `yaml:"id" json:"id"`
	Severity    string `yaml:"severity" json:"severity"` // critical | high | medium | low
	Regex       string `yaml:"regex" json:"regex"`
	Description string `yaml:"description" json:"description"`
	Enabled     bool   `yaml:"enabled" json:"enabled"`
}

// ─── findings ───────────────────────────────────────────────────────────────

// SensitivityFinding describes the highest-severity sensitivity match found
// in a tool call's args.
type SensitivityFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"` // critical | high | medium | low
	Issue    string `json:"issue"`
	Snippet  string `json:"snippet"`
}

var sensitivitySeverityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

// classifySensitivity runs every enabled, precompiled pattern in regexes
// against the raw `args` JSON of a tool call and returns the
// highest-severity match, or nil if none match. regexes and rules are
// index-aligned, mirroring auditExecArgs/compiledExecRegexes.
func classifySensitivity(args json.RawMessage, regexes []*regexp.Regexp, rules []SensitivityRule) *SensitivityFinding {
	text := string(args)
	var best *SensitivityFinding
	bestRank := -1
	for i, rule := range rules {
		if !rule.Enabled || i >= len(regexes) || regexes[i] == nil {
			continue
		}
		loc := regexes[i].FindStringIndex(text)
		if loc == nil {
			continue
		}
		rank := sensitivitySeverityRank[rule.Severity]
		if rank > bestRank {
			bestRank = rank
			best = &SensitivityFinding{
				RuleID:   rule.ID,
				Severity: rule.Severity,
				Issue:    rule.Description,
				Snippet:  snippetAround(text, loc[0], loc[1]),
			}
		}
	}
	return best
}

// targetFingerprint returns a short, stable identifier for a tool call's
// args — used to scope a Zero-Trust approval grant to a specific target
// (e.g. a specific file path or table name) rather than the tool as a whole.
func targetFingerprint(args json.RawMessage) string {
	sum := sha256.Sum256(args)
	return hex.EncodeToString(sum[:])[:12]
}
