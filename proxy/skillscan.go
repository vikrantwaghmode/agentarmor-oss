package main

// Intent-based skill scanning & supply-chain defense — Phase 2.1.
//
// Every skill loaded from ./skills/<id>/ (skill.yaml's name/description/
// keywords/system_prompt, plus knowledge/*.md) is scanned against
// configurable patterns for "dual-vector" toxic-skill indicators: malicious
// intent can live in the natural-language layer (prompt-injection directives
// aimed at the orchestrating agent, embedded in a skill's own instructions)
// as well as in embedded shell/code snippets (pipe-to-shell, obfuscated
// base64 payloads, credential exfiltration) — the pattern documented by the
// Snyk ToxicSkills research on the ClawHavoc campaign.
//
// A "critical" finding quarantines the skill (when block_critical is true):
// DetectSkill stops selecting it (header, marker, keyword, and semantic
// routing all skip it) and BuildSkillContext/BuildCombinedSkillContext
// withhold its content, until the skill or the matching pattern is fixed and
// the policy is reloaded.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ─── Policy section ───────────────────────────────────────────────────────────

// SkillScanningConfig is the skill_scanning policy block.
type SkillScanningConfig struct {
	Enabled       bool            `yaml:"enabled" json:"enabled"`
	BlockCritical bool            `yaml:"block_critical" json:"block_critical"`
	Patterns      []SkillScanRule `yaml:"patterns" json:"patterns"`
}

// SkillScanRule is one behavioral-intent pattern checked against a skill's
// combined text content (system prompt, description, keywords, knowledge docs).
type SkillScanRule struct {
	ID          string `yaml:"id" json:"id"`
	Severity    string `yaml:"severity" json:"severity"` // critical | high | medium | low
	Regex       string `yaml:"regex" json:"regex"`
	Description string `yaml:"description" json:"description"`
	Enabled     bool   `yaml:"enabled" json:"enabled"`
}

// ─── findings ───────────────────────────────────────────────────────────────

// SkillFinding describes one behavioral-intent issue found in a loaded skill.
type SkillFinding struct {
	SkillID  string `json:"skill_id"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"` // critical | high | medium | low
	Issue    string `json:"issue"`
	Snippet  string `json:"snippet"`
}

// skillContentText concatenates everything in a skill that ends up in the
// agent's context — the natural-language layer (name, description, keywords,
// system prompt) and its knowledge docs (which may embed shell/code snippets)
// — into a single string for pattern matching.
func skillContentText(skill *LoadedSkill) string {
	var sb strings.Builder
	sb.WriteString(skill.Config.Name)
	sb.WriteString("\n")
	sb.WriteString(skill.Config.Description)
	sb.WriteString("\n")
	sb.WriteString(strings.Join(skill.Config.Keywords, " "))
	sb.WriteString("\n")
	sb.WriteString(skill.Config.SystemPrompt)
	for _, doc := range skill.Docs {
		sb.WriteString("\n")
		sb.WriteString(doc.body)
	}
	return sb.String()
}

// auditSkillContent runs every enabled pattern in rules against skill's
// combined text content and returns one finding per matching rule.
func auditSkillContent(skill *LoadedSkill, rules []SkillScanRule) []SkillFinding {
	text := skillContentText(skill)
	var findings []SkillFinding
	for _, rule := range rules {
		if !rule.Enabled || rule.Regex == "" {
			continue
		}
		rx, err := regexp.Compile(rule.Regex)
		if err != nil {
			continue
		}
		if loc := rx.FindStringIndex(text); loc != nil {
			findings = append(findings, SkillFinding{
				SkillID:  skill.Config.ID,
				RuleID:   rule.ID,
				Severity: rule.Severity,
				Issue:    rule.Description,
				Snippet:  snippetAround(text, loc[0], loc[1]),
			})
		}
	}
	return findings
}

// snippetAround returns a short, single-line excerpt of text around
// [start,end) for display in the audit panel, rather than the full skill content.
func snippetAround(text string, start, end int) string {
	const pad = 30
	from := start - pad
	if from < 0 {
		from = 0
	}
	to := end + pad
	if to > len(text) {
		to = len(text)
	}
	s := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, text[from:to])
	s = strings.TrimSpace(s)
	if from > 0 {
		s = "…" + s
	}
	if to < len(text) {
		s = s + "…"
	}
	return s
}

// auditSkills runs auditSkillContent over every loaded skill and returns the
// full finding list plus the set of skill IDs quarantined by a "critical"
// finding (skill ID -> "rule-id: issue"). If cfg.Enabled is false, no
// scanning is performed and both return values are empty.
func auditSkills(cfg SkillScanningConfig) (findings []SkillFinding, quarantined map[string]string) {
	quarantined = make(map[string]string)
	if !cfg.Enabled {
		return findings, quarantined
	}

	skillsMu.RLock()
	skills := make([]*LoadedSkill, 0, len(loadedSkills))
	for _, s := range loadedSkills {
		skills = append(skills, s)
	}
	skillsMu.RUnlock()

	sort.Slice(skills, func(i, j int) bool { return skills[i].Config.ID < skills[j].Config.ID })

	for _, s := range skills {
		for _, f := range auditSkillContent(s, cfg.Patterns) {
			findings = append(findings, f)
			if f.Severity == "critical" && cfg.BlockCritical {
				if _, exists := quarantined[f.SkillID]; !exists {
					quarantined[f.SkillID] = fmt.Sprintf("%s: %s", f.RuleID, f.Issue)
				}
			}
		}
	}
	return findings, quarantined
}

// ─── audit cache ────────────────────────────────────────────────────────────
//
// Recomputed by loadPolicy() on every (re)load, so DetectSkill, ToggleSkill,
// and the dashboard's Skills panel never need to re-run the scan themselves.

var (
	skillAuditMu       sync.RWMutex
	skillAuditFindings = []SkillFinding{}
	skillQuarantined   = map[string]string{}
)

// setSkillAudit stores the latest skill-scanning audit results.
func setSkillAudit(findings []SkillFinding, quarantined map[string]string) {
	skillAuditMu.Lock()
	skillAuditFindings = findings
	skillQuarantined = quarantined
	skillAuditMu.Unlock()
}

// getSkillAudit returns the latest skill-scanning findings and quarantine map.
func getSkillAudit() ([]SkillFinding, map[string]string) {
	skillAuditMu.RLock()
	defer skillAuditMu.RUnlock()
	return skillAuditFindings, skillQuarantined
}

// skillIsQuarantined reports whether skillID is currently quarantined by the
// behavioral-intent scan, and why.
func skillIsQuarantined(skillID string) (reason string, ok bool) {
	skillAuditMu.RLock()
	defer skillAuditMu.RUnlock()
	reason, ok = skillQuarantined[skillID]
	return
}
