package main

// ATR (Agent Threat Rules) loader and evaluator.
//
// Loads YAML rule files from the atr-rules/ directory (recursively), compiles
// detection conditions, and evaluates them against every scanned payload.
//
// Rules are hot-reloaded every poll_interval_minutes (default: 60).
// Only stable rules are loaded by default; set include_experimental: true for
// experimental rules. Draft and deprecated rules are always skipped.
//
// Rule format: https://github.com/Agent-Threat-Rule/agent-threat-rules

import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ─── Policy section ───────────────────────────────────────────────────────────

type ATRConfig struct {
	Enabled             bool   `yaml:"enabled" json:"enabled"`
	RulesDir            string `yaml:"rules_dir" json:"rules_dir"`
	PollIntervalMinutes int    `yaml:"poll_interval_minutes" json:"poll_interval_minutes"`
	// MinSeverity filters out rules below this level.
	// Order: informational < low < medium < high < critical
	MinSeverity         string `yaml:"min_severity" json:"min_severity"`
	IncludeExperimental bool   `yaml:"include_experimental" json:"include_experimental"`
}

// ─── ATR YAML structs — matches agent-threat-rules corpus schema ──────────────

// atrAgentSource handles both string form ("llm_io") and struct form
// ({type: llm_io, framework: [...]}) used in the actual corpus.
type atrAgentSource struct {
	Type      string   `yaml:"type"`
	Framework []string `yaml:"framework"`
}

func (a *atrAgentSource) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		a.Type = value.Value
		return nil
	}
	type plain atrAgentSource
	return value.Decode((*plain)(a))
}

type atrCondition struct {
	Field         string      `yaml:"field"`    // user_input|agent_output|tool_response|tool_args|tool_name|tool_description|content
	Operator      string      `yaml:"operator"` // regex|substring|equality|prefix|suffix|length|membership
	Value         interface{} `yaml:"value"`    // string, int, []string, or map for length
	CaseSensitive bool        `yaml:"case_sensitive"`
	Description   string      `yaml:"description"` // informational — not used at eval time
}

type atrDetection struct {
	Conditions []atrCondition `yaml:"conditions"`
	// Logic is absent in virtually all corpus rules; default is OR — any
	// single condition match fires the rule (each condition encodes one
	// independent attack pattern).
	Logic string `yaml:"logic"`
}

type atrResponse struct {
	// Real corpus actions: block_input | block_output | block_tool | alert | escalate | reduce_permissions
	// Also accept: block | quarantine | redact | revoke_credentials (spec v1 variants)
	Actions              []string `yaml:"actions"`
	AutoResponseThreshold string  `yaml:"auto_response_threshold"`
	Message              string   `yaml:"message"`
	MessageTemplate      string   `yaml:"message_template"` // alias used in corpus
}

type atrRuleFile struct {
	ID          string         `yaml:"id"`
	Title       string         `yaml:"title"`
	Status      string         `yaml:"status"`   // stable|experimental|draft|deprecated
	Maturity    string         `yaml:"maturity"` // alias for status used in corpus
	Severity    string         `yaml:"severity"` // critical|high|medium|low|informational
	Description string         `yaml:"description"`
	Tags        struct {
		Category   string `yaml:"category"`
		Confidence string `yaml:"confidence"`
	} `yaml:"tags"`
	AgentSource atrAgentSource `yaml:"agent_source"`
	Detection   atrDetection   `yaml:"detection"`
	Response    atrResponse    `yaml:"response"`
}

// effectiveStatus returns the first non-empty of Status and Maturity.
func (r *atrRuleFile) effectiveStatus() string {
	if r.Status != "" {
		return strings.ToLower(strings.Trim(r.Status, "\""))
	}
	return strings.ToLower(strings.Trim(r.Maturity, "\""))
}

// ─── field → direction mapping ────────────────────────────────────────────────
//
// field values seen in corpus:
//   user_input            → Request only
//   agent_output          → Response only
//   tool_response         → Response only (tool call results coming back)
//   tool_args             → Request only  (args sent to a tool)
//   tool_name             → Request only
//   tool_description      → Request only
//   content               → both
//   trace.*, behavioral.* → skip (we don't have structured trace data)

func fieldDirection(field string) string {
	switch strings.ToLower(field) {
	case "user_input", "tool_args", "tool_name", "tool_description":
		return "Request"
	case "agent_output", "tool_response":
		return "Response"
	case "content":
		return "Both"
	}
	return "Skip" // trace.*, behavioral.* — no data to evaluate
}

// ─── Compiled rule ─────────────────────────────────────────────────────────────

type compiledATRCond struct {
	raw     atrCondition
	dir     string         // "Request" | "Response" | "Both" | "Skip"
	rx      *regexp.Regexp // set when operator == regex
	members []string       // set when operator == membership
	lenN    int            // length threshold
	lenOp   string         // gt|lt|gte|lte|eq
}

type compiledATRRule struct {
	rule  atrRuleFile
	conds []compiledATRCond
}

// ─── In-memory store ──────────────────────────────────────────────────────────

var (
	atrRules     []compiledATRRule
	atrRulesLock sync.RWMutex
	atrRuleCount int
)

// ─── Severity ordering ─────────────────────────────────────────────────────────

var severityRank = map[string]int{
	"informational": 0,
	"low":           1,
	"medium":        2,
	"high":          3,
	"critical":      4,
}

func atrSeverityAtLeast(sev, minSev string) bool {
	r, ok := severityRank[strings.ToLower(sev)]
	if !ok {
		return true
	}
	m, ok := severityRank[strings.ToLower(minSev)]
	if !ok {
		return true
	}
	return r >= m
}

// ─── Loader ───────────────────────────────────────────────────────────────────

func startATRLoader() {
	policyLock.RLock()
	cfg := policy.ATRRules
	policyLock.RUnlock()
	if !cfg.Enabled {
		return
	}
	interval := cfg.PollIntervalMinutes
	if interval <= 0 {
		interval = 60
	}
	loadATRRules(cfg)
	go func() {
		t := time.NewTicker(time.Duration(interval) * time.Minute)
		defer t.Stop()
		for range t.C {
			policyLock.RLock()
			c := policy.ATRRules
			policyLock.RUnlock()
			loadATRRules(c)
		}
	}()
}

func loadATRRules(cfg ATRConfig) {
	dir := cfg.RulesDir
	if dir == "" {
		dir = "./atr-rules"
	}
	minSev := cfg.MinSeverity
	if minSev == "" {
		minSev = "medium"
	}

	var loaded []compiledATRRule
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rules, err := parseATRFile(path, cfg, minSev)
		if err != nil {
			log.Printf("⚠️  ATR: skipping %s: %v", path, err)
		}
		loaded = append(loaded, rules...)
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.Printf("⚠️  ATR: walk error in %s: %v", dir, err)
		return
	}

	atrRulesLock.Lock()
	atrRules = loaded
	atrRuleCount = len(loaded)
	atrRulesLock.Unlock()

	if len(loaded) > 0 {
		log.Printf("✅ ATR: loaded %d rules from %s (min_severity=%s)", len(loaded), dir, minSev)
	}
}

func parseATRFile(path string, cfg ATRConfig, minSev string) ([]compiledATRRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var r atrRuleFile
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if r.ID == "" {
		return nil, nil
	}

	// Status filter — accept both status and maturity fields
	switch r.effectiveStatus() {
	case "deprecated", "draft":
		return nil, nil
	case "experimental":
		if !cfg.IncludeExperimental {
			return nil, nil
		}
	}

	// Severity filter
	if !atrSeverityAtLeast(r.Severity, minSev) {
		return nil, nil
	}

	// Compile conditions
	var conds []compiledATRCond
	for _, c := range r.Detection.Conditions {
		dir := fieldDirection(c.Field)
		if dir == "Skip" {
			continue // trace/behavioral fields — no matching data available
		}
		cc := compiledATRCond{raw: c, dir: dir}

		switch c.Operator {
		case "regex":
			pattern, _ := c.Value.(string)
			prefix := "(?i)"
			if c.CaseSensitive {
				prefix = ""
			}
			rx, err := regexp.Compile(prefix + pattern)
			if err != nil {
				log.Printf("⚠️  ATR %s: bad regex: %v", r.ID, err)
				continue
			}
			cc.rx = rx

		case "membership":
			switch v := c.Value.(type) {
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok {
						cc.members = append(cc.members, s)
					}
				}
			case []string:
				cc.members = append(cc.members, v...)
			}

		case "length":
			switch v := c.Value.(type) {
			case int:
				cc.lenN = v
				cc.lenOp = "gt"
			case map[string]interface{}:
				for op, val := range v {
					cc.lenOp = op
					switch n := val.(type) {
					case int:
						cc.lenN = n
					case string:
						cc.lenN, _ = strconv.Atoi(n)
					}
					break
				}
			case string:
				cc.lenN, _ = strconv.Atoi(v)
				cc.lenOp = "gt"
			}
			if cc.lenOp == "" {
				cc.lenOp = "gt"
			}
		}

		conds = append(conds, cc)
	}

	if len(conds) == 0 {
		return nil, nil
	}

	return []compiledATRRule{{rule: r, conds: conds}}, nil
}

// ─── Condition evaluator ──────────────────────────────────────────────────────

func evalATRCond(cc compiledATRCond, text string) bool {
	c := cc.raw
	val, _ := c.Value.(string)

	cmp, cmpVal := text, val
	if !c.CaseSensitive && c.Operator != "regex" && c.Operator != "length" {
		cmp = strings.ToLower(text)
		cmpVal = strings.ToLower(val)
	}

	switch c.Operator {
	case "regex":
		return cc.rx != nil && cc.rx.MatchString(text)
	case "substring":
		return strings.Contains(cmp, cmpVal)
	case "equality":
		return cmp == cmpVal
	case "prefix":
		return strings.HasPrefix(cmp, cmpVal)
	case "suffix":
		return strings.HasSuffix(cmp, cmpVal)
	case "membership":
		for _, m := range cc.members {
			mv, tv := m, text
			if !c.CaseSensitive {
				mv = strings.ToLower(mv)
				tv = strings.ToLower(tv)
			}
			if tv == mv {
				return true
			}
		}
		return false
	case "length":
		l := len(text)
		switch cc.lenOp {
		case "gt":
			return l > cc.lenN
		case "lt":
			return l < cc.lenN
		case "gte":
			return l >= cc.lenN
		case "lte":
			return l <= cc.lenN
		default:
			return l == cc.lenN
		}
	}
	return false
}

// evalATRRule evaluates the compiled rule against text in the given scan direction.
// Conditions that don't apply to the current direction are skipped.
// Default logic is OR — the corpus contains rules where each condition encodes
// an independent attack variant; any single match fires the rule.
func evalATRRule(cr compiledATRRule, text, direction string) bool {
	logic := strings.ToUpper(strings.TrimSpace(cr.rule.Detection.Logic))
	if logic == "" {
		logic = "OR"
	}

	switch logic {
	case "AND":
		applicable := 0
		for _, cc := range cr.conds {
			if cc.dir != "Both" && cc.dir != direction {
				continue
			}
			applicable++
			if !evalATRCond(cc, text) {
				return false
			}
		}
		return applicable > 0

	case "NOT":
		for _, cc := range cr.conds {
			if cc.dir != "Both" && cc.dir != direction {
				continue
			}
			if evalATRCond(cc, text) {
				return false
			}
		}
		return true

	default: // OR
		for _, cc := range cr.conds {
			if cc.dir != "Both" && cc.dir != direction {
				continue
			}
			if evalATRCond(cc, text) {
				return true
			}
		}
		return false
	}
}

// ─── Match result ─────────────────────────────────────────────────────────────

type atrMatch struct {
	RuleID   string
	Title    string
	Severity string
	Category string
	Actions  []string
}

// blocks returns true when any action should cause a hard block.
func (m atrMatch) blocks() bool {
	for _, a := range m.Actions {
		switch strings.ToLower(a) {
		case "block", "block_input", "block_output", "block_tool", "quarantine", "revoke_credentials":
			return true
		}
	}
	return false
}

// ─── Scanner entry point ──────────────────────────────────────────────────────

// checkATRRules evaluates all loaded ATR rules against text.
// direction is "Request" or "Response" (AgentArmor convention).
// Returns the first matching rule, or (zero, false) on no match.
func checkATRRules(text, direction string) (atrMatch, bool) {
	atrRulesLock.RLock()
	rules := atrRules
	atrRulesLock.RUnlock()

	for _, cr := range rules {
		if evalATRRule(cr, text, direction) {
			return atrMatch{
				RuleID:   cr.rule.ID,
				Title:    cr.rule.Title,
				Severity: cr.rule.Severity,
				Category: cr.rule.Tags.Category,
				Actions:  cr.rule.Response.Actions,
			}, true
		}
	}
	return atrMatch{}, false
}
