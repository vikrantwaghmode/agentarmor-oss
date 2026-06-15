package main

// Deployment profiles + capability registry (Modular Architecture, step 1).
//
// A `profile:` in policy.yaml lets an operator pick a target architecture
// (edge / gateway / enterprise / compliance) and have the relevant feature
// toggles seeded for them, instead of hand-tuning ~20 switches. The registry
// below is the single source of truth that maps each capability MODULE to the
// Config field it controls and the dashboard tab it surfaces under — it drives
// profile seeding, the /armor/api/profile endpoint, and (later) module-aware
// dashboard hiding and compose/build wiring.
//
// SAFETY: seeding is a *baseline* applied BEFORE the operator's policy.yaml is
// unmarshalled, so any explicit key in policy.yaml wins. And seeding only runs
// when `profile:` is explicitly set to a known, non-custom value — an absent or
// `custom` profile changes nothing, so every existing (profile-less) policy
// behaves exactly as before.

// Profile is a named deployment architecture.
type Profile string

const (
	ProfileEdge       Profile = "edge"       // minimal inline firewall
	ProfileGateway    Profile = "gateway"    // bundled agent gateway (today's default)
	ProfileEnterprise Profile = "enterprise" // multi-team / scaled / SSO / HA
	ProfileCompliance Profile = "compliance" // regulated: audit log, HITL, PCI, reporting
	ProfileCustom     Profile = "custom"     // operator drives every toggle (no seeding)
)

// Module is one toggleable capability.
type Module struct {
	ID    string
	Label string
	Tab   string // dashboard tab id this surfaces under ("" if none)
	// Get reports whether the module is currently enabled for cfg.
	Get func(*Config) bool
	// Set enables/disables the module on cfg. nil means the module is not
	// policy-settable (env/infra-driven, e.g. the compliance engine) — such
	// modules are reported by the API but never seeded by a profile.
	Set func(*Config, bool)
	// Core modules are always on regardless of profile.
	Core bool
}

// moduleRegistry returns the capability catalog. Order is display order.
func moduleRegistry() []Module {
	return []Module{
		// ── Core L7 scanners (always on) ──
		{ID: "prompt_injection", Label: "Prompt Injection", Tab: "policy", Core: true,
			Get: func(c *Config) bool { return c.Scanners.PromptInjection.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.PromptInjection.Enabled = v }},
		{ID: "secrets", Label: "Secret Redaction", Tab: "policy", Core: true,
			Get: func(c *Config) bool { return c.Scanners.Secrets.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.Secrets.Enabled = v }},
		{ID: "pii", Label: "PII / DLP", Tab: "policy", Core: true,
			Get: func(c *Config) bool { return c.Scanners.PII.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.PII.Enabled = v }},
		{ID: "malicious_content", Label: "Malicious Content", Tab: "policy", Core: true,
			Get: func(c *Config) bool { return c.Scanners.MaliciousContent.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.MaliciousContent.Enabled = v }},
		{ID: "internal_ip", Label: "Internal IP / SSRF", Tab: "policy", Core: true,
			Get: func(c *Config) bool { return c.Scanners.InternalIPProtection.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.InternalIPProtection.Enabled = v }},
		{ID: "canary", Label: "Canary Tokens", Tab: "policy", Core: true,
			Get: func(c *Config) bool { return c.Scanners.CanaryTokens.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.CanaryTokens.Enabled = v }},

		// ── Optional scanners / governance ──
		{ID: "advanced_pii", Label: "Presidio PII", Tab: "policy",
			Get: func(c *Config) bool { return c.Scanners.PII.AdvancedPII.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.PII.AdvancedPII.Enabled = v }},
		{ID: "llm_scanner", Label: "LLM Scanner", Tab: "policy",
			Get: func(c *Config) bool { return c.Scanners.LLMScanner.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.LLMScanner.Enabled = v }},
		{ID: "rate_limiting", Label: "Rate Limiting", Tab: "policy",
			Get: func(c *Config) bool { return c.Scanners.RateLimiting.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.RateLimiting.Enabled = v }},
		{ID: "risk_scoring", Label: "Intent Risk Scoring", Tab: "policy",
			Get: func(c *Config) bool { return c.Scanners.RiskScoring.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.RiskScoring.Enabled = v }},
		{ID: "anomaly_scoring", Label: "Anomaly Scoring", Tab: "policy",
			Get: func(c *Config) bool { return c.Scanners.AnomalyScoring.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.AnomalyScoring.Enabled = v }},
		{ID: "zero_trust_tools", Label: "Zero-Trust Tool Approval", Tab: "repave",
			Get: func(c *Config) bool { return c.Scanners.ZeroTrustTools.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.ZeroTrustTools.Enabled = v }},
		{ID: "blast_radius", Label: "Blast Radius Cap", Tab: "repave",
			Get: func(c *Config) bool { return c.Scanners.BlastRadius.Enabled },
			Set: func(c *Config, v bool) { c.Scanners.BlastRadius.Enabled = v }},
		{ID: "mcp_brokering", Label: "MCP Zero-Trust Brokering", Tab: "policy",
			Get: func(c *Config) bool { return c.MCPServers.Enabled },
			Set: func(c *Config, v bool) { c.MCPServers.Enabled = v }},
		{ID: "skill_scanning", Label: "Skill Behavioral Scanning", Tab: "skills",
			Get: func(c *Config) bool { return c.SkillScanning.Enabled },
			Set: func(c *Config, v bool) { c.SkillScanning.Enabled = v }},
		{ID: "execution_scanning", Label: "Execution Containment", Tab: "policy",
			Get: func(c *Config) bool { return c.ExecutionScanning.Enabled },
			Set: func(c *Config, v bool) { c.ExecutionScanning.Enabled = v }},
		{ID: "data_sensitivity", Label: "Data-Sensitivity Grants", Tab: "repave",
			Get: func(c *Config) bool { return c.DataSensitivity.Enabled },
			Set: func(c *Config, v bool) { c.DataSensitivity.Enabled = v }},
		{ID: "skills_rag", Label: "Skills + Semantic RAG", Tab: "skills",
			Get: func(c *Config) bool { return c.SkillsRAG.Enabled },
			Set: func(c *Config, v bool) { c.SkillsRAG.Enabled = v }},
		{ID: "atr_rules", Label: "ATR Rules", Tab: "policy",
			Get: func(c *Config) bool { return c.ATRRules.Enabled },
			Set: func(c *Config, v bool) { c.ATRRules.Enabled = v }},
		{ID: "doc_conversion", Label: "Document Conversion", Tab: "policy",
			Get: func(c *Config) bool { return c.DocConversion.Enabled },
			Set: func(c *Config, v bool) { c.DocConversion.Enabled = v }},
		{ID: "threat_feeds", Label: "Threat Feeds", Tab: "policy",
			Get: func(c *Config) bool { return c.ThreatFeeds.Enabled },
			Set: func(c *Config, v bool) { c.ThreatFeeds.Enabled = v }},
		{ID: "agent_routing", Label: "Agent Routing", Tab: "tokens",
			Get: func(c *Config) bool { return c.AgentRouting.Enabled },
			Set: func(c *Config, v bool) { c.AgentRouting.Enabled = v }},
		{ID: "sso", Label: "SSO / OIDC", Tab: "auth",
			Get: func(c *Config) bool { return c.SSO.Enabled },
			Set: func(c *Config, v bool) { c.SSO.Enabled = v }},

		// ── Compliance engine (env/infra-driven — reported, not profile-seeded) ──
		{ID: "compliance_audit", Label: "Sealed Audit Log", Tab: "compliance",
			Get: func(*Config) bool { return complianceAuditActive() }},
		{ID: "compliance_pci_dlp", Label: "PCI Deep Inspection", Tab: "compliance",
			Get: func(*Config) bool { return complianceDLPActive() }},
	}
}

// profileBaseline maps each profile to the set of module IDs enabled at its
// baseline (core modules are implicitly included). Only modules with a Set
// function are affected by seeding.
func profileBaseline(p Profile) map[string]bool {
	on := func(ids ...string) map[string]bool {
		m := map[string]bool{}
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	switch p {
	case ProfileEdge:
		return on("rate_limiting", "atr_rules")
	case ProfileGateway:
		return on("rate_limiting", "risk_scoring", "anomaly_scoring", "zero_trust_tools",
			"blast_radius", "llm_scanner", "skills_rag", "mcp_brokering", "skill_scanning",
			"execution_scanning", "data_sensitivity", "atr_rules", "doc_conversion")
	case ProfileEnterprise:
		return on("rate_limiting", "risk_scoring", "anomaly_scoring", "zero_trust_tools",
			"blast_radius", "llm_scanner", "skills_rag", "mcp_brokering", "skill_scanning",
			"execution_scanning", "data_sensitivity", "atr_rules", "doc_conversion",
			"advanced_pii", "sso", "agent_routing", "threat_feeds")
	case ProfileCompliance:
		return on("rate_limiting", "zero_trust_tools", "blast_radius", "data_sensitivity",
			"advanced_pii", "atr_rules", "execution_scanning")
	default:
		return map[string]bool{}
	}
}

// knownProfile reports whether p is a recognized, seedable profile.
func knownProfile(p Profile) bool {
	switch p {
	case ProfileEdge, ProfileGateway, ProfileEnterprise, ProfileCompliance:
		return true
	}
	return false
}

// activeProfile returns the effective profile for a config. An empty or
// unrecognized value is reported as custom (no seeding happened).
func activeProfile(c *Config) Profile {
	p := Profile(c.Profile)
	if knownProfile(p) {
		return p
	}
	return ProfileCustom
}

// applyProfileDefaults seeds cfg's toggles to the profile baseline. It is a
// no-op for custom/absent/unknown profiles. Core modules are forced on. This
// runs BEFORE the operator's policy.yaml is unmarshalled, so explicit keys win.
func applyProfileDefaults(cfg *Config, p Profile) {
	if !knownProfile(p) {
		return // custom / absent → change nothing
	}
	baseline := profileBaseline(p)
	for _, m := range moduleRegistry() {
		if m.Set == nil {
			continue // env/infra-driven module — not seeded
		}
		m.Set(cfg, m.Core || baseline[m.ID])
	}
}

// ModuleChange describes a toggle that a profile switch would flip.
type ModuleChange struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	From  bool   `json:"from"`
	To    bool   `json:"to"`
}

// profileDiff returns the settable modules whose enabled state would change if
// cfg were stamped to profile p (the preview shown before applying). For custom
// (or unknown) it returns no changes — switching to custom keeps current toggles.
func profileDiff(cur *Config, p Profile) []ModuleChange {
	known := knownProfile(p)
	baseline := profileBaseline(p)
	var out []ModuleChange
	for _, m := range moduleRegistry() {
		if m.Set == nil {
			continue
		}
		from := m.Get(cur)
		to := from
		if known {
			to = m.Core || baseline[m.ID]
		}
		if from != to {
			out = append(out, ModuleChange{ID: m.ID, Label: m.Label, From: from, To: to})
		}
	}
	return out
}

// stampProfile records the profile and forces the governed toggles to its
// baseline (a deliberate one-time action on operator request — distinct from
// the seed-only behavior at load). custom/unknown only records the label.
func stampProfile(cfg *Config, p Profile) {
	cfg.Profile = string(p)
	applyProfileDefaults(cfg, p) // no-op for custom/unknown
}

// moduleStatus is the per-module view returned by /armor/api/profile.
type moduleStatus struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Tab      string `json:"tab,omitempty"`
	Enabled  bool   `json:"enabled"`
	Core     bool   `json:"core"`
	Settable bool   `json:"settable"`
}

// profileSnapshot describes the active profile and live module states.
type profileSnapshot struct {
	Profile  string         `json:"profile"`
	Flavor   string         `json:"flavor"` // build flavor: full | lite
	Profiles []string       `json:"profiles"`
	Modules  []moduleStatus `json:"modules"`
}

// snapshotProfile builds the API view from a config (caller holds policyLock).
func snapshotProfile(c *Config) profileSnapshot {
	snap := profileSnapshot{
		Profile:  string(activeProfile(c)),
		Flavor:   buildFlavor,
		Profiles: []string{string(ProfileEdge), string(ProfileGateway), string(ProfileEnterprise), string(ProfileCompliance), string(ProfileCustom)},
	}
	for _, m := range moduleRegistry() {
		snap.Modules = append(snap.Modules, moduleStatus{
			ID: m.ID, Label: m.Label, Tab: m.Tab,
			Enabled:  m.Get(c),
			Core:     m.Core,
			Settable: m.Set != nil,
		})
	}
	return snap
}
