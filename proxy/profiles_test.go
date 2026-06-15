package main

import "testing"

// moduleEnabled looks up a module's Get result on cfg by id.
func moduleEnabled(cfg *Config, id string) bool {
	for _, m := range moduleRegistry() {
		if m.ID == id {
			return m.Get(cfg)
		}
	}
	panic("unknown module id in test: " + id)
}

func TestApplyProfileDefaults_SeedsBaseline(t *testing.T) {
	cases := []struct {
		profile Profile
		on      []string // expected enabled (besides core)
		off     []string // expected disabled
	}{
		{ProfileEdge,
			[]string{"prompt_injection", "secrets", "rate_limiting", "atr_rules"},
			[]string{"llm_scanner", "mcp_brokering", "sso", "data_sensitivity", "skills_rag"}},
		{ProfileGateway,
			[]string{"zero_trust_tools", "skills_rag", "mcp_brokering", "execution_scanning", "data_sensitivity"},
			[]string{"sso", "advanced_pii"}},
		{ProfileEnterprise,
			[]string{"sso", "agent_routing", "threat_feeds", "advanced_pii", "zero_trust_tools"},
			[]string{}},
		{ProfileCompliance,
			[]string{"zero_trust_tools", "data_sensitivity", "advanced_pii", "atr_rules"},
			[]string{"llm_scanner", "sso", "skills_rag"}},
	}
	for _, c := range cases {
		var cfg Config
		applyProfileDefaults(&cfg, c.profile)
		// Core always on.
		for _, id := range []string{"prompt_injection", "secrets", "pii", "malicious_content", "internal_ip", "canary"} {
			if !moduleEnabled(&cfg, id) {
				t.Fatalf("%s: core module %s should be enabled", c.profile, id)
			}
		}
		for _, id := range c.on {
			if !moduleEnabled(&cfg, id) {
				t.Fatalf("%s: expected %s enabled", c.profile, id)
			}
		}
		for _, id := range c.off {
			if moduleEnabled(&cfg, id) {
				t.Fatalf("%s: expected %s disabled", c.profile, id)
			}
		}
	}
}

func TestCustomAndAbsentSeedNothing(t *testing.T) {
	for _, p := range []Profile{ProfileCustom, "", "bogus"} {
		var cfg Config
		applyProfileDefaults(&cfg, p)
		// Nothing seeded → every settable toggle stays at its zero value (false).
		for _, m := range moduleRegistry() {
			if m.Set != nil && m.Get(&cfg) {
				t.Fatalf("profile %q: module %s should remain off (no seeding)", p, m.ID)
			}
		}
		if activeProfile(&cfg) != ProfileCustom {
			t.Fatalf("profile %q should report as custom", p)
		}
	}
}

// Simulates loadPolicy's seed-then-override: an explicit policy key must win
// over the profile baseline (both directions).
func TestExplicitPolicyOverridesProfile(t *testing.T) {
	// gateway baseline enables llm_scanner; operator disables it explicitly.
	var cfg Config
	applyProfileDefaults(&cfg, ProfileGateway)
	if !cfg.Scanners.LLMScanner.Enabled {
		t.Fatal("precondition: gateway should seed llm_scanner on")
	}
	cfg.Scanners.LLMScanner.Enabled = false // explicit override (as a later unmarshal would do)
	if moduleEnabled(&cfg, "llm_scanner") {
		t.Fatal("explicit disable should override the profile baseline")
	}

	// edge baseline disables mcp_brokering; operator enables it explicitly.
	var cfg2 Config
	applyProfileDefaults(&cfg2, ProfileEdge)
	if cfg2.MCPServers.Enabled {
		t.Fatal("precondition: edge should not seed mcp_brokering")
	}
	cfg2.MCPServers.Enabled = true
	if !moduleEnabled(&cfg2, "mcp_brokering") {
		t.Fatal("explicit enable should override the profile baseline")
	}
}

func TestSnapshotReportsProfileAndModules(t *testing.T) {
	var cfg Config
	cfg.Profile = string(ProfileEnterprise)
	applyProfileDefaults(&cfg, ProfileEnterprise)
	snap := snapshotProfile(&cfg)
	if snap.Profile != "enterprise" {
		t.Fatalf("snapshot profile = %s", snap.Profile)
	}
	if len(snap.Modules) != len(moduleRegistry()) {
		t.Fatalf("snapshot module count = %d, want %d", len(snap.Modules), len(moduleRegistry()))
	}
	// Compliance modules are reported but not settable.
	var sawAudit bool
	for _, m := range snap.Modules {
		if m.ID == "compliance_audit" {
			sawAudit = true
			if m.Settable {
				t.Fatal("compliance_audit should be reported as not settable")
			}
		}
	}
	if !sawAudit {
		t.Fatal("snapshot missing compliance_audit module")
	}
}
