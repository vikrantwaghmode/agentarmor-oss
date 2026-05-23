package main

// Scanner status — probes sidecars (Presidio, Ollama) and reports the live
// state of every scanner in AgentArmor. Results are cached for 15 seconds so
// repeated badge refreshes from the OpenClaw UI don't hammer the sidecars.
//
// Served at GET /armor/api/scanner-status (public — no auth required).

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ─── cache ───────────────────────────────────────────────────────────────────

var (
	scannerStatusCache    map[string]interface{}
	scannerStatusCacheAt  time.Time
	scannerStatusCacheMu  sync.Mutex
	scannerStatusCacheTTL = 15 * time.Second
)

// logStartupScannerStatus waits a few seconds for sidecars to start, then logs
// a one-line summary of every scanner so the admin can see at a glance what is
// active, what needs a model pull, and what is disabled.
// scannerGateReady returns true when every enabled scanner is operational.
// Used by handleRoot to block proxy traffic until the system is ready.
func scannerGateReady() bool {
	status := getCachedScannerStatus()
	scanners, ok := status["scanners"].([]scannerEntry)
	if !ok {
		return true // can't determine — don't block
	}
	for _, s := range scanners {
		if s.Status == "down" || s.Status == "model-missing" {
			return false
		}
	}
	return true
}

func logStartupScannerStatus() {
	time.Sleep(5 * time.Second) // give Presidio / Ollama time to respond

	status := buildScannerStatus()
	scanners, _ := status["scanners"].([]scannerEntry)

	log.Println("──────────────────────────────────────────────────")
	log.Println("⬡  AgentArmor — Scanner Status")
	log.Println("──────────────────────────────────────────────────")
	var actions []string
	for _, s := range scanners {
		icon := "✅"
		switch s.Status {
		case "down":
			icon = "🔴"
		case "model-missing":
			icon = "🟡"
			actions = append(actions,
				fmt.Sprintf("  docker exec ollama ollama pull %s", extractModelName(s.Detail)))
		case "disabled", "inactive":
			icon = "⚫"
		}
		log.Printf("  %s  %-24s  %-15s  %s", icon, s.Name, s.Status, s.Detail)
	}
	log.Println("──────────────────────────────────────────────────")
	if len(actions) > 0 {
		log.Println("  ↳ To pull missing models:")
		for _, a := range actions {
			log.Println(a)
		}
		log.Println("──────────────────────────────────────────────────")
	}
}

// extractModelName pulls the model name from detail strings like "llama3.2:1b not pulled".
func extractModelName(detail string) string {
	if idx := strings.Index(detail, " "); idx > 0 {
		return detail[:idx]
	}
	return detail
}

func getCachedScannerStatus() map[string]interface{} {
	scannerStatusCacheMu.Lock()
	defer scannerStatusCacheMu.Unlock()
	if scannerStatusCache != nil && time.Since(scannerStatusCacheAt) < scannerStatusCacheTTL {
		return scannerStatusCache
	}
	scannerStatusCache = buildScannerStatus()
	scannerStatusCacheAt = time.Now()
	return scannerStatusCache
}

// ─── status builder ───────────────────────────────────────────────────────────

type scannerEntry struct {
	Name   string `json:"name"`
	Type   string `json:"type"`   // regex | sidecar | llm | wasm | network
	Status string `json:"status"` // active | up | down | disabled | model-missing
	Detail string `json:"detail"`
}

func buildScannerStatus() map[string]interface{} {
	policyLock.RLock()
	piEnabled   := policy.Scanners.PromptInjection.Enabled
	piRules     := len(policy.Scanners.PromptInjection.BlockedPhrases)
	piiEnabled  := policy.Scanners.PII.Enabled
	piiRules    := len(policy.Scanners.PII.BlockPatterns)
	presEnabled := policy.Scanners.PII.AdvancedPII.Enabled
	presURL     := policy.Scanners.PII.AdvancedPII.URL
	secEnabled  := policy.Scanners.Secrets.Enabled
	secRules    := len(policy.Scanners.Secrets.RedactPatterns)
	malEnabled  := policy.Scanners.MaliciousContent.Enabled
	malRules    := len(policy.Scanners.MaliciousContent.BlockPatterns)
	llmEnabled  := policy.Scanners.LLMScanner.Enabled
	llmURL      := policy.Scanners.LLMScanner.URL
	llmModel    := policy.Scanners.LLMScanner.Model
	ragEnabled  := policy.SkillsRAG.Enabled
	ragURL      := policy.SkillsRAG.URL
	ragModel    := policy.SkillsRAG.Model
	fwDomains   := globalRuleCounts.FirewallDomains
	policyLock.RUnlock()

	client := &http.Client{Timeout: 800 * time.Millisecond}

	// ── In-process regex scanners — no network, build immediately ────────────
	entries := []scannerEntry{
		regexEntry("Prompt Injection", piEnabled, piRules, "pattern"),
		regexEntry("PII / DLP", piiEnabled, piiRules, "pattern"),
		regexEntry("Secret Redaction", secEnabled, secRules, "rule"),
		regexEntry("Malicious Content", malEnabled, malRules, "pattern"),
	}

	// ── Network probes — run in parallel so total wait is max(probe) not sum ─
	type probeSlot struct {
		idx   int
		entry scannerEntry
	}
	slots := make(chan probeSlot, 3)
	pending := 0

	if !presEnabled || presURL == "" {
		entries = append(entries, scannerEntry{
			Name: "Presidio PII", Type: "sidecar", Status: "disabled",
			Detail: "enable advanced_pii in policy",
		})
	} else {
		pending++
		go func() {
			st, det := probeSidecar(client, healthBaseOf(presURL), "Presidio")
			slots <- probeSlot{4, scannerEntry{Name: "Presidio PII", Type: "sidecar", Status: st, Detail: det}}
		}()
	}

	if !llmEnabled || llmURL == "" {
		entries = append(entries, scannerEntry{
			Name: "LLM Scanner", Type: "llm", Status: "disabled",
			Detail: "enable llm_scanner in policy",
		})
	} else {
		pending++
		go func() {
			st, det := probeOllama(client, llmURL, llmModel)
			// If the circuit breaker is open the scanner is functionally down even
			// when Ollama is reachable — surface this so the gate blocks traffic.
			if st == "up" && llmCircuitOpen(llmURL+"|"+llmModel) {
				st = "down"
				det = "circuit open — recovering from previous failure"
			}
			slots <- probeSlot{5, scannerEntry{Name: "LLM Scanner", Type: "llm", Status: st, Detail: det}}
		}()
	}

	if !ragEnabled || ragURL == "" {
		entries = append(entries, scannerEntry{
			Name: "Semantic RAG", Type: "llm", Status: "disabled",
			Detail: "enable skills_rag in policy",
		})
	} else {
		pending++
		go func() {
			st, det := probeOllama(client, ragURL, ragModel)
			if st == "up" && llmCircuitOpen(ragURL+"|"+ragModel) {
				st = "down"
				det = "circuit open — recovering from previous failure"
			}
			slots <- probeSlot{6, scannerEntry{Name: "Semantic RAG", Type: "llm", Status: st, Detail: det}}
		}()
	}

	// Collect parallel probe results (order doesn't matter for the badge)
	probeEntries := make([]scannerEntry, 0, pending)
	for i := 0; i < pending; i++ {
		s := <-slots
		probeEntries = append(probeEntries, s.entry)
	}
	entries = append(entries, probeEntries...)

	// ── WASM filters ─────────────────────────────────────────────────────────
	if wasmEnabled {
		filters := ListWASMFilters()
		active := 0
		for _, f := range filters {
			if f.Enabled {
				active++
			}
		}
		entries = append(entries, scannerEntry{
			Name: "WASM Filters", Type: "wasm", Status: "active",
			Detail: fmt.Sprintf("%d/%d enabled", active, len(filters)),
		})
	} else {
		entries = append(entries, scannerEntry{
			Name: "WASM Filters", Type: "wasm", Status: "inactive",
			Detail: "drop .wasm files into ./wasm-filters/",
		})
	}

	// ── iptables egress firewall ──────────────────────────────────────────────
	fwStatus := "active"
	if fwDomains == 0 {
		fwStatus = "inactive"
	}
	entries = append(entries, scannerEntry{
		Name: "Egress Firewall", Type: "network", Status: fwStatus,
		Detail: fmt.Sprintf("%d domains allow-listed", fwDomains),
	})

	// Overall health: critical scanners are the in-process ones + any enabled sidecars
	up, total := 0, len(entries)
	for _, e := range entries {
		if e.Status == "active" || e.Status == "up" {
			up++
		}
	}

	return map[string]interface{}{
		"scanners": entries,
		"up":       up,
		"total":    total,
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func regexEntry(name string, enabled bool, count int, unit string) scannerEntry {
	if !enabled {
		return scannerEntry{Name: name, Type: "regex", Status: "disabled", Detail: "off in policy"}
	}
	return scannerEntry{
		Name:   name,
		Type:   "regex",
		Status: "active",
		Detail: fmt.Sprintf("%d %ss", count, unit),
	}
}

// healthBaseOf strips the path from a URL and appends /health.
// e.g. "http://presidio-analyzer:3000/analyze" → "http://presidio-analyzer:3000/health"
func healthBaseOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + "/health"
	}
	return u.Scheme + "://" + u.Host + "/health"
}

func probeSidecar(client *http.Client, url, name string) (status, detail string) {
	resp, err := client.Get(url)
	if err != nil {
		return "down", name + " unreachable"
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return "up", "healthy"
	}
	return "down", fmt.Sprintf("HTTP %d", resp.StatusCode)
}

func probeOllama(client *http.Client, baseURL, model string) (status, detail string) {
	resp, err := client.Get(strings.TrimRight(baseURL, "/") + "/api/tags")
	if err != nil {
		return "down", "Ollama unreachable"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "down", fmt.Sprintf("Ollama HTTP %d", resp.StatusCode)
	}
	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	json.NewDecoder(resp.Body).Decode(&tags) //nolint:errcheck
	for _, m := range tags.Models {
		if strings.HasPrefix(m.Name, model) {
			return "up", model + " ready"
		}
	}
	return "model-missing", model + " not pulled"
}
