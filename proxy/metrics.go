package main

// Prometheus text-format metrics endpoint at GET /armor/metrics.
//
// Optional: set METRICS_TOKEN to require a Bearer token for scraping.
// Prometheus scrape config:
//
//	- job_name: agentarmor
//	  static_configs:
//	    - targets: ["host:8443"]
//	  scheme: https
//	  bearer_token: <METRICS_TOKEN>
//	  tls_config: { insecure_skip_verify: true }   # remove when using CA cert

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"
)

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	if tok := os.Getenv("METRICS_TOKEN"); tok != "" {
		if r.Header.Get("Authorization") != "Bearer "+tok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	blocked := statsBlocked.Load()
	redacted := statsRedacted.Load()
	allowed := statsAllowed.Load()
	uptime := time.Since(statsStarted).Seconds()

	policyLock.RLock()
	rc := globalRuleCounts
	policyLock.RUnlock()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, `# HELP agentarmor_requests_total Requests processed by AgentArmor
# TYPE agentarmor_requests_total counter
agentarmor_requests_total{result="blocked"} %d
agentarmor_requests_total{result="redacted"} %d
agentarmor_requests_total{result="allowed"} %d
agentarmor_requests_total{result="total"} %d

# HELP agentarmor_uptime_seconds Seconds since the proxy started
# TYPE agentarmor_uptime_seconds gauge
agentarmor_uptime_seconds %.1f

# HELP agentarmor_scanner_rules Active rules per scanner
# TYPE agentarmor_scanner_rules gauge
agentarmor_scanner_rules{scanner="prompt_injection"} %d
agentarmor_scanner_rules{scanner="secrets"} %d
agentarmor_scanner_rules{scanner="pii"} %d
agentarmor_scanner_rules{scanner="malicious_content"} %d
agentarmor_scanner_rules{scanner="internal_ips"} %d
agentarmor_scanner_rules{scanner="canary_tokens"} %d
agentarmor_scanner_rules{scanner="firewall_domains"} %d
agentarmor_scanner_rules{scanner="rate_limit_rpm"} %d

# HELP agentarmor_heap_bytes Go heap memory currently in use
# TYPE agentarmor_heap_bytes gauge
agentarmor_heap_bytes %d

# HELP agentarmor_goroutines Current goroutine count
# TYPE agentarmor_goroutines gauge
agentarmor_goroutines %d

# HELP agentarmor_info Build and configuration metadata
# TYPE agentarmor_info gauge
agentarmor_info{db_driver=%q,secrets_provider=%q} 1
`,
		blocked, redacted, allowed, blocked+redacted+allowed,
		uptime,
		rc.PromptInjection, rc.Secrets, rc.PII, rc.MaliciousContent,
		rc.InternalIPs, rc.CanaryTokens, rc.FirewallDomains, rc.RateLimitRpm,
		mem.HeapInuse,
		runtime.NumGoroutine(),
		dbDriver, secretsProviderName,
	)
}
