package main

// Infrastructure configuration — hot-reloadable settings for database,
// Redis, TLS/ACME, Prometheus metrics, and OpenTelemetry tracing.
//
// Stored in infra.yaml (volume-mounted). Admins can edit via the
// Infrastructure tab (10) in the dashboard; changes are applied immediately
// where possible and marked "restart required" where not.
//
// Hot-reloadable:  Redis URL, Metrics token, OpenTelemetry config
// Restart required: Database URL, ACME domain / email

import (
	"log"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

type InfraConfig struct {
	Database InfraDatabase `yaml:"database" json:"database"`
	Redis    InfraRedis    `yaml:"redis"    json:"redis"`
	ACME     InfraACME     `yaml:"acme"     json:"acme"`
	Metrics  InfraMetrics  `yaml:"metrics"  json:"metrics"`
	OTel     InfraOTel     `yaml:"otel"     json:"otel"`
}

type InfraOTel struct {
	Enabled     bool   `yaml:"enabled"      json:"enabled"`
	Endpoint    string `yaml:"endpoint"     json:"endpoint"`
	ServiceName string `yaml:"service_name" json:"service_name"`
	Insecure    bool   `yaml:"insecure"     json:"insecure"`
}

type InfraDatabase struct {
	URL string `yaml:"url" json:"url"`
}

type InfraRedis struct {
	URL string `yaml:"url" json:"url"`
}

type InfraACME struct {
	Domain  string `yaml:"domain"  json:"domain"`
	Email   string `yaml:"email"   json:"email"`
	Staging bool   `yaml:"staging" json:"staging"`
}

type InfraMetrics struct {
	Token string `yaml:"token" json:"token"`
}

var (
	infraConfig       InfraConfig
	infraConfigMu     sync.RWMutex
	infraNeedsRestart bool
)

const infraConfigPath = "infra.yaml"

// loadInfraConfig reads infra.yaml and applies settings as env vars so that
// initRedis, initAuditDB, and startTLS pick them up on first run.
func loadInfraConfig() {
	data, err := os.ReadFile(infraConfigPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("⚠️  infra.yaml read error: %v", err)
		}
		return
	}

	var cfg InfraConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Printf("⚠️  infra.yaml parse error: %v", err)
		return
	}

	infraConfigMu.Lock()
	infraConfig = cfg
	infraConfigMu.Unlock()

	applyInfraEnvVars(cfg)
	log.Printf("✅ Infrastructure config loaded (infra.yaml)")
}

// applyInfraEnvVars pushes non-empty infra.yaml values into the process
// environment. Values here override what was set in .env.
func applyInfraEnvVars(cfg InfraConfig) {
	set := func(k, v string) {
		if v != "" {
			os.Setenv(k, v)
		}
	}
	set("DATABASE_URL", cfg.Database.URL)
	set("REDIS_URL", cfg.Redis.URL)
	set("ACME_DOMAIN", cfg.ACME.Domain)
	set("ACME_EMAIL", cfg.ACME.Email)
	set("METRICS_TOKEN", cfg.Metrics.Token)
	set("OTEL_EXPORTER_OTLP_ENDPOINT", cfg.OTel.Endpoint)
	set("OTEL_SERVICE_NAME", cfg.OTel.ServiceName)
	if cfg.OTel.Insecure {
		os.Setenv("OTEL_INSECURE", "true")
	}
	if cfg.ACME.Staging {
		os.Setenv("ACME_STAGING", "true")
	} else {
		os.Unsetenv("ACME_STAGING")
	}
}

// saveInfraConfig persists the new config to infra.yaml, then hot-applies
// whatever it can. Returns lists of what was applied immediately and what
// needs a restart, plus any write error.
func saveInfraConfig(newCfg InfraConfig) (restartReasons, hotApplied []string, err error) {
	data, err := yaml.Marshal(newCfg)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(infraConfigPath, data, 0644); err != nil {
		return nil, nil, err
	}

	infraConfigMu.Lock()
	oldCfg := infraConfig
	infraConfig = newCfg
	infraConfigMu.Unlock()

	restartReasons, hotApplied = hotApplyInfra(oldCfg, newCfg)
	return restartReasons, hotApplied, nil
}

// hotApplyInfra applies changes that don't require a restart immediately.
// Returns (restartReasons, hotApplied) so the dashboard can tell the user
// exactly which settings took effect and which need a restart.
func hotApplyInfra(old, new InfraConfig) (restartReasons, hotApplied []string) {
	// Redis — reconnect immediately, no restart needed
	if new.Redis.URL != old.Redis.URL {
		os.Setenv("REDIS_URL", new.Redis.URL)
		redisEnabled = false
		redisPool = &rPool{}
		redisAddr = ""
		redisPass = ""
		initRedis()
		log.Printf("🔴 Redis config reloaded (%s)", new.Redis.URL)
		hotApplied = append(hotApplied, "Redis rate limiting")
	}

	// Metrics token — read from env on every request, updating env is enough
	if new.Metrics.Token != old.Metrics.Token {
		if new.Metrics.Token != "" {
			os.Setenv("METRICS_TOKEN", new.Metrics.Token)
		} else {
			os.Unsetenv("METRICS_TOKEN")
		}
		log.Printf("📊 Metrics token updated")
		hotApplied = append(hotApplied, "Metrics scrape token")
	}

	// OTel — fully hot-reloadable: update globals, sender goroutine picks them up
	if new.OTel != old.OTel {
		ReinitOTel(new.OTel)
		hotApplied = append(hotApplied, "OpenTelemetry tracing")
	}

	// Database — requires restart
	if new.Database.URL != old.Database.URL {
		os.Setenv("DATABASE_URL", new.Database.URL)
		restartReasons = append(restartReasons, "Database (URL changed — new connection needs a fresh start)")
	}

	// ACME / TLS — requires restart to rebind the TLS listener
	if new.ACME.Domain != old.ACME.Domain || new.ACME.Email != old.ACME.Email || new.ACME.Staging != old.ACME.Staging {
		os.Setenv("ACME_DOMAIN", new.ACME.Domain)
		os.Setenv("ACME_EMAIL", new.ACME.Email)
		if new.ACME.Staging {
			os.Setenv("ACME_STAGING", "true")
		} else {
			os.Unsetenv("ACME_STAGING")
		}
		restartReasons = append(restartReasons, "TLS / ACME (cert listener must be restarted)")
	}

	if len(restartReasons) > 0 {
		infraNeedsRestart = true
	}
	return
}

// getInfraStatus returns the currently active infra config for the dashboard.
func getInfraStatus() map[string]interface{} {
	infraConfigMu.RLock()
	cfg := infraConfig
	infraConfigMu.RUnlock()
	return map[string]interface{}{
		"config":         cfg,
		"needs_restart":  infraNeedsRestart,
		"db_driver":      dbDriver,
		"redis_enabled":  redisEnabled,
		"tls_mode":       activeTLSMode(),
		"acme_domain":    os.Getenv("ACME_DOMAIN"),
		"secrets_provider": secretsProviderName,
	}
}

func activeTLSMode() string {
	if os.Getenv("ACME_DOMAIN") != "" {
		return "acme"
	}
	if os.Getenv("TLS_CERT") != "" {
		return "custom"
	}
	return "self-signed"
}
