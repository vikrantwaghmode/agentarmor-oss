package main

// Infrastructure configuration — hot-reloadable settings for database,
// Redis, TLS/ACME, and Prometheus metrics.
//
// Stored in infra.yaml (volume-mounted). Admins can edit via the
// Infrastructure tab (10) in the dashboard; changes are applied immediately
// where possible and marked "restart required" where not.
//
// Hot-reloadable:  Redis URL, Metrics token
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
	if cfg.ACME.Staging {
		os.Setenv("ACME_STAGING", "true")
	} else {
		os.Unsetenv("ACME_STAGING")
	}
}

// saveInfraConfig persists the new config to infra.yaml, then hot-applies
// whatever it can. Returns whether a container restart is needed.
func saveInfraConfig(newCfg InfraConfig) (needsRestart bool, err error) {
	data, err := yaml.Marshal(newCfg)
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(infraConfigPath, data, 0644); err != nil {
		return false, err
	}

	infraConfigMu.Lock()
	oldCfg := infraConfig
	infraConfig = newCfg
	infraConfigMu.Unlock()

	return hotApplyInfra(oldCfg, newCfg), nil
}

// hotApplyInfra applies changes that don't require a restart.
// Returns true when at least one change needs a restart.
func hotApplyInfra(old, new InfraConfig) bool {
	restart := false

	// Redis — reconnect immediately
	if new.Redis.URL != old.Redis.URL {
		os.Setenv("REDIS_URL", new.Redis.URL)
		redisEnabled = false
		redisPool = &rPool{}
		redisAddr = ""
		redisPass = ""
		initRedis()
		log.Printf("🔴 Redis config reloaded (%s)", new.Redis.URL)
	}

	// Metrics token — read via os.Getenv on every request, so updating env is enough
	if new.Metrics.Token != old.Metrics.Token {
		if new.Metrics.Token != "" {
			os.Setenv("METRICS_TOKEN", new.Metrics.Token)
		} else {
			os.Unsetenv("METRICS_TOKEN")
		}
		log.Printf("📊 Metrics token updated")
	}

	// Database and ACME require a restart to take effect
	if new.Database.URL != old.Database.URL {
		os.Setenv("DATABASE_URL", new.Database.URL)
		restart = true
	}
	if new.ACME.Domain != old.ACME.Domain || new.ACME.Email != old.ACME.Email || new.ACME.Staging != old.ACME.Staging {
		os.Setenv("ACME_DOMAIN", new.ACME.Domain)
		os.Setenv("ACME_EMAIL", new.ACME.Email)
		if new.ACME.Staging {
			os.Setenv("ACME_STAGING", "true")
		} else {
			os.Unsetenv("ACME_STAGING")
		}
		restart = true
	}

	if restart {
		infraNeedsRestart = true
	}
	return restart
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
