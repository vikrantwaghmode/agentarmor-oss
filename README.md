<p align="center">
  <img src="assets/banner.png" alt="AgentArmor — Defense-in-depth for AI agents" width="700" />
</p>
<p align="center">
  <a href="https://github.com/vikrantwaghmode/agentarmor-oss/blob/main/LICENSE"><img src="https://img.shields.io/github/license/vikrantwaghmode/agentarmor-oss?style=flat-square&color=blue" alt="License"></a>
  <img src="https://img.shields.io/badge/go-1.24-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/docker-ready-2496ED?style=flat-square&logo=docker" alt="Docker">
  <img src="https://img.shields.io/badge/layer_7-proxy-8B5CF6?style=flat-square" alt="L7">
  <img src="https://img.shields.io/badge/layer_3/4-firewall-EF4444?style=flat-square" alt="L3/4">
</p>

---

AgentArmor is a **two-layer security proxy** for LLM-powered applications. It sits between your application and any LLM provider, scanning every message and enforcing network-level egress control. Works with any tool — OpenClaw, Cursor, custom apps, raw API clients.

```text
┌─────────────┐         ┌──────────────────────────────────────────────────┐        ┌───────────────┐
│             │         │              AgentArmor Environment              │        │               │
│ Client Apps │ HTTPS/WS│  ┌────────────────┐     ┌─────────────────────┐  │ Egress │ External LLMs │
│ (Browser,   ├─────────┼─▶│ AgentArmor     ├────▶│ iptables Firewall   ├──┼───────▶│ (OpenAI,      │
│ OpenClaw,   │◀────────┼─┤│ Proxy (L7)     │     │ (L3/L4)             │  │◀───────┤ Anthropic,    │
│ IDE, etc.)  │         │  │ - Scanners     │     │ - Zero-Trust Egress │  │        │ Gemini, etc.) │
│             │         │  │ - RAG/Skills   │     └─────────────────────┘  │        │               │
└─────────────┘         │  └─┬──────┬─────┬─┘                              │        └───────────────┘
                        │    │      │     │                                │
                        │    ▼      ▼     └──▶ ┌───────────────────────┐   │
                        │ ┌──────┐ ┌─────────┐ │  Web Dashboard & API  │   │
                        │ │Ollama│ │Presidio │ └───────────┬───────────┘   │
                        │ │(LLM) │ │(PII/DLP)│             ▼               │
                        │ └──────┘ └─────────┘ ┌───────────────────────┐   │
                        │                      │   Audit DB (SQLite)   │   │
                        │                      └───────────────────────┘   │
                        └──────────────────────────────────────────────────┘
```

## Security Posture — Assume Breach · Survive & Repave

AgentArmor is built around three principles:

| Principle | What it means | How AgentArmor implements it |
|-----------|--------------|------------------------------|
| **Assume Breach** | Every session is already compromised | Canary tokens detect exfiltration; intent scoring detects lateral movement; anomaly scoring detects behavioural deviation |
| **Survive** | Stay operational and logging under active attack | Graceful sidecar degradation; WAL-mode SQLite audit log; per-scanner fallbacks |
| **Repave** | Destroy and rebuild from known-good state | Session kill switch (<1 s); canary rotation (<1 s); policy rollback (<1 s); automated repave trigger |

## Features

| Scanner / Feature | Direction | Action | What it catches |
|-------------------|-----------|--------|-----------------|
| Prompt Injection | In | Block | Jailbreaks, instruction overrides, false authority claims (30+ phrases) |
| LLM Scanner | In | Block | Subtle injections that evade regex — Ollama `llama3.2:1b`, confidence-gated |
| GoalLock Canary | Both | Block | Runtime token injected into every system prompt; any echo = exfiltration proof |
| Secret Redaction | Both | Redact | API keys, JWTs, tokens — per-rule strategy: **replace / hash / mask / remove** |
| PII / DLP | Both | Block | Email, phone, SSN, credit card |
| Presidio PII | Both | Block | Names, addresses, freeform PII (confidence-gated sidecar) |
| DNS Rebinding | In | Block | Hostnames in URLs that resolve to private/metadata IPs |
| Internal IP / SSRF | In | Block | Literal RFC 1918, loopback, link-local IPs |
| Malicious Content | Both | Block | SQLi, XSS, SSRF, command injection, executables |
| Intent Scoring | In | Block | Stateful tool-call sequences per session (`read_file → post_request` etc.) |
| Anomaly Scoring | In | Block/Alert | 3-signal behavioural scorer (0–1); configurable alert + block thresholds |
| Zero-Trust Tool Approval | In | Block | `exec`, `browser`, `sessions_spawn` blocked until admin approves per-session |
| Blast Radius Cap | In | Block | Hard limits on tool calls, blocks, high-risk calls per session |
| Rate Limiting | In | Block | Token bucket per session key **and** per client IP (X-Forwarded-For aware) — 60 req/min, burst 120 |
| Auto-Repave Trigger | — | Repave | Fires kill-sessions + canary rotation when event thresholds are crossed |
| Skills + Semantic RAG | — | Inject | 5 built-in role personas; BM25 or vector embedding retrieval; auto-routes messages to best-matching skill |
| SIEM / Webhooks | — | Notify | Multiple destinations: Slack / Splunk HEC / generic JSON; per-destination event filters |
| Threat Intel Feeds | — | Block | Live regex rules pulled from external URLs, merged in-memory |
| WebSocket Scanning | Both | All | Scans real-time WS frames, not just HTTP POST bodies |
| Streaming DLP | Out | Redact | Sliding-window scanner catches secrets fragmented across SSE chunks |
| Policy Snapshots | — | Repave | Every save auto-checkpointed; one-click rollback from dashboard |
| Session Kill Switch | — | Repave | `POST /armor/api/sessions/kill` — closes all WS connections instantly |
| Canary Rotation | — | Repave | `POST /armor/api/canary/rotate` — new token mid-run, old one immediately invalid |
| Custom Redaction | — | Config | Per-rule strategies: replace with label, SHA-256 hash, mask prefix/suffix, or remove entirely |
| Multi-turn Scanning | In | All | All non-system messages scanned, not just the first — covers full conversation history |
| TLS by Default | — | Transport | Auto-generated self-signed cert on first run; HTTPS on `:8443`, HTTP→HTTPS redirect on `:8080` |
| Web Dashboard | — | Monitor | Editorial Terminal UI — live ticker, ⌘K palette, RBAC, all posture config editable |

## Quick Start

```bash
git clone https://github.com/vikrantwaghmode/agentarmor-oss.git
cd agentarmor-oss
cp .env.template .env                            # set ADMIN_TOKEN, USER_TOKEN, GEMINI_API_KEY
docker compose up --build -d
docker exec ollama ollama pull llama3.2:1b       # LLM scanner model (~800 MB, once)
# Dashboard → https://localhost:8443/armor/
# Accept the self-signed cert warning — or replace certs/server.crt + certs/server.key
```

> **TLS is on by default.** A self-signed certificate is generated automatically on first run and stored in `./certs/`. Replace with a CA-signed cert for production — no rebuild needed.

**`.env` keys:**
```bash
ADMIN_TOKEN="..."               # full dashboard access
USER_TOKEN="..."                # read-only dashboard
LLM_PROVIDER="openclaw"        # openclaw | openai | anthropic | gemini
GEMINI_API_KEY="AIza..."
OPENCLAW_GATEWAY_TOKEN="..."

# TLS — defaults to auto-generated self-signed cert
# TLS_CERT="/certs/server.crt"   # path inside container
# TLS_KEY="/certs/server.key"

# CORS — comma-separated list of allowed extra origins (own host always allowed)
# AGENTARMOR_CORS_ORIGINS="https://your-dashboard.example.com"
```

## Transport Security

All traffic is encrypted out of the box using TLS termination:

```
Browser / Client
    │  HTTPS :8443 (TLS)   WSS :8443 (TLS)
    ▼
AgentArmor Proxy ← TLS terminates here
    │  HTTP (loopback only — never leaves the host)
    ▼
OpenClaw Gateway :18789 (bound to 127.0.0.1)
```

| Port | Protocol | Purpose |
|------|----------|---------|
| `8443` | HTTPS / WSS | All proxy traffic — scanner pipeline, dashboard, WebSocket relay |
| `8080` | HTTP | Redirect only → `https://host:8443` |

**Production cert:** Mount your CA-signed certificate into `./certs/` as `server.crt` + `server.key`. The proxy picks them up on next restart — no rebuild.

**OpenClaw UI** is served through the proxy on `https://localhost:8443` — the browser sees full TLS. The loopback hop (AgentArmor → OpenClaw gateway) is plain HTTP on `127.0.0.1` only, which is standard TLS termination behaviour.

## How It Works

Each request passes through the pipeline in order. First match wins.

```text
┌────────┐   ┌───────────────────────────────────────────────────────────────────────────────────┐   ┌────────┐
│        │   │                           AgentArmor Security Pipeline                            │   │        │
│        │──▶│ ┌────────────────┐   ┌────────────────┐   ┌────────────────┐   ┌────────────────┐ │──▶│        │
│ Client │   │ │ 1. Pre-Flight  │──▶│ 2. Content L7  │──▶│ 3. Stateful    │──▶│ 4. Egress (L3) │ │   │External│
│  App   │   │ │ • Rate Limit   │   │ • Prompt Inj.  │   │ • Intent Score │   │ • Blast Cap    │ │   │  LLMs  │
│        │   │ │ • GoalLock     │   │ • LLM Scanner  │   │ • Anomaly Score│   │ • iptables     │ │   │        │
│        │   │ │ • SSRF / DNS   │   │ • PII & DLP    │   │ • Zero-Trust   │   │                │ │   │        │
│        │   │ │                │   │ • Malicious    │   │                │   │                │ │   │        │
│        │   │ │                │   │ • Secrets      │   │                │   │                │ │   │        │
│        │   │ └────────────────┘   └────────────────┘   └────────────────┘   └────────────────┘ │   │        │
│        │◀──│ ───────────────────── (Streaming DLP on Response) ─────────────────────────────── │◀──│        │
└────────┘   └─────────────────────────────────────────┬─────────────────────────────────────────┘   └────────┘
                                                       ▼
                                        All decisions logged to SQLite
```

Clean requests have the active skill's system prompt + RAG context + GoalLock canary injected before forwarding. All decisions are logged to SQLite.

## Configuration

### `policy.yaml` — hot-reloadable, no restart needed

<details>
<summary><strong>Key sections with their defaults (Click to expand)</strong></summary>
<br>

```yaml
scanners:
  prompt_injection:
    enabled: true
    blocked_phrases:               # 30+ built-in; add your own
      - rule: "ignore all previous instructions"
        enabled: true

  secrets:
    enabled: true
    redact_patterns:
      - rule: '(?i)(sk-[a-zA-Z0-9]{20,})'
        enabled: true
        strategy: mask             # replace | hash | mask | remove
        mask_prefix: 7
        mask_suffix: 4
      - rule: 'ghp_[0-9a-zA-Z]{36}'
        enabled: true
        strategy: hash             # → [REDACTED:a3f1b2c9]

  rate_limiting:     { enabled: true, requests_per_minute: 60, burst: 120 }
  anomaly_scoring:   { enabled: true, alert_threshold: 0.34, block_threshold: 0.9 }
  zero_trust_tools:  { enabled: true, high_risk_tools: [exec, browser, sessions_spawn], auto_deny_after_minutes: 10 }
  blast_radius:      { enabled: true, max_tool_calls_per_session: 100, max_blocks_per_session: 10 }
  auto_repave:       { enabled: true, triggers: { canary_detections: 3, window_minutes: 5 } }
  llm_scanner:       { enabled: true, url: "http://ollama:11434", model: "llama3.2:1b", confidence_threshold: 0.75 }

# Multiple SIEM destinations
webhooks:
  - enabled: true
    name: "Slack Security"
    url: "https://hooks.slack.com/services/..."
    format: slack                  # slack | splunk | generic
    events: [BLOCKED, AUTO_REPAVE, BLAST_RADIUS]

# Threat intelligence feeds
threat_feeds:
  enabled: true
  feeds:
    - enabled: true
      url: "https://gist.githubusercontent.com/.../rules.json"
      scanner: prompt_injection    # prompt_injection | malicious_content | pii | secrets
      interval_minutes: 60

# Semantic RAG + auto-routing for skills
skills_rag:
  enabled: true
  url: "http://ollama:11434"
  model: "nomic-embed-text"        # docker exec ollama ollama pull nomic-embed-text
  auto_route: true                  # route each message to best-matching skill automatically
  auto_route_threshold: 0.70
```

### `firewall.yaml` — egress allow-list
</details>
<details>
<summary><strong>Egress domains (Click to expand)</strong></summary>
<br>

```yaml
allowed_domains:
  - "generativelanguage.googleapis.com"
  - "api.openai.com"
  - "api.anthropic.com"
  - "ollama"             # sidecar — must be listed or iptables drops it
  - "presidio-analyzer"  # sidecar
```
</details>

### Skills

Five built-in personas live in `./skills/<id>/` — each has a `skill.yaml` (system prompt + keywords) and `knowledge/*.md` (RAG docs).

| ID | Name | Expertise |
|----|------|-----------|
| `security-engineer` | Security Engineer | AppSec, OWASP, pentesting, CVE analysis |
| `security-auditor` | Security Auditor | SOC 2, ISO 27001, GDPR, HIPAA, PCI-DSS |
| `software-developer` | Software Developer | Code review, design patterns, API design |
| `software-qa` | Software QA Engineer | Test strategy, automation, bug reporting |
| `cloud-engineer` | Cloud Engineer | AWS/GCP/Azure, Terraform, Kubernetes |

**Activation priority:** `X-AgentArmor-Skill` header → `[ARMOR-SKILL:xxx]` marker → keyword match → semantic auto-route → admin-activated global defaults

Admin can activate skills globally from the **Skills tab (05)** in the dashboard — no header needed.

### Sidecars

| Service | Purpose | Setup |
|---------|---------|-------|
| `ollama` | LLM scanner + semantic RAG | `docker exec ollama ollama pull llama3.2:1b` (scanner) + `nomic-embed-text` (RAG) |
| `presidio-analyzer` | Confidence-gated PII | Enable `pii.advanced_pii.enabled: true` after confirming `curl http://localhost:3000/health` |

Both fail gracefully — proxy falls back to regex scanners if unreachable.

## Project Structure

```
agentarmor-oss/
├── proxy/
│   ├── main.go          # All scanners, WS handler, API endpoints, repave features
│   ├── skills.go        # Skill loader, BM25 + semantic RAG, auto-routing
│   ├── dashboard.html   # Editorial Terminal UI (React, embedded)
│   └── policy.yaml      # Embedded default policy (go:embed)
├── skills/              # Built-in skill definitions (volume-mounted)
│   └── <id>/skill.yaml + knowledge/*.md
├── certs/               # TLS certificates — auto-generated if empty; replace for production
│   ├── server.crt
│   └── server.key
├── policy.yaml          # Live config (hot-reloads)
├── firewall.yaml        # Egress allow-list
├── docker-compose.yml   # proxy + presidio-analyzer + ollama
└── assets/              # logo.png + banner.png
```

## Enterprise Readiness

| Area | Status | Notes |
|------|--------|-------|
| TLS / transport encryption | ✅ | Auto self-signed by default; bring your own cert for production |
| CORS restriction | ✅ | Origin-restricted; `AGENTARMOR_CORS_ORIGINS` for extra origins |
| Audit trail | ✅ | Full — client IP, session key, rule, payload snippet; WAL-mode SQLite |
| SIEM integration | ✅ | Multiple webhook destinations (Slack, Splunk, generic) |
| RBAC | ✅ | Admin / user roles on dashboard and all API endpoints |
| Policy hot-reload + rollback | ✅ | Snapshot on every save; one-click restore |
| Graceful config validation | ✅ | Invalid regex skipped with warning; bad YAML keeps previous policy active |
| Multi-turn conversation scanning | ✅ | All non-system messages scanned, not just the first |
| IP-level rate limiting | ✅ | Session key + client IP (X-Forwarded-For aware) token bucket |
| **SSO / OIDC** | ❌ | Static tokens only — no Okta/Azure AD/Google Workspace integration |
| **Multi-tenancy** | ❌ | Single policy for all traffic — no per-team isolation |
| **High availability** | ❌ | Single container + SQLite — no clustering or shared state |
| **Prometheus metrics** | ❌ | No `/metrics` endpoint for Grafana/Datadog |
| **Secrets vault** | ❌ | API keys in env vars — no Vault/KMS integration |
| **Cert auto-renewal** | ❌ | No ACME/Let's Encrypt — manual rotation |

The security *design* is enterprise-grade. Gaps 1–3 (SSO, multi-tenancy, HA) are the blockers for large-scale enterprise deployment.

## Roadmap

- [ ] **SSO / OIDC** — Okta, Azure AD, Google Workspace integration to replace static tokens
- [ ] **Multi-tenancy** — Isolated policies, audit logs, and rate limits per application or team
- [ ] **High availability** — PostgreSQL audit log, Redis rate-limiter state, horizontal scaling
- [ ] **Prometheus metrics** — `/metrics` endpoint for Grafana / Datadog
- [ ] **WASM filters** — Custom filtering logic without recompiling

## Contributing

Open an issue first to discuss changes or reachout to vikrant.waghmode@gmail.com

LinkedIn: https://www.linkedin.com/in/securityhandyman/

## License

See [LICENSE](LICENSE).

---

<p align="center"><strong>AgentArmor</strong> — because your AI agent shouldn't have unsupervised access to the internet.</p>
