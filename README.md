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
┌─────────────┐         ┌──────────────────────────────────────────────────┐      ┌───────────────┐
│              │        │              AgentArmor Environment              │      │               │
│ Client Apps  │HTTPS/WS│  ┌────────────────┐     ┌─────────────────────┐  │Egress│ External LLMs │
│ (Browser,    ├────────┼─▶│ AgentArmor     ├────▶│ iptables Firewall   ├──┼─────▶│ (OpenAI,      │
│ OpenClaw,    │◀───────┼─│ Proxy (L7)     │     │ (L3/L4)             │  │◀─────┤ Anthropic,    │
│ IDE, etc.)   │        │  │ - Scanners     │     │ - Zero-Trust Egress │  │      │ Gemini, etc.) │
│              │        │  │ - RAG/Skills   │     └─────────────────────┘  |      │               │
└─────────────┘         │  └─┬──────┬─────┬─┘                              │      └───────────────┘
                        │    │      │     │                                │
                        │    ▼      ▼     └──▶ ┌───────────────────────┐   │
                        │ ┌──────┐ ┌─────────┐ │  Web Dashboard & API  │   │
                        │ │Ollama│ │Presidio │ └───────────┬───────────┘   │
                        │ │(LLM) │ │(PII/DLP)│             ▼               │
                        │ └──────┘ └─────────┘ ┌───────────────────────┐   │
                        │                           │   Audit DB (SQLite)  │   
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
| SSO / OIDC | — | Auth | Any OIDC provider (Google, Microsoft, Okta, Auth0, Keycloak); role mapping from groups; configurable from the Auth tab without restart |
| Multi-tenancy | — | Isolate | Per-tenant policies, tokens, audit trails, rate limits, and sessions — routed via `X-Tenant-ID` header or Bearer token; managed from Tenants tab (08) |
| WASM Filters | Both | Block | Drop any `.wasm` file into `./wasm-filters/`; runs on every request, hot-reloaded from dashboard; any WASI language (Go, Rust, C, AssemblyScript) |
| OpenTelemetry Traces | — | Observe | One span per request + scan child span; OTLP/HTTP to Jaeger / Tempo / Honeycomb; `X-Trace-ID` response header; zero new Go deps |
| Infrastructure Config | — | Config | `infra.yaml` dashboard (tab 10) — configure PostgreSQL, Redis, ACME, metrics token with hot-reload; **Restart System** button with "now or later" dialog |
| Web Dashboard | — | Monitor | Editorial Terminal UI — live ticker, ⌘K palette, RBAC; 10 tabs covering health, policy, audit, firewall, skills, repave, SSO, tenants, logs, and infrastructure |

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

# SSO — or configure live from the Auth tab (07) in the dashboard
# OIDC_ENABLED=true
# OIDC_ISSUER=https://accounts.google.com
# OIDC_CLIENT_ID=...  OIDC_CLIENT_SECRET=...
# OIDC_REDIRECT_URL=https://your-host:8443/armor/callback
# OIDC_ADMIN_GROUPS=security-admins  OIDC_USER_GROUPS=employees

# TLS — defaults to auto-generated self-signed cert
# TLS_CERT="/certs/server.crt"   # path inside container
# TLS_KEY="/certs/server.key"

# CORS — comma-separated list of allowed extra origins (own host always allowed)
# AGENTARMOR_CORS_ORIGINS="https://your-dashboard.example.com"
```

## Kubernetes / Helm

```bash
# Install directly from the OCI registry (no clone needed)
helm install agentarmor \
  oci://ghcr.io/vikrantwaghmode/agentarmor \
  --version 0.1.0 \
  --set auth.adminToken=changeme \
  --set auth.userToken=readonly

# HA mode — PostgreSQL + Redis + HPA (2–10 replicas)
helm install agentarmor \
  oci://ghcr.io/vikrantwaghmode/agentarmor --version 0.1.0 \
  --set auth.adminToken=changeme \
  --set auth.userToken=readonly \
  --set ha.enabled=true \
  --set ha.database.url="postgres://agentarmor:secret@pg:5432/agentarmor?sslmode=disable" \
  --set ha.redis.url="redis://redis:6379"

# Sidecar mode — ClusterIP only, no Ingress
helm install agentarmor \
  oci://ghcr.io/vikrantwaghmode/agentarmor --version 0.1.0 \
  --set sidecar.enabled=true \
  --set auth.adminToken=changeme \
  --set auth.userToken=readonly

# From source (local chart)
helm install agentarmor ./helm/agentarmor --set auth.adminToken=changeme --set auth.userToken=readonly
```

The chart is published automatically to `ghcr.io` via GitHub Actions on every release tag. See [`helm/agentarmor/values.yaml`](helm/agentarmor/values.yaml) for the full option reference — OIDC, ACME, OTel, all secrets providers, custom policy/firewall ConfigMaps, resource limits, and Ingress.

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
│   ├── main.go          # Scanners, WS handler, API endpoints, repave features
│   ├── skills.go        # Skill loader, BM25 + semantic RAG, auto-routing
│   ├── oidc.go          # SSO/OIDC — provider init, login/callback/logout handlers
│   ├── tenants.go       # Multi-tenancy — Tenant struct, CRUD, token resolution
│   ├── dashboard.html   # Editorial Terminal UI (React, embedded via go:embed)
│   └── policy.yaml      # Embedded default policy (go:embed)
├── skills/              # Built-in skill definitions (volume-mounted for live edits)
│   └── <id>/skill.yaml + knowledge/*.md
├── tenants/             # Per-tenant configs — create from dashboard or by hand
│   └── <id>/tenant.yaml + policy.yaml
├── certs/               # TLS certificates — auto-generated if empty; replace for production
│   ├── server.crt
│   └── server.key
├── policy.yaml          # Live config (hot-reloads)
├── firewall.yaml        # Egress allow-list
├── docker-compose.yml   # proxy + presidio-analyzer + ollama
└── assets/              # logo.png + banner.png
```

## Deployment Architectures

AgentArmor is a single stateless binary that fits into any enterprise topology. Choose the pattern that matches your scale, compliance requirements, and existing infrastructure.

| Requirement | Recommended Pattern |
|---|---|
| Trying it out, POC | [Pattern 1](#) — single container |
| One team, public cloud | [Pattern 2](#) — single VM + ACME |
| Multiple teams, compliance audit | [Pattern 3](#) — HA + multi-tenant |
| Many AI microservices | [Pattern 4](#) — Kubernetes sidecar |
| Data residency / air-gap | [Pattern 5](#) — on-premises |
| All of the above (phased rollout) | Start with 1 → migrate to 3 → decompose to 4 |

All patterns use the same Docker image and the same `policy.yaml` schema — you change the infrastructure around AgentArmor, not AgentArmor itself.

---

<details>
<summary><strong>Pattern 1 — Developer / POC (single container)</strong> &nbsp;·&nbsp; <em>docker compose up, no external deps</em></summary>

<br>

The default out-of-the-box setup. One `docker compose up` command, no external dependencies.

```
┌─────────────────────────────────────────────────────┐
│  Single host / developer laptop                      │
│                                                     │
│  ┌──────────────┐   HTTPS :8443   ┌──────────────┐  │
│  │  Browser /   │────────────────▶│  AgentArmor  │  │
│  │  IDE / CLI   │                 │  + Ollama    │  │
│  └──────────────┘                 │  + Presidio  │  │
│                                   │  SQLite DB   │  │
│                                   └──────┬───────┘  │
│                                          │ HTTPS     │
│                                   LLM API (external) │
└─────────────────────────────────────────────────────┘
```

| Setting | Value |
|---|---|
| Database | SQLite (WAL mode, local file) |
| Rate limiting | In-memory token bucket |
| TLS | Self-signed cert (auto-generated) |
| Auth | Static `ADMIN_TOKEN` / `USER_TOKEN` |
| Secrets | Environment variables |

**Best for:** Proof-of-concept, developer workstations, feature evaluation.

</details>

---

<details>
<summary><strong>Pattern 2 — Team / Small Production (single VM + external LLM)</strong> &nbsp;·&nbsp; <em>ACME cert, SSO, Vault secrets</em></summary>

<br>

One VM or VPS running AgentArmor as the gateway for a team. CA cert from Let's Encrypt, SSO via existing IdP.

```
                       ┌────────────────────────────────────┐
   Developers /        │  Cloud VM  (e.g. AWS EC2, GCP VM)  │
   IDE extensions ────▶│                                    │
                       │  ┌──────────────────────────────┐  │
   Internal tools ────▶│  │      AgentArmor              │  │
                       │  │  - Let's Encrypt cert (ACME) │  │──▶ OpenAI / Anthropic
   Web dashboard ─────▶│  │  - Okta / Azure AD SSO       │  │──▶ Gemini / Bedrock
                       │  │  - SQLite audit log          │  │
                       │  │  - Slack SIEM webhook        │  │
                       │  └──────────────────────────────┘  │
                       └────────────────────────────────────┘
```

| Setting | Value |
|---|---|
| Database | SQLite (sufficient for < ~10k events/day) |
| TLS | ACME / Let's Encrypt (`ACME_DOMAIN` + `ACME_EMAIL`) |
| Auth | OIDC (Okta, Azure AD, Google Workspace) |
| Secrets | HashiCorp Vault or AWS Secrets Manager |
| SIEM | Slack webhook or Splunk HEC |

**Best for:** Engineering teams of 5–50, startup security baseline, single-region.

</details>

---

<details>
<summary><strong>Pattern 3 — Multi-team Enterprise (HA with tenant isolation)</strong> &nbsp;·&nbsp; <em>PostgreSQL, Redis, load balancer, per-team tenants</em></summary>

<br>

Multiple proxy instances behind a load balancer, shared PostgreSQL + Redis, per-team tenant isolation. Horizontally scalable.

```
                    ┌───────────────────────────────────────────────────────┐
                    │   Enterprise Private Network / VPC                     │
                    │                                                       │
  Team Alpha ──────▶│  ┌──────────────┐       ┌───────────────────────┐   │
  (X-Tenant-ID:     │  │  Load         │       │  AgentArmor  (×N)     │   │
   team-alpha)      │  │  Balancer /   │──────▶│  - Policy per tenant  │──▶│──▶ LLM APIs
                    │  │  API Gateway  │       │  - Shared PostgreSQL   │   │
  Team Beta ───────▶│  │  (nginx /     │       │  - Shared Redis        │   │
  (X-Tenant-ID:     │  │   Envoy /     │       │  - Vault secrets       │   │
   team-beta)       │  │   ALB)        │       └───────────────────────┘   │
                    │  └──────────────┘                                     │
                    │                         ┌──────────┐  ┌───────────┐  │
                    │                         │PostgreSQL│  │  Redis    │  │
                    │                         │ (RDS /   │  │(Elasticache│  │
                    │                         │ Cloud SQL)│  │ / Memstore)│  │
                    │                         └──────────┘  └───────────┘  │
                    └───────────────────────────────────────────────────────┘
```

| Setting | Value |
|---|---|
| Database | PostgreSQL (RDS, Cloud SQL, or self-hosted) — set `DATABASE_URL` |
| Rate limiting | Redis (ElastiCache, Memorystore, or self-hosted) — set `REDIS_URL` |
| TLS | CA-signed cert from internal PKI, mounted into `./certs/` |
| Auth | Enterprise OIDC (Okta, Azure AD, Keycloak) |
| Secrets | HashiCorp Vault (AppRole) or cloud KMS |
| Tenancy | One tenant per team — `X-Tenant-ID` header or Bearer token routing |
| Observability | Prometheus scrape → Grafana; Splunk HEC for SIEM |

**Best for:** Large engineering orgs, platform/security teams serving multiple product teams, SOC 2 environments.

</details>

---

<details>
<summary><strong>Pattern 4 — Kubernetes Sidecar (per-application isolation)</strong> &nbsp;·&nbsp; <em>one AgentArmor per pod, ConfigMap policies</em></summary>

<br>

AgentArmor deployed as a sidecar container alongside each AI-enabled application pod. Each pod has its own policy, audit trail, and rate limits. No shared state required.

```
┌──────────────────────────────────────┐  ┌──────────────────────────────────────┐
│  Pod: chat-service                   │  │  Pod: code-assistant                  │
│                                      │  │                                      │
│  ┌────────────┐   ┌───────────────┐  │  │  ┌────────────┐   ┌───────────────┐  │
│  │ App        │──▶│  AgentArmor   │──┼──┼─▶│ App        │──▶│  AgentArmor   │  │
│  │ Container  │   │  (sidecar)    │  │  │  │ Container  │   │  (sidecar)    │  │
│  └────────────┘   │  policy.yaml  │  │  │  └────────────┘   │  policy.yaml  │  │
│                   │  skills/      │  │  │                   │  skills/      │  │
│                   └──────┬────────┘  │  │                   └──────┬────────┘  │
└──────────────────────────┼───────────┘  └──────────────────────────┼───────────┘
                           │                                          │
                    ┌──────▼──────────────────────────────────────────▼──────┐
                    │                  LLM API (cluster egress)               │
                    └────────────────────────────────────────────────────────┘
```

**Kubernetes setup:**
```yaml
# In your app Deployment spec:
containers:
  - name: app
    image: your-app:latest
  - name: agentarmor
    image: ghcr.io/vikrantwaghmode/agentarmor:latest
    env:
      - name: TARGET_URL
        value: "https://api.openai.com"
      - name: ADMIN_TOKEN
        valueFrom: { secretKeyRef: { name: agentarmor, key: admin-token } }
    ports:
      - containerPort: 8443
    volumeMounts:
      - name: policy
        mountPath: /app/policy.yaml
        subPath: policy.yaml
volumes:
  - name: policy
    configMap: { name: agentarmor-policy }
```

| Setting | Value |
|---|---|
| Database | SQLite per pod (ephemeral audit log) **or** PostgreSQL (shared persistent audit) |
| Policy | ConfigMap per application — different rules for chat vs. code vs. data apps |
| Secrets | Kubernetes Secrets → env vars, or Vault Agent sidecar |
| Network policy | Kubernetes NetworkPolicy restricting egress to only the LLM API |

**Best for:** Platform engineering teams running many AI apps, zero-trust service mesh environments, Istio / Linkerd deployments.

</details>

---

<details>
<summary><strong>Pattern 5 — Air-gapped / On-premises (no external calls)</strong> &nbsp;·&nbsp; <em>local Ollama scanning, internal PKI, no internet</em></summary>

<br>

Fully self-contained deployment with no internet access. All LLM scanning uses local Ollama models.

```
┌───────────────────────────────────────────────────────────────────────┐
│   On-premises data centre (air-gapped)                                 │
│                                                                       │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐  │
│  │  Internal    │────▶│  AgentArmor  │────▶│  On-prem LLM         │  │
│  │  AI clients  │     │              │     │  (Ollama / vLLM /    │  │
│  └──────────────┘     │  Scanners:   │     │   Azure OpenAI       │  │
│                       │  - Regex     │     │   Private Endpoint)  │  │
│  ┌──────────────┐     │  - Ollama    │     └──────────────────────┘  │
│  │  Admin       │     │    LLM scan  │                               │
│  │  Dashboard   │     │  - Presidio  │     ┌──────────────────────┐  │
│  └──────────────┘     │    (local)   │     │  PostgreSQL (on-prem) │  │
│                       └──────────────┘     └──────────────────────┘  │
│                                                                       │
│  ✗ No outbound internet — threat feeds disabled, ACME disabled        │
└───────────────────────────────────────────────────────────────────────┘
```

| Setting | Value |
|---|---|
| LLM provider | `TARGET_URL` pointing to internal vLLM / Ollama / Azure Private Endpoint |
| LLM scanner | `llm_scanner.url: http://ollama:11434` — local model |
| PII scanner | Presidio sidecar — local NLP, no cloud calls |
| TLS | Internal CA cert in `./certs/` |
| Threat feeds | Disabled (no outbound internet) |
| Secrets | On-prem HashiCorp Vault or Kubernetes Secrets |
| SIEM | Internal Splunk / QRadar / ArcSight via generic webhook |

**Best for:** Financial services, defence, government, healthcare — any environment with strict data residency or no-internet requirements.

</details>

---

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
| **SSO / OIDC** | ✅ | Google, Microsoft, Okta, Auth0, Keycloak — configurable from Auth tab (07) without restart |
| **Multi-tenancy** | ✅ | Per-tenant policies, tokens, audit trails, rate limits — routed via `X-Tenant-ID` header or Bearer token; managed from Tenants tab (08) |
| **High availability** | ✅ | PostgreSQL audit log (`DATABASE_URL`) + Redis distributed rate limiting (`REDIS_URL`); stateless proxy scales horizontally |
| **Prometheus metrics** | ✅ | `/armor/metrics` Prometheus text format; optional `METRICS_TOKEN` scrape auth; exposes request counters, scanner rules, goroutines, heap |
| **Secrets vault** | ✅ | HashiCorp Vault (token/AppRole), AWS Secrets Manager (static/IMDSv2), GCP Secret Manager (SA key/metadata), Azure Key Vault (SP/managed identity) |
| **Cert auto-renewal** | ✅ | ACME / Let's Encrypt via `ACME_DOMAIN` + `ACME_EMAIL`; auto-renews; falls back to self-signed when unset |
| **WASM custom filters** | ✅ | Drop any `.wasm` file into `./wasm-filters/`; upload/toggle/delete from dashboard; WASI ABI — Go, Rust, C, AssemblyScript |
| **OpenTelemetry tracing** | ✅ | OTLP/HTTP spans to Jaeger / Tempo / Honeycomb; configurable from dashboard without restart; `X-Trace-ID` header on every response |
| **Audit log export** | ✅ | CSV or NDJSON download from the Audit tab; date-range and action filters; up to 100k rows; admin-only |
| **Kubernetes / Helm** | ✅ | Helm chart with HA, sidecar, and ACME modes; OCI registry at `ghcr.io/vikrantwaghmode/agentarmor`; auto-published on release tags |
| **Dashboard infrastructure config** | ✅ | All infra settings (DB, Redis, ACME, OTel, metrics token) editable from tab 10; hot-reload where possible; restart dialog for settings that need it |

The security *design* is enterprise-grade. All major infrastructure gaps have been closed.

## Infrastructure Configuration (Dashboard Tab 10)

All infrastructure settings are managed from the **Infrastructure tab (10)** in the dashboard — no shell access or file editing required after initial setup.

| Setting | Hot-reload | How to configure |
|---|---|---|
| PostgreSQL URL | No — restart required | Infrastructure tab → Database section |
| Redis URL | **Yes** — reconnects immediately | Infrastructure tab → Rate Limiting section |
| ACME domain + email | No — restart required | Infrastructure tab → TLS section |
| Metrics scrape token | **Yes** — live | Infrastructure tab → Prometheus section |

**Save behaviour:** When you click **Save & Apply**, changes that can be applied immediately take effect without interruption. Settings that need a restart trigger a dialog:

```
┌──────────────────────────────────────────────────┐
│  Restart required                                 │
│                                                   │
│  • Database (URL changed — needs a fresh start)  │
│                                                   │
│  ✓ Already live: Redis rate limiting              │
│                                                   │
│  Active sessions will be interrupted briefly.    │
│  Docker will restart automatically.              │
│                                                   │
│            [ Later ]   [ Restart Now ]           │
└──────────────────────────────────────────────────┘
```

The **Restart System** button in the tab header lets admins trigger a clean restart at any time. A full-screen spinner tracks the restart and auto-reloads the dashboard when the service is back up.

Configuration is persisted to `infra.yaml` (volume-mounted), so settings survive container rebuilds.

## High Availability Setup

To run multiple proxy instances sharing state, uncomment the `postgres` and `redis` services in `docker-compose.yml`, then set in `infra.yaml` (or `.env`):

```bash
DATABASE_URL="postgres://agentarmor:secret@postgres:5432/agentarmor?sslmode=disable"
REDIS_URL="redis://redis:6379"
```

Or configure it directly from the **Infrastructure tab** in the dashboard — no file editing needed.

Both are **opt-in** — the default single-container SQLite + in-memory rate limiting requires no changes.

## Prometheus Metrics

```
GET https://localhost:8443/armor/metrics
Authorization: Bearer <METRICS_TOKEN>   # if METRICS_TOKEN is set
```

Set `METRICS_TOKEN` from the Infrastructure tab (hot-reloaded, no restart needed).

Prometheus scrape config:
```yaml
- job_name: agentarmor
  static_configs:
    - targets: ["your-host:8443"]
  scheme: https
  bearer_token: "<METRICS_TOKEN>"
  tls_config: { insecure_skip_verify: true }  # remove when using CA cert
```

## Roadmap

### Recently shipped
- [x] **SSO / OIDC** — Google, Microsoft, Okta, Auth0, Keycloak; live-configurable from the Auth tab without restart
- [x] **Multi-tenancy** — Isolated policies, tokens, audit logs, and rate limits per team/application; routed via `X-Tenant-ID` header or Bearer token
- [x] **Secrets vault / KMS** — HashiCorp Vault (token or AppRole), AWS Secrets Manager (static creds or EC2 IMDSv2), GCP Secret Manager (service account or GCE metadata), Azure Key Vault (service principal or managed identity); zero new Go dependencies
- [x] **High availability** — PostgreSQL audit log + Redis distributed rate limiting; proxy is now stateless and horizontally scalable
- [x] **Prometheus metrics** — `/armor/metrics` endpoint with request counters, scanner rule counts, goroutines, heap usage
- [x] **Cert auto-renewal** — ACME / Let's Encrypt with HTTP-01 challenge; auto-renews before expiry
- [x] **Infrastructure dashboard (tab 10)** — configure PostgreSQL, Redis, ACME, and metrics token from the UI; hot-reload where possible; restart dialog ("now or later") for settings that need a container restart; Restart System button with auto-reload

### Recently shipped (continued)
- [x] **WASM filters** — Drop `.wasm` files into `./wasm-filters/`; runs after all built-in scanners; WASI stdin/stdout ABI works with Go, Rust, C, AssemblyScript; enable/disable/reload from Infrastructure tab without restart
- [x] **OpenTelemetry traces** — Minimal OTLP/HTTP emitter (zero new Go deps); one span per HTTP request + scan child span; compatible with Jaeger, Grafana Tempo, Honeycomb, Datadog Agent; `X-Trace-ID` in response headers

- [x] **Helm chart** — `helm/agentarmor/` — values for single, HA (PostgreSQL + Redis + HPA), sidecar, and ACME patterns; supports `existingSecret`, custom policy/firewall ConfigMaps, OIDC, OTel, and all secrets providers
- [x] **Audit log export** — `⬇ Export` dropdown in the Audit Log tab; CSV or NDJSON; row-limit options (1k / 10k / all rows); active filter preserved; admin-only; streams as a browser download

- [x] **Helm OCI registry** — chart published to `ghcr.io/vikrantwaghmode/agentarmor` via GitHub Actions on every release tag; `helm install oci://ghcr.io/vikrantwaghmode/agentarmor --version x.y.z`
- [x] **Audit date-range filter** — `From` / `To` datetime-local pickers in the export dropdown; filters passed as RFC3339 `?from=` / `?to=` params; active date range shown in the filter summary strip

### Upcoming
- [ ] **Diff viewer** — side-by-side policy snapshot comparison before restoring
- [ ] **Tenant policy templates** — create tenants from a named policy template instead of copying root policy

## Contributing

Open an issue first to discuss changes or reachout to vikrant.waghmode@gmail.com

LinkedIn: https://www.linkedin.com/in/securityhandyman/

## License

See [LICENSE](LICENSE).

---

<p align="center"><strong>AgentArmor</strong> — because your AI agent shouldn't have unsupervised access to the internet.</p>
