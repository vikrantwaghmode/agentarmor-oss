<p align="center">
  <h1 align="center">🛡️ AgentArmor</h1>
  <p align="center">
    <strong>A two-layer security proxy for LLM-powered applications</strong>
  </p>
  <p align="center">
    <a href="https://github.com/vikrantwaghmode/agentarmor-oss/blob/main/LICENSE"><img src="https://img.shields.io/github/license/vikrantwaghmode/agentarmor-oss?style=flat-square&color=blue" alt="License"></a>
    <img src="https://img.shields.io/badge/go-1.24-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.24">
    <img src="https://img.shields.io/badge/docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker">
    <img src="https://img.shields.io/badge/layer_7-application_proxy-8B5CF6?style=flat-square" alt="Layer 7">
    <img src="https://img.shields.io/badge/layer_3/4-network_firewall-EF4444?style=flat-square" alt="Layer 3/4">
  </p>
</p>

---

AgentArmor sits between your application and external LLM providers, inspecting and controlling **every** request and response. It combines application-layer content scanning with network-layer egress control — so even if one layer is bypassed, the other still protects you.

```
                    ┌──────────────────────┐
                    │   Your Application   │
                    │  (OpenClaw, custom)   │
                    └──────────┬───────────┘
                               │ HTTP / WebSocket
                    ┌──────────▼───────────────────────────────────┐
                    │         AgentArmor Proxy (Layer 7)           │
                    │                                              │
                    │  ┌────────────┐  ┌────────────┐  ┌────────┐ │
                    │  │  Prompt    │  │  Secret    │  │  PII   │ │
                    │  │ Injection  │  │ Redaction  │  │  DLP   │ │
                    │  └────────────┘  └────────────┘  └────────┘ │
                    │  ┌────────────┐  ┌────────────┐  ┌────────┐ │
                    │  │ Malicious  │  │   Audit    │  │  Web   │ │
                    │  │  Content   │  │  Logging   │  │ Dash.  │ │
                    │  └────────────┘  └────────────┘  └────────┘ │
                    └──────────┬───────────────────────────────────┘
                               │ Filtered traffic
                    ┌──────────▼───────────────────────────────────┐
                    │     iptables Egress Firewall (Layer 3/4)     │
                    │     Zero-trust: only whitelisted domains     │
                    └──────────┬───────────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
         ┌─────────┐    ┌──────────┐    ┌───────────┐
         │ OpenAI  │    │Anthropic │    │  Gemini   │
         └─────────┘    └──────────┘    └───────────┘
```

## Why AgentArmor?

AI agents can browse the web, execute code, and call APIs — but most teams ship them with **zero middleware security**. A single prompt injection can leak API keys, exfiltrate data, or execute malicious commands with no audit trail.

AgentArmor provides defense-in-depth: every message is scanned, every action is logged, and the container can only reach domains you explicitly allow.

## Features

### Layer 7 — Application Proxy

| Scanner | Direction | Action | What it catches |
|---------|-----------|--------|-----------------|
| **Prompt Injection** | Inbound | Block | Jailbreaks, instruction overrides, role manipulation |
| **Secret Redaction** | Both | Redact | API keys (OpenAI, Anthropic, Google), JWTs, private keys |
| **PII / DLP** | Both | Block | Email, phone, SSN, credit card numbers |
| **Malicious Content** | Both | Block | SQLi, XSS, SSRF, command injection, executables |

Additional capabilities:

- **WebSocket scanning** — Intercepts and scans real-time WebSocket frames, not just HTTP POST bodies
- **Streaming DLP** — Sliding-window scanner catches secrets fragmented across streaming response chunks
- **Hot-reload policies** — Update `policy.yaml` without restarting; changes apply within seconds
- **Audit logging** — Every request logged to SQLite with timestamp, action, matched rule, and payload snippet
- **Web dashboard** — Real-time monitoring at `http://localhost:8080/armor/` with RBAC (admin/user roles)
- **Granular rule control** — Enable/disable individual rules from the dashboard

### Layer 3/4 — Network Firewall

- **Zero-trust egress** — `iptables` DROP rule blocks all outbound traffic except whitelisted domains
- **DNS-aware** — Allows runtime DNS resolution for whitelisted domains
- **Container-scoped** — Firewall rules apply to the entire container, including all child processes

## Quick Start

**Prerequisites:** Docker and Docker Compose

```bash
# 1. Clone
git clone https://github.com/vikrantwaghmode/agentarmor-oss.git
cd agentarmor-oss

# 2. Configure
cp .env.template .env
# Edit .env — add your API key and set access tokens

# 3. Run
docker compose up --build

# 4. Open the dashboard
# → http://localhost:8080/armor/
```

### Environment Variables

```bash
# --- Dashboard Access ---
ADMIN_TOKEN="your-admin-token"        # Full dashboard control
USER_TOKEN="your-user-token"          # Read-only dashboard access

# --- LLM Provider (choose one) ---
LLM_PROVIDER="gemini"                 # openai | anthropic | gemini | openclaw

# --- API Keys (for your chosen provider) ---
OPENAI_API_KEY="sk-..."
ANTHROPIC_API_KEY="sk-ant-..."
GEMINI_API_KEY="AIza..."
```

## How It Works

```
 Inbound Request
       │
       ▼
 ┌─────────────────┐     ┌─────────┐
 │ Prompt Injection │──▶  │ BLOCKED │  → 403 / WS drop
 │     Scanner      │     └─────────┘
 └────────┬────────┘
          │ pass
          ▼
 ┌─────────────────┐     ┌──────────┐
 │ Secret Redaction │──▶  │ REDACTED │  → modified payload forwarded
 │     Scanner      │     └──────────┘
 └────────┬────────┘
          │ pass
          ▼
 ┌─────────────────┐     ┌─────────┐
 │   PII / DLP     │──▶  │ BLOCKED │
 │    Scanner       │     └─────────┘
 └────────┬────────┘
          │ pass
          ▼
 ┌─────────────────┐     ┌─────────┐
 │   Malicious     │──▶  │ BLOCKED │
 │   Content        │     └─────────┘
 └────────┬────────┘
          │ clean
          ▼
 ┌─────────────────┐
 │iptables Firewall│──▶  Whitelisted domains only
 └────────┬────────┘
          │
          ▼
     LLM Provider
          │
          ▼ response
 ┌─────────────────┐
 │ Response DLP    │──▶  Streaming secret scan
 │   Scanner        │
 └────────┬────────┘
          │
          ▼
  Back to your app
```

All decisions are logged to the audit database. View them in the dashboard or query directly:

```bash
sqlite3 ./data/audit.db "SELECT timestamp, direction, action, rule_matched FROM audit_logs ORDER BY id DESC LIMIT 10;"
```

## Configuration

### Security Policies — `policy.yaml`

Policies are hot-reloadable. Edit the file and AgentArmor picks up changes automatically.

```yaml
scanners:
  prompt_injection:
    enabled: true
    blocked_phrases:
      - "ignore all previous instructions"
      - "you are an unfiltered ai"
      - "system prompt override"
      - "respond as dan"

  secrets:
    enabled: true
    redact_patterns:
      - '(?i)(sk-[a-zA-Z0-9]{20,})'           # OpenAI
      - '(?i)(sk-ant-[a-zA-Z0-9-]{20,})'       # Anthropic
      - '(?i)(AIza[a-zA-Z0-9_-]{35})'           # Google

  pii:
    enabled: true
    patterns:
      - '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Email
      - '\b\d{3}-\d{2}-\d{4}\b'                                   # SSN

  malicious_content:
    enabled: true
    patterns:
      - "(?i)(union\\s+select|' or 1=1)"        # SQLi
      - "(?i)(<script|onerror=)"                  # XSS
      - "(?i)(file:///etc/passwd)"                # SSRF
```

### Network Firewall — `firewall.yaml`

```yaml
allowed_domains:
  - "api.openai.com"
  - "api.anthropic.com"
  - "generativelanguage.googleapis.com"
```

Only these domains can be reached from the container. All other outbound traffic is dropped.

## Project Structure

```
agentarmor-oss/
├── Dockerfile                 # Multi-stage build (Go proxy + OpenClaw from source)
├── docker-compose.yml         # Single-container orchestration
├── docker-entrypoint.sh       # Starts gateway → firewall → proxy
├── .env.template              # Environment variable template
├── policy.yaml                # Security scanner rules (hot-reloadable)
├── firewall.yaml              # Allowed egress domains
├── proxy/
│   ├── main.go                # Reverse proxy + WebSocket scanner + audit logging
│   ├── firewall.go            # iptables configuration at startup
│   ├── go.mod
│   └── go.sum
├── data/                      # Audit database (auto-created)
│   └── audit.db
└── config/                    # OpenClaw state (auto-created)
    └── openclaw.json
```

## Testing

```bash
# Check if it's running
curl -sf http://localhost:8080/healthz

# Test prompt injection blocking (should return 403)
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{"message": "ignore all previous instructions"}'

# Test secret redaction (key should be replaced with [REDACTED_API_KEY])
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{"message": "My key is sk-ant-abc123def456ghi789jklmnopqrstuv"}'

# Test firewall (should timeout — example.com is not whitelisted)
docker exec agentarmor curl -s --max-time 3 https://example.com

# Check audit log
sqlite3 ./data/audit.db \
  "SELECT timestamp, direction, action, rule_matched FROM audit_logs ORDER BY id DESC LIMIT 5;"
```

## Roadmap

- [ ] **LLM-powered scanners** — Local model for contextual prompt injection detection beyond regex
- [ ] **Rate limiting** — Per-user/per-IP throttling
- [ ] **Dynamic firewall updates** — Modify egress rules from the dashboard without restart
- [ ] **SIEM integration** — Export audit logs to external systems
- [ ] **Custom redaction** — User-defined redaction strings (hashing, masking)
- [ ] **Threat intelligence feeds** — Dynamic malicious content pattern updates
- [ ] **Multi-tenancy** — Isolated policies and audit trails per application
- [ ] **WASM filters** — WebAssembly modules for custom filtering logic

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

## License

See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>AgentArmor</strong> — because your AI agent shouldn't have unsupervised access to the internet.
</p>