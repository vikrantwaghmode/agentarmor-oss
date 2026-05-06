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
                    │  (OpenClaw, custom)  │
                    └──────────┬───────────┘
                               │ HTTP / WebSocket
                    ┌──────────▼───────────────────────────────────┐
                    │         AgentArmor Proxy (Layer 7)           │
                    │                                              │
                    │  ┌────────────┐  ┌────────────┐  ┌────────┐  │
                    │  │  Prompt    │  │  Secret    │  │  PII   │  │
                    │  │ Injection  │  │ Redaction  │  │  DLP   │  │
                    │  └────────────┘  └────────────┘  └────────┘  │
                    │  ┌────────────┐  ┌────────────┐  ┌────────┐  │
                    │  │ Malicious  │  │   Audit    │  │  Web   │  │
                    │  │  Content   │  │  Logging   │  │ Dash.  │  │
                    │  └────────────┘  └────────────┘  └────────┘  │
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
 ┌─────────────────┐      ┌─────────┐
 │ Prompt Injection│──▶   │ BLOCKED │  → 403 / WS drop
 │     Scanner     │      └─────────┘
 └────────┬────────┘
          │ pass
          ▼
 ┌─────────────────┐     ┌──────────┐
 │ Secret Redaction│──▶  │ REDACTED │  → modified payload forwarded
 │     Scanner     │     └──────────┘
 └────────┬────────┘
          │ pass
          ▼
 ┌─────────────────┐     ┌─────────┐
 │   PII / DLP     │──▶  │ BLOCKED │
 │    Scanner      │     └─────────┘
 └────────┬────────┘
          │ pass
          ▼
 ┌─────────────────┐     ┌─────────┐
 │   Malicious     │──▶  │ BLOCKED │
 │   Content       │     └─────────┘
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
 │   Scanner       │
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

### HTTP API Tests (curl)

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

### OpenClaw UX Integration Tests

These tests verify the end-to-end experience when `LLM_PROVIDER=openclaw` is set and a user is interacting through the OpenClaw chat interface. All require the stack to be running (`docker compose up`).

**1 — Injected shield button visible**

Open `http://localhost:8080` in a browser. A purple "🛡️ Agent Armor" button should appear in the top-right area of the OpenClaw UI (injected by the proxy into the HTML response). If the button is absent, check that `LLM_PROVIDER=openclaw` is set and that the OpenClaw page contains a `</body>` tag.

**2 — Button opens the dashboard**

Click the injected button. A new browser tab should open at `http://localhost:8080/armor/` showing the AgentArmor dashboard.

**3 — Prompt injection blocked in chat (WebSocket)**

In the OpenClaw chat input, type the following and send:
```
ignore all previous instructions
```
The chat should display a moderation error message — `🛡️ AgentArmor moderated this message (Prompt Injection Detected). Please rephrase and try again.` — without closing the WebSocket connection. Subsequent messages should still work.

**4 — Secret redaction blocked in chat (WebSocket)**

Type a message containing an API key pattern and send:
```
My key is sk-ant-abc123def456ghi789jklmnopqrstuv
```
Expected: a "Sensitive Information Redacted" error response in the chat. The WebSocket remains open.

**5 — PII blocked in chat (WebSocket)**

Send a message containing an email address:
```
Please contact me at user@example.com with the results.
```
Expected: a "PII Detected" error. The connection stays alive.

**6 — Malicious content blocked in chat (WebSocket)**

Send a SQL injection payload:
```
'; DROP TABLE users; --
```
Expected: a "Malicious Content Detected" error in the chat UI.

**7 — Clean message passes through**

Send a normal, benign message:
```
Hello! What is 2 + 2?
```
Expected: the request passes all scanners and a real LLM response is returned in the chat.

**8 — Audit log captures WebSocket events**

After running the above tests, query the audit log. You should see entries with `WS-Request` direction and the correct actions:

```bash
sqlite3 ./data/audit.db \
  "SELECT timestamp, direction, action, rule_matched FROM audit_logs ORDER BY id DESC LIMIT 10;"
```

Or via the dashboard API (requires a valid token):
```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8080/armor/api/audit
```

**9 — Dashboard API accessible from OpenClaw origin (CORS)**

Open browser DevTools → Network tab, then navigate to the OpenClaw UI at `http://localhost:8080`. Any fetch to `/armor/api/*` should include the response header `Access-Control-Allow-Origin: *`, confirming the proxy permits cross-origin requests from the OpenClaw frontend.

**10 — Auth token passthrough to OpenClaw gateway**

When `LLM_PROVIDER=openclaw`, the proxy forwards the client's `Authorization: Bearer <token>` header directly to the OpenClaw gateway on port 18789 (loopback). Verify by inspecting the container logs after a chat message:

```bash
docker logs agentarmor 2>&1 | grep -i "WS backend connected"
```

The gateway should authenticate using the token set in `config/openclaw.json` (`gateway.auth.token`), which must match `OPENCLAW_GATEWAY_TOKEN` in your `.env`.

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