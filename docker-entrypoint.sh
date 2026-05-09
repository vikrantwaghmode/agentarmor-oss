#!/bin/bash
set -e

echo "============================================"
echo "  🛡️  AgentArmor — Starting Up"
echo "============================================"

# -----------------------------------------------
# 1. LLM Provider Configuration
# -----------------------------------------------

# Default to gemini if not set
LLM_PROVIDER="${LLM_PROVIDER:-gemini}"

if [ "$LLM_PROVIDER" = "openclaw" ]; then
    echo "🚀 Configuring proxy for OpenClaw Gateway"
    OPENCLAW_HOME="/data/.openclaw"
    OPENCLAW_CONFIG="${OPENCLAW_HOME}/openclaw.json"

    # Create state directories
    mkdir -p "${OPENCLAW_HOME}" /data/workspace /app/data

    # Generate openclaw.json if it doesn't exist
    if [ ! -f "${OPENCLAW_CONFIG}" ]; then
        echo "📝 Generating OpenClaw config..."

        # Determine gateway token (from .env or generate a new one)
        TOKEN="${OPENCLAW_GATEWAY_TOKEN:-$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)}"

        cat > "${OPENCLAW_CONFIG}" <<OCEOF
{
  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "loopback",
    "auth": {
      "mode": "token",
      "token": "${TOKEN}"
    },
    "controlUi": {
      "enabled": true,
      "allowInsecureAuth": true,
      "allowedOrigins": [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:18789",
        "http://127.0.0.1:18789"
      ]
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "google/gemini-2.5-flash"
      }
    }
  },
  "plugins": {
    "entries": {
      "google": {
        "enabled": true
      }
    }
  }
}
OCEOF

        echo "✅ OpenClaw config written to ${OPENCLAW_CONFIG}"
        echo "🔑 Gateway token: ${TOKEN}"
        export OPENCLAW_GATEWAY_TOKEN_VALUE="${TOKEN}"
    else
        echo "✅ Using existing OpenClaw config at ${OPENCLAW_CONFIG}"
        # Extract token from existing config to pass to the proxy for UI injection
        TOKEN=$(grep -oP '"token":\s*"\K[^"]+' "${OPENCLAW_CONFIG}" || echo "")
        export OPENCLAW_GATEWAY_TOKEN_VALUE="${TOKEN}"
    fi

    # Run onboarding if first time
    if [ ! -f "${OPENCLAW_HOME}/.onboarded" ]; then
        echo "🔧 Running first-time onboarding..."
        cd /app/openclaw
        HOME=/data OPENCLAW_ALLOW_ROOT=1 node dist/index.js onboard --mode local --no-install-daemon 2>/dev/null || true
        touch "${OPENCLAW_HOME}/.onboarded"
        cd /app
    fi

    # Start OpenClaw Gateway (background, loopback only)
    echo "🦞 Starting OpenClaw Gateway on 127.0.0.1:18789..."
    cd /app/openclaw
    HOME=/data OPENCLAW_ALLOW_ROOT=1 node dist/index.js gateway --bind loopback --port 18789 &
    GATEWAY_PID=$!
    cd /app

    # Wait for gateway to be ready
    echo "⏳ Waiting for OpenClaw Gateway to be ready..."
    for i in $(seq 1 30); do
        if curl -sf http://127.0.0.1:18789/healthz > /dev/null 2>&1; then
            echo "✅ OpenClaw Gateway is ready!"
            break
        fi
        if ! kill -0 $GATEWAY_PID 2>/dev/null; then
            echo "❌ OpenClaw Gateway process died. Check logs above."
            exit 1
        fi
        sleep 1
    done

    if ! curl -sf http://127.0.0.1:18789/healthz > /dev/null 2>&1; then
        echo "❌ OpenClaw Gateway failed to start within 30 seconds."
        exit 1
    fi
    export TARGET_URL="http://127.0.0.1:18789"
    echo "   Proxying to OpenClaw Gateway at ${TARGET_URL}"
else
    echo "🚀 Configuring direct proxy for provider: $LLM_PROVIDER"
    # Create data directory if it doesn't exist (for audit.db)
    mkdir -p /app/data
    case "$LLM_PROVIDER" in
        "openai")
            export TARGET_URL="https://api.openai.com"
            export LLM_API_KEY="$OPENAI_API_KEY"
            export LLM_AUTH_HEADER_NAME="Authorization"
            export LLM_AUTH_HEADER_VALUE_PREFIX="Bearer "
            ;;
        "anthropic")
            export TARGET_URL="https://api.anthropic.com"
            export LLM_API_KEY="$ANTHROPIC_API_KEY"
            export LLM_AUTH_HEADER_NAME="x-api-key"
            ;;
        "gemini")
            export TARGET_URL="https://generativelanguage.googleapis.com"
            export LLM_API_KEY="$GEMINI_API_KEY"
            export LLM_AUTH_HEADER_NAME="x-goog-api-key"
            ;;
        *)
            echo "❌ Unknown LLM_PROVIDER: '$LLM_PROVIDER'. Must be one of: openai, anthropic, gemini, openclaw. Exiting."
            exit 1
            ;;
    esac
    if [ -z "$LLM_API_KEY" ]; then
        echo "⚠️  Warning: LLM_PROVIDER is '$LLM_PROVIDER' but the corresponding API key is not set."
    fi
    echo "   Proxying to ${TARGET_URL}"
fi

# -----------------------------------------------
# 2. Apply iptables Firewall (Layer 3/4)
# -----------------------------------------------
echo "🧱 Applying AgentArmor network firewall..."
./agentarmor-firewall || echo "⚠️  Firewall setup failed (may need NET_ADMIN capability)"

# -----------------------------------------------
# 3. Start AgentArmor Proxy (foreground, Layer 7)
# -----------------------------------------------
echo "🛡️  Starting AgentArmor Security Proxy on 0.0.0.0:8080..."
echo "============================================"
echo "  ✅ AgentArmor is LIVE"
echo "  🌐 Open http://localhost:8080/armor/ in your browser"
echo "============================================"

exec ./agentarmor-proxy
