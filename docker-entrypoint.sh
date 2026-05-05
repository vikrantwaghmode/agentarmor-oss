#!/bin/bash
set -e

echo "============================================"
echo "  🛡️  AgentArmor — Starting Up"
echo "============================================"

# -----------------------------------------------
# 1. OpenClaw Configuration
# -----------------------------------------------
OPENCLAW_HOME="/data/.openclaw"
OPENCLAW_CONFIG="${OPENCLAW_HOME}/openclaw.json"

# Create state directories
mkdir -p "${OPENCLAW_HOME}" /data/workspace /app/data

# Generate openclaw.json if it doesn't exist
if [ ! -f "${OPENCLAW_CONFIG}" ]; then
    echo "📝 Generating OpenClaw config..."

    # Determine gateway token
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
  }
}
OCEOF

    echo "✅ OpenClaw config written to ${OPENCLAW_CONFIG}"
    echo "🔑 Gateway token: ${TOKEN}"
else
    echo "✅ Using existing OpenClaw config at ${OPENCLAW_CONFIG}"
fi

# -----------------------------------------------
# 2. Run onboarding if first time
# -----------------------------------------------
if [ ! -f "${OPENCLAW_HOME}/.onboarded" ]; then
    echo "🔧 Running first-time onboarding..."
    cd /app/openclaw
    HOME=/data node dist/index.js onboard --mode local --no-install-daemon 2>/dev/null || true
    touch "${OPENCLAW_HOME}/.onboarded"
    cd /app
fi

# -----------------------------------------------
# 3. Start OpenClaw Gateway (background, loopback only)
# -----------------------------------------------
echo "🦞 Starting OpenClaw Gateway on 127.0.0.1:18789..."
cd /app/openclaw
HOME=/data node dist/index.js gateway --bind loopback --port 18789 &
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

# -----------------------------------------------
# 4. Apply iptables Firewall (Layer 2)
# -----------------------------------------------
echo "🧱 Applying AgentArmor network firewall..."
./agentarmor-firewall || echo "⚠️  Firewall setup failed (may need NET_ADMIN capability)"

# -----------------------------------------------
# 5. Start AgentArmor Proxy (foreground, Layer 1)
# -----------------------------------------------
echo "🛡️  Starting AgentArmor Security Proxy on 0.0.0.0:8080..."
echo "   Proxying to OpenClaw Gateway at http://127.0.0.1:18789"
echo "============================================"
echo "  ✅ AgentArmor is LIVE"
echo "  🌐 Open http://localhost:8080 in your browser"
echo "============================================"

export TARGET_URL="http://127.0.0.1:18789"
exec ./agentarmor-proxy
