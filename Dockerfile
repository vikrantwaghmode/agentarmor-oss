# =============================================================================
# AgentArmor — Single-container build
# Combines: OpenClaw Gateway + AgentArmor Security Proxy + iptables Firewall
#
# Architecture:
#   User :8080 → AgentArmor Proxy → OpenClaw Gateway :18789 (loopback only)
#                  ▪ Prompt injection scan
#                  ▪ Secret redaction
#                  ▪ iptables egress firewall
# =============================================================================

# --- Stage 1: Build OpenClaw from source ---
FROM node:22-bookworm AS openclaw-build

# Bun is required for OpenClaw's build scripts
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"

RUN corepack enable

WORKDIR /build
RUN git clone --depth 1 https://github.com/openclaw/openclaw.git .

# Install deps, build gateway, then build the Control UI
RUN pnpm install --frozen-lockfile || pnpm install
RUN pnpm build
RUN pnpm ui:install
RUN pnpm ui:build

# --- Stage 2: Build AgentArmor Go binaries ---
FROM golang:1.24-bookworm AS proxy-build

RUN apt-get update && apt-get install -y gcc libsqlite3-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY proxy/ ./proxy/
# policy.yaml is //go:embed-ed by main.go, so it must live next to it at build time
COPY policy.yaml ./proxy/policy.yaml

WORKDIR /src/proxy
RUN go mod tidy \
    && CGO_ENABLED=1 GOOS=linux go build -o /agentarmor-proxy ./main.go ./skills.go \
    && CGO_ENABLED=0 GOOS=linux go build -o /agentarmor-firewall ./firewall.go

# --- Stage 3: Final runtime ---
FROM node:22-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    git \
    curl \
    ca-certificates \
    openssl \
    python3 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create the openclaw user and directories
RUN useradd -m -s /bin/bash openclaw || true
RUN mkdir -p /data/.openclaw /data/workspace /app/data \
    && chown -R node:node /data

# Copy OpenClaw build artifacts (gateway + Control UI + runtime files)
COPY --from=openclaw-build /build/dist /app/openclaw/dist
COPY --from=openclaw-build /build/node_modules /app/openclaw/node_modules
COPY --from=openclaw-build /build/package.json /app/openclaw/package.json
COPY --from=openclaw-build /build/scripts /app/openclaw/scripts
COPY --from=openclaw-build /build/skills /app/openclaw/skills
COPY --from=openclaw-build /build/docs /app/openclaw/docs

# Copy AgentArmor binaries
COPY --from=proxy-build /agentarmor-proxy /app/agentarmor-proxy
COPY --from=proxy-build /agentarmor-firewall /app/agentarmor-firewall

# Copy config files
COPY policy.yaml /app/policy.yaml
COPY firewall.yaml /app/firewall.yaml

# Copy default skills (volume-mounted at runtime for live updates)
COPY skills/ /app/skills/

# Copy the entrypoint
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

WORKDIR /app

# 8443 = HTTPS (primary), 8080 = HTTP redirect → 8443
# OpenClaw gateway is on 127.0.0.1:18789 (loopback only, behind the proxy)
EXPOSE 8443 8080

ENTRYPOINT ["/app/docker-entrypoint.sh"]
