#!/bin/bash
set -e

chown -R openclaw:openclaw /data 2>/dev/null || true
chmod 700 /data

if [ ! -d /data/.linuxbrew ]; then
  cp -a /home/linuxbrew/.linuxbrew /data/.linuxbrew
fi

rm -rf /home/linuxbrew/.linuxbrew
ln -sfn /data/.linuxbrew /home/linuxbrew/.linuxbrew

# Run bootstrap to generate personalized workspace files if this is a
# provisioned consumer container (USER_NAME or GEMINI_API_KEY is set).
if [ -n "$USER_NAME" ] || [ -n "$GEMINI_API_KEY" ]; then
  mkdir -p "${OPENCLAW_WORKSPACE_DIR:-/data/workspace}"
  bash /app/scripts/bootstrap.sh
fi

# ── Network isolation ─────────────────────────────────────────────────────────
# Block outbound access to RFC 1918 private ranges so this container cannot
# reach other containers on Railway's private WireGuard mesh. Falls back
# silently if NET_ADMIN capability is not available (e.g. local dev).
if iptables -L OUTPUT -n > /dev/null 2>&1; then
  iptables -F OUTPUT 2>/dev/null || true
  # Allow loopback and already-established connections
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  # Allow DNS (servers are often in private ranges, so allow before the DROPs)
  iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
  # Block RFC 1918 — prevents lateral movement to other Railway services
  iptables -A OUTPUT -d 10.0.0.0/8     -j DROP
  iptables -A OUTPUT -d 172.16.0.0/12  -j DROP
  iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
  # Allow all other outbound (public internet)
  iptables -A OUTPUT -j ACCEPT
  echo "[entrypoint] network isolation: iptables rules applied"
else
  echo "[entrypoint] network isolation: iptables unavailable (no NET_ADMIN), skipping"
fi

exec gosu openclaw node src/server.js
