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

exec gosu openclaw node src/server.js
