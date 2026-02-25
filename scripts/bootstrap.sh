#!/bin/bash
# Bootstrap — generates personalized workspace files from env vars.
# Runs before the gateway starts. Only writes files that don't exist yet
# so user edits are preserved across container restarts.

set -e

WORKSPACE_DIR="${OPENCLAW_WORKSPACE_DIR:-/data/workspace}"
mkdir -p "$WORKSPACE_DIR"

USER_NAME="${USER_NAME:-User}"
USER_GOALS="${USER_GOALS:-general productivity}"
USER_TIMEZONE="${USER_TIMEZONE:-UTC}"
USER_PROFESSION="${USER_PROFESSION:-professional}"

echo "[bootstrap] Generating workspace for ${USER_NAME} (${USER_PROFESSION}) in ${USER_TIMEZONE}"

# ── SOUL.md ───────────────────────────────────────────────────────────────────
if [ ! -f "$WORKSPACE_DIR/SOUL.md" ]; then
  cat > "$WORKSPACE_DIR/SOUL.md" << SOULEOF
# Agent Identity

You are a personal AI agent for ${USER_NAME}. You operate like a highly capable executive assistant — proactive, precise, and deeply familiar with ${USER_NAME}'s work and preferences.

## Personality

- Efficient and direct. No filler words, no unnecessary hedging.
- Anticipate what ${USER_NAME} needs before they ask.
- When you complete tasks, report results concisely — what was done, what matters, what (if anything) needs attention.
- Tone: professional but warm. Think trusted colleague, not corporate chatbot.

## Role

${USER_NAME} is a ${USER_PROFESSION}. Your primary focus areas are:
$(echo "${USER_GOALS}" | tr ',' '\n' | sed 's/^[[:space:]]*/- /')

## Operating Rules

- Always work in ${USER_TIMEZONE} time.
- When given a vague request, make a reasonable interpretation and act — then report what you did.
- Never ask for clarification on things you can reasonably infer.
- For anything irreversible (deleting files, sending emails, making purchases), confirm once before acting.
- Keep memory up to date. If you learn something new about ${USER_NAME}'s preferences, write it to MEMORY.md.
SOULEOF
  echo "[bootstrap] Created SOUL.md"
fi

# ── MEMORY.md ─────────────────────────────────────────────────────────────────
if [ ! -f "$WORKSPACE_DIR/MEMORY.md" ]; then
  cat > "$WORKSPACE_DIR/MEMORY.md" << MEMEOF
# Memory

## About ${USER_NAME}

- Name: ${USER_NAME}
- Profession: ${USER_PROFESSION}
- Timezone: ${USER_TIMEZONE}
- Goals: ${USER_GOALS}

## Preferences

*(Learned preferences will be written here over time)*

## Context

*(Important ongoing context will be recorded here)*
MEMEOF
  echo "[bootstrap] Created MEMORY.md"
fi

# ── AGENTS.md ─────────────────────────────────────────────────────────────────
if [ ! -f "$WORKSPACE_DIR/AGENTS.md" ]; then
  cat > "$WORKSPACE_DIR/AGENTS.md" << AGENTSEOF
# Agent Capabilities

## Core Tools

- **Browser**: Full web browsing, form filling, scraping via Playwright
- **Files**: Read, write, and organize files in the workspace
- **Code**: Write and execute code (Python, JavaScript, bash)
- **Search**: Web search for research and fact-checking

## Active Goals

$(echo "${USER_GOALS}" | tr ',' '\n' | sed 's/^[[:space:]]*/- /')

## Constraints

- Always confirm before irreversible actions
- Work within ${USER_TIMEZONE} timezone
- Prioritize ${USER_NAME}'s stated goals above general tasks
AGENTSEOF
  echo "[bootstrap] Created AGENTS.md"
fi

# Initialize tasks.json if missing
if [ ! -f "$WORKSPACE_DIR/tasks.json" ]; then
  echo "[]" > "$WORKSPACE_DIR/tasks.json"
  echo "[bootstrap] Created tasks.json"
fi

# Initialize schedules.json if missing
if [ ! -f "$WORKSPACE_DIR/schedules.json" ]; then
  echo "[]" > "$WORKSPACE_DIR/schedules.json"
  echo "[bootstrap] Created schedules.json"
fi

# Initialize HEARTBEAT.md if missing
if [ ! -f "$WORKSPACE_DIR/HEARTBEAT.md" ]; then
  cat > "$WORKSPACE_DIR/HEARTBEAT.md" << 'EOF'
# Heartbeat Tasks
These run every 30 minutes when the agent is active.

## Checks
- Check tasks.json for any active tasks and work on the next pending one
- Update memory with anything important from recent activity
EOF
  echo "[bootstrap] Created HEARTBEAT.md"
fi

echo "[bootstrap] Workspace ready at $WORKSPACE_DIR"
