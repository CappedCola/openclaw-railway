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

# ── Daily memory directory ────────────────────────────────────────────────────
MEMORY_DIR="$WORKSPACE_DIR/memory"
mkdir -p "$MEMORY_DIR"

TODAY=$(date +%Y-%m-%d)
MEMORY_FILE="$MEMORY_DIR/${TODAY}.md"

if [ ! -f "$MEMORY_FILE" ]; then
  cat > "$MEMORY_FILE" << MEMDAYEOF
# Session Log — ${TODAY}

## Worked On

*(Fill in at end of session)*

## Decisions Made

*(Fill in at end of session)*

## Blockers

*(Fill in at end of session)*

## Next Steps

*(Fill in at end of session)*
MEMDAYEOF
  echo "[bootstrap] Created memory/${TODAY}.md"
fi

# ── CLAUDE.md — session initialization rules ─────────────────────────────────
# Always overwrite so updates to the template are applied on redeploy.
cat > "$WORKSPACE_DIR/CLAUDE.md" << CLAUDEEOF
# Session Rules for ${USER_NAME}'s Agent

## SESSION INITIALIZATION — LOAD ONLY THESE FILES

On every session start, load ONLY:
1. \`SOUL.md\` — identity and operating rules
2. \`MEMORY.md\` — user preferences and long-term context
3. \`memory/\$(date +%Y-%m-%d).md\` — today's session log (if it exists)

DO NOT auto-load:
- Session history or prior messages
- Previous tool outputs
- Any file not listed above

When the user asks about prior context:
- Search \`memory/\` directory for the relevant date file
- Pull only the specific section needed
- Do not load the whole file

## WORKSPACE MAP

Everything lives under \`${WORKSPACE_DIR}/\`:

| File / Dir         | Purpose                                          |
|--------------------|--------------------------------------------------|
| \`SOUL.md\`          | Agent identity, personality, operating rules     |
| \`MEMORY.md\`        | Long-term preferences and user context           |
| \`memory/YYYY-MM-DD.md\` | Daily session logs                          |
| \`tasks.json\`       | Active task queue (read/write via agent tools)   |
| \`schedules.json\`   | Scheduled job definitions                        |
| \`HEARTBEAT.md\`     | Recurring background task definitions            |
| \`AGENTS.md\`        | Capability reference (tools and skills)          |
| \`skills/\`          | Installed skill directories                      |

## TOKEN-SAVING RULES

- Read files in narrow sections — never load entire large files unless required.
- For skills: read only the \`SKILL.md\` header (first 20 lines) unless you need full instructions.
- For memory search: scan \`memory/\` filenames first, then open only the matching date.
- When writing to \`MEMORY.md\`: append or patch the relevant section — never rewrite the whole file.
- Prefer targeted reads (specific line ranges) over full-file reads.

## END OF SESSION

Before closing, update \`memory/\$(date +%Y-%m-%d).md\` with:
- What you worked on
- Decisions made
- Blockers encountered
- Next steps for ${USER_NAME}

This saves ~80% context overhead across sessions.

## USER

- Name: ${USER_NAME}
- Profession: ${USER_PROFESSION}
- Timezone: ${USER_TIMEZONE}
- Goals: ${USER_GOALS}
CLAUDEEOF
echo "[bootstrap] Wrote CLAUDE.md"

# ── Skills Setup ──────────────────────────────────────────────────────────────
SKILLS_DIR="$WORKSPACE_DIR/skills"
mkdir -p "$SKILLS_DIR"

# Copy built-in skills from container
if [ -d "/app/skills" ]; then
  for skill in /app/skills/*/; do
    skill_name=$(basename "$skill")
    if [ ! -e "$SKILLS_DIR/$skill_name" ]; then
      cp -r "$skill" "$SKILLS_DIR/"
      echo "[bootstrap] Installed skill: $skill_name"
    fi
  done
fi

# ── AGENTS.md with Skills ────────────────────────────────────────────────────
if [ ! -f "$WORKSPACE_DIR/AGENTS.md" ]; then
  cat > "$WORKSPACE_DIR/AGENTS.md" << AGENTSEOF
# Agent Capabilities

## Core Tools

- **Browser**: Full web browsing, form filling, scraping via Playwright
- **Files**: Read, write, and organize files in the workspace
- **Code**: Write and execute code (Python, JavaScript, bash)
- **Search**: Web search via Exa.ai for research and fact-checking
- **Memory**: Daily session logs in \`memory/YYYY-MM-DD.md\` — search by date, load only the relevant section

## Built-in Skills

$(for skill_dir in "$SKILLS_DIR"/*/; do
  if [ -f "$skill_dir/SKILL.md" ]; then
    skill_name=$(basename "$skill_dir")
    desc=$(grep -m1 "^description:" "$skill_dir/SKILL.md" | sed 's/description: //' || echo "No description")
    echo "- **$skill_name**: $desc"
  fi
done)

## Active Goals

$(echo "${USER_GOALS}" | tr ',' '\n' | sed 's/^[[:space:]]*/- /')

## Constraints

- Always confirm before irreversible actions
- Work within ${USER_TIMEZONE} timezone
- Prioritize ${USER_NAME}'s stated goals above general tasks
AGENTSEOF
  echo "[bootstrap] Created AGENTS.md"
fi

echo "[bootstrap] Workspace ready at $WORKSPACE_DIR"
