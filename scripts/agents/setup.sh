#!/usr/bin/env bash
# One-time, idempotent GitHub setup for the agent team: the labels
# run-loop.sh drives the review loop with, and one log issue per agent.
# Safe to re-run; it creates only what is missing.
set -euo pipefail
: "${REPO:=benj2468/wayfinder}"

label() { gh label create "$1" -R "$REPO" --color "$2" --description "$3" --force >/dev/null && echo "label $1"; }
label agent::ml 00A6A6 "PR authored by the ml-engineer agent"
label agent::needs-review FBCA04 "Agent loop: waiting for the principal-engineer agent"
label agent::changes-requested D93F0B "Agent loop: waiting for the authoring agent"
label agent::approved 0E8A16 "Agent loop: principal agent satisfied; waiting for Ben"
label needs-ben B60205 "Agent loop stopped; Ben decides. Remove to hand back to the loop"
label agent-log 5319E7 "An agent's run log: one comment per run"

log_issue() { # <role> <lane summary>
  local title="Agent log: $1"
  if gh issue list -R "$REPO" --label agent-log --state open --json title --jq '.[].title' | grep -qxF "$title"; then
    echo "issue '$title' exists"
    return
  fi
  gh issue create -R "$REPO" --label agent-log --title "$title" --body "🤖 **orchestrator**: run log for the \`$1\` agent ($2).

Each run appends one comment: **Done / Next / Blocked**. Every agent reads all logs before choosing work. Driven by \`scripts/agents/run-loop.sh\`; see \`scripts/agents/README.md\`."
}
log_issue ml-engineer "lane: sim/, ml/, proposed design docs"
log_issue principal-engineer "reviews every agent PR; daily sweep"
