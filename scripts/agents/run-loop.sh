#!/usr/bin/env bash
# Orchestrates wayfinder's agent team on this machine.
#
#   run-loop.sh ml       ML run (respond to reviews, then one task), then the
#                        principal review loop on every agent PR it produced
#   run-loop.sh review   only the review loop, over agent PRs awaiting it
#   run-loop.sh sweep    the principal engineer's daily sweep
#   run-loop.sh status   print agent PRs and their loop state; changes nothing
#
# The script owns all orchestration state, and that state lives on GitHub, so
# every run is stateless and a crash loses nothing:
#   agent::ml                  PR authored by the ML agent (branch agent/ml/*)
#   agent::needs-review        waiting for the principal
#   agent::changes-requested   waiting for the author
#   agent::approved            principal is satisfied; waiting for Ben
#   needs-ben                  loop stopped (round cap, out of lane, failure);
#                              remove the label to hand the PR back to the loop
# A review round is one principal review carrying an `<!-- agent-review … -->`
# marker. GitHub cannot record a real verdict, because every agent runs as
# Ben's account, so the marker carries it.
#
# The prompts and this script are run from AGENT_REF (default origin/main),
# never from a working tree: an agent cannot change its own rules until Ben
# merges the change. Set AGENT_REF=HEAD to try a local commit first.
#
# See scripts/agents/README.md for setup and the cron lines.
set -euo pipefail

# ---------------------------------------------------------------- config
: "${REPO:=benj2468/wayfinder}"
: "${AGENT_REF:=origin/main}"           # where prompts + this script come from
: "${AGENT_BASE:=origin/main}"          # what agent worktrees start from
: "${AGENT_HOME:=$HOME/.local/state/wayfinder-agents}"
: "${WT_BASE:=$HOME/sources/wt-agent}"  # → wt-agent-ml, wt-agent-principal
: "${ML_MODEL:=sonnet}"                 # CLAUDE.md: Sonnet builds,
: "${PRINCIPAL_MODEL:=opus}"            #            Opus reviews
: "${ML_BUDGET_USD:=15}"                # per claude invocation
: "${PRINCIPAL_BUDGET_USD:=10}"
: "${RUN_TIMEOUT:=90m}"                 # per claude invocation
: "${MAX_ROUNDS:=3}"                    # review rounds per cycle
: "${MAX_RESTARTS:=1}"                  # cycles the principal may restart before Ben must decide
: "${ML_WIP_LIMIT:=2}"                  # open, un-merged ML PRs before it stops
: "${PERMISSION_MODE:=auto}"
: "${MEMORY_MAX:=4500M}"                # cgroup cap so cargo can't OOM the box
: "${MIN_FREE_GB:=6}"
: "${LOCK_WAIT_S:=}"                    # default: ml/review 0 (next hour retries), sweep 4 h
: "${DRY_RUN:=0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

L_ML=agent::ml
L_REVIEW=agent::needs-review
L_CHANGES=agent::changes-requested
L_APPROVED=agent::approved
L_BEN=needs-ben
L_LOG=agent-log
STATE_LABELS=("$L_REVIEW" "$L_CHANGES" "$L_APPROVED" "$L_BEN")
ML_BRANCH_PREFIX=agent/ml/
# What the ML agent may change without a design doc being accepted first.
ML_LANE='^(sim/|ml/|uv\.lock$|docs/design/[0-9]{2}-[^/]+\.md$)'

cmd=${1:-}
case $cmd in ml | review | sweep | status) ;; *)
  sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
  ;;
esac

# Cron gives a bare environment.
export PATH="$HOME/.npm-packages/bin:/run/current-system/sw/bin:/etc/profiles/per-user/$USER/bin:$HOME/.nix-profile/bin:$PATH"
# A caller's activated venv (direnv) must not leak into the agents' shells.
unset VIRTUAL_ENV
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

# ---------------------------------------------------------------- stage
# First pass: snapshot scripts/agents at AGENT_REF and re-exec it with gh on
# PATH. The orchestrator needs only gh, jq and git. Each agent gets the repo's
# devShell entered *in its own worktree* (see run_agent), so the shell hook
# syncs that worktree's .venv rather than whichever checkout cron started in.
if [[ -z ${AGENT_STAGED:-} ]]; then
  REPO_ROOT=$(git -C "$(dirname "$(readlink -f "$0")")" rev-parse --show-toplevel)
  git -C "$REPO_ROOT" fetch -q origin
  rev=$(git -C "$REPO_ROOT" rev-parse "$AGENT_REF^{commit}")
  stage=$AGENT_HOME/staged
  rm -rf "$stage" && mkdir -p "$stage"
  git -C "$REPO_ROOT" cat-file -e "$rev:scripts/agents/run-loop.sh" 2>/dev/null ||
    { echo "scripts/agents is not on $AGENT_REF yet; try AGENT_REF=HEAD" >&2; exit 1; }
  git -C "$REPO_ROOT" archive "$rev" scripts/agents | tar -x -C "$stage"
  exec env AGENT_STAGED="$stage/scripts/agents" REPO_ROOT="$REPO_ROOT" AGENT_REV="$rev" \
    nix shell nixpkgs#gh nixpkgs#jq --command \
    bash "$stage/scripts/agents/run-loop.sh" "$@"
fi
AGENTS=$AGENT_STAGED
: "${AGENT_REV:=unknown}" "${REPO_ROOT:?}"

# Agents push over HTTPS with gh's token, so a run needs no ssh-agent.
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=url.https://github.com/.insteadOf GIT_CONFIG_VALUE_0=git@github.com:
export GIT_CONFIG_KEY_1=credential.https://github.com.helper GIT_CONFIG_VALUE_1='!gh auth git-credential'

RUN_DIR=$AGENT_HOME/runs/$(date +%F)/$(date +%H%M%S)-$cmd
mkdir -p "$RUN_DIR"
log() { printf '%s [%s] %s\n' "$(date -Is)" "$cmd" "$*" | tee -a "$RUN_DIR/loop.log" >&2; }
die() { log "FATAL: $*"; exit 1; }

# Every GitHub write goes through here, so DRY_RUN is honest.
ghw() {
  if [[ $DRY_RUN == 1 ]]; then log "dry-run: gh $*"; else gh "$@" >/dev/null; fi
}

# ---------------------------------------------------------------- preflight
preflight() {
  command -v claude >/dev/null || die "claude not on PATH"
  gh auth status >/dev/null 2>&1 || die "gh is not authenticated"
  local free_gb
  free_gb=$(df -BG --output=avail "$(dirname "$WT_BASE")" | tail -1 | tr -dc 0-9)
  ((free_gb >= MIN_FREE_GB)) || die "only ${free_gb}G free (< ${MIN_FREE_GB}G); run 'just clean' in a worktree"
  if systemd-run --user --scope --quiet true 2>/dev/null; then
    SCOPE=(systemd-run --user --scope --quiet -p "MemoryMax=$MEMORY_MAX" -p MemorySwapMax=0 nice -n 10)
  else
    log "warn: no systemd user manager (enable linger); running without a memory cap"
    SCOPE=(nice -n 10)
  fi
  ML_LOG=$(log_issue ml-engineer)
  PRINCIPAL_LOG=$(log_issue principal-engineer)
  if [[ -z $ML_LOG || -z $PRINCIPAL_LOG ]]; then
    [[ $DRY_RUN == 1 ]] || die "agent log issues missing; run scripts/agents/setup.sh"
    log "dry-run: agent log issues missing (run setup.sh before a real run)"
  fi
  log "agents from $AGENT_REF ($AGENT_REV), logs in $RUN_DIR"
}

prep_worktree() { # <name> → prints path; resets it to AGENT_BASE
  local wt=$WT_BASE-$1
  if [[ ! -e $wt ]]; then
    git -C "$REPO_ROOT" worktree add -q --detach "$wt" "$AGENT_BASE" >&2
  else
    git -C "$wt" reset -q --hard
    git -C "$wt" clean -qfd # untracked only; target/ and .venv survive
    git -C "$wt" checkout -q --detach "$AGENT_BASE"
  fi
  printf '%s\n' "$wt"
}

# ---------------------------------------------------------------- GitHub state
log_issue() { # <role>
  gh issue list -R "$REPO" --label "$L_LOG" --state open --json number,title \
    --jq ".[] | select(.title | contains(\"$1\")) | .number" | head -1
}

ml_prs() { # [label] → PR numbers authored by the ML agent
  local filter='select(.headRefName | startswith("'$ML_BRANCH_PREFIX'"))'
  [[ -n ${1:-} ]] && filter+=" | select([.labels[].name] | index(\"$1\"))"
  gh pr list -R "$REPO" --state open --limit 100 --json number,headRefName,labels \
    --jq "[.[] | $filter | .number] | sort | .[]"
}

pr_labels() { gh pr view "$1" -R "$REPO" --json labels --jq '.labels[].name'; }
pr_head() { gh pr view "$1" -R "$REPO" --json headRefOid --jq .headRefOid; }

pr_state() { # → one of STATE_LABELS, or empty
  local labels s
  labels=$(pr_labels "$1")
  for s in "$L_BEN" "$L_APPROVED" "$L_CHANGES" "$L_REVIEW"; do
    grep -qxF "$s" <<<"$labels" && { echo "$s"; return; }
  done
  return 0
}

set_state() { # <pr> <label>
  local pr=$1 want=$2 have s args=()
  have=$(pr_labels "$pr")
  for s in "${STATE_LABELS[@]}"; do
    [[ $s != "$want" ]] && grep -qxF "$s" <<<"$have" && args+=(--remove-label "$s")
  done
  grep -qxF "$want" <<<"$have" || args+=(--add-label "$want")
  ((${#args[@]})) || return 0
  log "#$pr → $want"
  ghw pr edit "$pr" -R "$REPO" "${args[@]}"
}

escalate() { # <pr> <reason>
  log "#$1 escalated: $2"
  set_state "$1" "$L_BEN"
  ghw pr comment "$1" -R "$REPO" --body "🤖 **orchestrator**: stopping the agent loop on this PR — $2. Remove \`$L_BEN\` to hand it back to the loop."
}

markers() { # <pr> → one `verdict=… sha=… [notes=N] [next=…]` line per principal review, oldest first
  gh api "repos/$REPO/pulls/$1/reviews" --paginate --jq '.[].body' |
    grep -oE '<!-- agent-review verdict=(approve|changes) sha=[0-9a-f]+( notes=[0-9]+)?( next=(restart|ben))? -->' |
    sed -E 's/<!-- agent-review (.*) -->/\1/' || true
}
reviews() { markers "$1" | grep -c . || true; }
# Rounds in the current cycle: a `next=restart` review closes a cycle, so
# only the reviews after the last one count.
rounds() { markers "$1" | awk '/next=restart/ { n = 0; next } { n++ } END { print n + 0 }'; }
restarts() { markers "$1" | grep -c 'next=restart' || true; }
last_marker() { markers "$1" | tail -1; }
marker_notes() { # <marker line> → its non-blocking note count (0 if absent)
  local n
  n=$(sed -nE 's/.* notes=([0-9]+).*/\1/p' <<<"$1")
  echo "${n:-0}"
}

# True when Ben (an unsigned comment, review or inline comment) has the last
# word on any open ML PR, so the ML agent has something to answer.
ml_has_feedback() {
  local pr
  for pr in $(ml_prs); do
    {
      gh api "repos/$REPO/issues/$pr/comments" --paginate \
        --jq '.[] | [.created_at, (.body | test("^\\s*🤖"))] | @tsv'
      gh api "repos/$REPO/pulls/$pr/reviews" --paginate \
        --jq '.[] | select(.body != "") | [.submitted_at, (.body | test("^(<!--[^\\n]*-->\\s*)?🤖"))] | @tsv'
      gh api "repos/$REPO/pulls/$pr/comments" --paginate \
        --jq '.[] | [.created_at, (.body | test("^\\s*🤖"))] | @tsv'
    } | sort | tail -1 | grep -q $'\tfalse$' && return 0
  done
  return 1
}

# Newly opened ML PRs join the loop; out-of-lane ones go straight to Ben.
adopt_new_prs() {
  local pr stray
  for pr in $(ml_prs); do
    grep -qxF "$L_ML" <<<"$(pr_labels "$pr")" && continue
    log "adopting #$pr"
    ghw pr edit "$pr" -R "$REPO" --add-label "$L_ML"
    stray=$(gh pr diff "$pr" -R "$REPO" --name-only | grep -vE "$ML_LANE" || true)
    if [[ -n $stray ]]; then
      escalate "$pr" "it changes files outside the ml-engineer lane: $(paste -sd, <<<"$stray")"
    else
      set_state "$pr" "$L_REVIEW"
    fi
  done
}

# A PR whose head moved past the last reviewed commit (Ben asked for a change
# and the author pushed it, say) goes back for review.
reconcile() {
  local pr state m
  for pr in $(ml_prs "$L_ML"); do
    state=$(pr_state "$pr")
    [[ $state == "$L_APPROVED" || $state == "$L_CHANGES" ]] || continue
    m=$(last_marker "$pr")
    [[ -n $m && ${m##*sha=} != "$(pr_head "$pr")" ]] && set_state "$pr" "$L_REVIEW"
  done
  return 0
}

# ---------------------------------------------------------------- agents
LAST_RESULT=
run_agent() { # <role> <worktree> <model> <budget> <task>
  local role=$1 wt=$2 model=$3 budget=$4 task=$5
  local out sys status=0
  out=$RUN_DIR/$(date +%H%M%S)-$role
  sys=$(cat "$AGENTS/rules.md" "$AGENTS/$role.md")
  printf '%s\n' "$task" >"$out.task"
  log "→ $role ($model): $(head -1 <<<"$task")"
  if [[ $DRY_RUN == 1 ]]; then
    LAST_RESULT="RESULT: noop"
    return
  fi
  # The devShell hook prints to stdout, so the transcript is parsed leniently
  # (`fromjson?`) below.
  #
  # No MCP at all. Left alone, a headless session loads Ben's whole MCP setup:
  # his plugins' servers and his claude.ai connectors (Gmail, Drive, Calendar,
  # Docs). That is far too much reach for an unattended agent in auto mode.
  # `--strict-mcp-config` with an empty config drops every server, connectors
  # included. The env var drops the connectors on its own as well, in case a
  # future CLI changes what "strict" covers.
  (cd "$wt" && "${SCOPE[@]}" nix develop "$wt" --command \
    env ENABLE_CLAUDEAI_MCP_SERVERS=false \
    timeout --kill-after=60 "$RUN_TIMEOUT" \
    claude -p "$task" \
    --append-system-prompt "$sys" \
    --model "$model" \
    --permission-mode "$PERMISSION_MODE" \
    --settings "$AGENTS/settings.json" \
    --strict-mcp-config --mcp-config '{"mcpServers":{}}' \
    --max-budget-usd "$budget" \
    --output-format stream-json --verbose) >"$out.jsonl" 2>"$out.stderr" || status=$?
  local mcp
  mcp=$(jq -rR 'fromjson? | select(.type == "system" and .subtype == "init") | [.mcp_servers[]?.name] | join(", ")' "$out.jsonl" 2>/dev/null | head -1)
  [[ -z $mcp ]] || log "WARN: $role session loaded MCP servers despite --strict-mcp-config: $mcp"
  LAST_RESULT=$(jq -rR 'fromjson? | select(.type == "result") | .result // empty' "$out.jsonl" 2>/dev/null |
    grep -E '^RESULT:' | tail -1 || true)
  local cost
  cost=$(jq -rR 'fromjson? | select(.type == "result") | .total_cost_usd // empty' "$out.jsonl" 2>/dev/null | tail -1)
  log "← $role exit=$status api-equiv=\$${cost:-?} ${LAST_RESULT:-<no RESULT line>}"
}

context() { # <role> → the shared preamble every task message starts with
  cat <<EOF
You are: $1
Agent log issues: ml-engineer #$ML_LOG, principal-engineer #$PRINCIPAL_LOG (yours is the $1 one).
Repository: $REPO. Your worktree is checked out at $AGENT_BASE ($(git -C "$REPO_ROOT" rev-parse --short "$AGENT_BASE")).
Today: $(date -u +%F). Review round cap: $MAX_ROUNDS.

Open PRs:
$(gh pr list -R "$REPO" --state open --limit 50 --json number,title,headRefName,labels \
    --jq '.[] | "  #\(.number) [\(.headRefName)] \(.title)  {\([.labels[].name] | join(", "))}"')

Open issues (agent logs excluded):
$(gh issue list -R "$REPO" --state open --limit 60 --json number,title,labels \
    --jq '.[] | select([.labels[].name] | index("'"$L_LOG"'") | not) | "  #\(.number) \(.title)  {\([.labels[].name] | join(", "))}"')
EOF
}

ml_respond() { # <pr>
  local wt
  wt=$(prep_worktree ml)
  run_agent ml-engineer "$wt" "$ML_MODEL" "$ML_BUDGET_USD" "Mode: respond $1
Check the branch out with \`gh pr checkout $1\`.

$(context ml-engineer)"
}

ml_notes() { # <pr> <final: 0|1>
  local wt how
  wt=$(prep_worktree ml)
  if (($2)); then
    how="final=yes — this was the last review round: do not push; file an issue or decline each note."
  else
    how="final=no — fix small in-scope notes on the branch and push; the principal reviews again."
  fi
  run_agent ml-engineer "$wt" "$ML_MODEL" "$ML_BUDGET_USD" "Mode: notes $1 $how
Check the branch out with \`gh pr checkout $1\`.

$(context ml-engineer)"
}

principal_review() { # <pr> <round> <restarts used>
  local wt
  wt=$(prep_worktree principal)
  run_agent principal-engineer "$wt" "$PRINCIPAL_MODEL" "$PRINCIPAL_BUDGET_USD" \
    "Mode: review $1 round=$2/$MAX_ROUNDS restarts=$3/$MAX_RESTARTS
Head commit to review: $(pr_head "$1"). Check it out with \`gh pr checkout $1\`.

$(context principal-engineer)"
}

# Drive one PR through review ⇄ response until it is approved, escalated or
# waiting on someone outside the loop. Bounded: every pass adds a review.
review_cycle() { # <pr>
  local pr=$1 state round total m final head used
  while :; do
    state=$(pr_state "$pr")
    case $state in
    "$L_REVIEW")
      round=$(($(rounds "$pr") + 1))
      ((round <= MAX_ROUNDS)) || { escalate "$pr" "it has had $MAX_ROUNDS review rounds"; return; }
      total=$(reviews "$pr")
      principal_review "$pr" "$round" "$(restarts "$pr")"
      [[ $DRY_RUN == 1 ]] && return
      (($(reviews "$pr") > total)) || { escalate "$pr" "the principal's run posted no verdict marker"; return; }
      m=$(last_marker "$pr")
      if [[ $m == verdict=approve* ]]; then
        # Approved, but with non-blocking notes: have the author act on them
        # now rather than a run later. A push re-enters review, until the
        # round cap; on the last round the author may only file or decline.
        if (($(marker_notes "$m") > 0)); then
          final=$((round >= MAX_ROUNDS))
          head=$(pr_head "$pr")
          ml_notes "$pr" "$final"
          if ((!final)) && [[ $(pr_head "$pr") != "$head" ]]; then
            set_state "$pr" "$L_REVIEW"
            continue
          fi
        fi
        set_state "$pr" "$L_APPROVED"
        return
      fi
      # Changes still required on the last round: a 4th round is the
      # principal's call. It either restarts the cycle (rounds reset, with a
      # brief for the author) or hands the PR to Ben. Saying neither means Ben.
      if ((round >= MAX_ROUNDS)); then
        used=$(restarts "$pr")
        if [[ $m == *next=restart* ]] && ((used <= MAX_RESTARTS)); then
          log "#$pr: principal restarted the review cycle ($used/$MAX_RESTARTS)"
          ghw pr comment "$pr" -R "$REPO" --body "🤖 **orchestrator**: the principal restarted the review cycle (restart $used of $MAX_RESTARTS). The round count resets; its latest review is the brief."
        elif [[ $m == *next=restart* ]]; then
          escalate "$pr" "the principal asked to restart again, but all $MAX_RESTARTS restart(s) are used, so Ben decides"
          return
        else
          escalate "$pr" "the principal handed it to Ben after $MAX_ROUNDS rounds. Its latest review says what needs deciding"
          return
        fi
      fi
      set_state "$pr" "$L_CHANGES"
      ;;
    "$L_CHANGES")
      ml_respond "$pr"
      [[ $DRY_RUN == 1 ]] && return
      [[ $LAST_RESULT == "RESULT: blocked"* ]] && { escalate "$pr" "the author is blocked (${LAST_RESULT#RESULT: blocked })"; return; }
      set_state "$pr" "$L_REVIEW"
      ;;
    *) return ;;
    esac
  done
}

fix_first() { # <pr>… → the same PRs, bug fixes (title `fix…`) first
  local pr
  for pr in "$@"; do
    gh pr view "$pr" -R "$REPO" --json number,title --jq '"\(if (.title | test("^fix")) then 0 else 1 end) \(.number)"'
  done | sort -n -k1,1 -k2,2 | cut -d' ' -f2
}

review_all() {
  reconcile
  local pr
  # shellcheck disable=SC2046  # PR numbers: word-splitting is intended
  for pr in $(fix_first $(ml_prs "$L_CHANGES") $(ml_prs "$L_REVIEW")); do review_cycle "$pr"; done
}

# ---------------------------------------------------------------- commands
cmd_status() {
  local pr m
  for pr in $(ml_prs); do
    m=$(last_marker "$pr")
    printf '#%-5s %-26s rounds=%s restarts=%s last=%s\n' "$pr" "$(pr_state "$pr")" "$(rounds "$pr")" "$(restarts "$pr")" "${m:-none}"
  done
}

cmd_ml() {
  # Reviews already waiting on the author come first, so they don't go stale.
  review_all
  local open wt
  open=$(ml_prs | grep -c . || true)
  # Hourly runs: at the WIP limit with nothing of Ben's to answer, a session
  # could only conclude `noop`, so don't start one.
  if ((open >= ML_WIP_LIMIT)) && ! ml_has_feedback; then
    log "at the WIP limit ($open/$ML_WIP_LIMIT) with no unanswered feedback; nothing to do"
    return
  fi
  wt=$(prep_worktree ml)
  run_agent ml-engineer "$wt" "$ML_MODEL" "$ML_BUDGET_USD" "Mode: work
Open-PR limit: you have $open open of $ML_WIP_LIMIT allowed$( ((open >= ML_WIP_LIMIT)) && echo ' — AT LIMIT, start nothing new').

$(context ml-engineer)"
  [[ $DRY_RUN == 1 ]] && return
  adopt_new_prs
  review_all
}

cmd_sweep() {
  local wt
  wt=$(prep_worktree principal)
  run_agent principal-engineer "$wt" "$PRINCIPAL_MODEL" "$PRINCIPAL_BUDGET_USD" "Mode: sweep

$(context principal-engineer)"
}

[[ $cmd == status ]] && { cmd_status; exit 0; }

if [[ -z $LOCK_WAIT_S ]]; then
  [[ $cmd == sweep ]] && LOCK_WAIT_S=14400 || LOCK_WAIT_S=0
fi
exec 9>"$AGENT_HOME/lock"
flock -w "$LOCK_WAIT_S" 9 || { log "another run still holds the lock after ${LOCK_WAIT_S}s; skipping"; exit 0; }
preflight
case $cmd in
ml) cmd_ml ;;
review) review_all ;;
sweep) cmd_sweep ;;
esac
log "done"
