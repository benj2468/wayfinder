#!/usr/bin/env bash
# Orchestrates wayfinder's agent team on this machine.
#
#   run-loop.sh work <role>  one authoring run for <role> (ml, security, routing): the
#                            review loop, then that role's work run, then the
#                            review loop again (`ml` is an alias for `work ml`)
#   run-loop.sh review       only the review loop, over every agent PR
#   run-loop.sh sweep        the principal engineer's daily sweep
#   run-loop.sh status       agent PRs and their loop state; changes nothing
#
# The script owns all orchestration state, and that state lives on GitHub, so
# every run is stateless and a crash loses nothing:
#   agent::<role>              PR authored by that role (branch agent/<role>/*)
#   agent::needs-review        waiting for the principal
#   agent::changes-requested   waiting for the author
#   agent::approved            principal is satisfied; waiting for Ben
#   needs-ben                  loop stopped, or Ben must look before merge
#                              (round cap, out of lane, keys/wire, failure).
#                              Remove it to hand the PR back to the loop.
# A review round is one principal review carrying an `<!-- agent-review … -->`
# marker. GitHub cannot record a real verdict, because every agent runs as
# Ben's account, so the marker carries it.
#
# The prompts and this script are run from AGENT_REF (default origin/main),
# never from a working tree: an agent cannot change its own rules until Ben
# merges the change. Set AGENT_REF=HEAD to try a local commit first.
#
# See scripts/agents/README.md for setup and scheduling.
set -euo pipefail

# ---------------------------------------------------------------- config
: "${REPO:=benj2468/wayfinder}"
: "${AGENT_REF:=origin/main}"           # where prompts + this script come from
: "${AGENT_BASE:=origin/main}"          # what agent worktrees start from
: "${AGENT_HOME:=$HOME/.local/state/wayfinder-agents}"
: "${WT_BASE:=$HOME/sources/wt-agent}"  # → wt-agent-<role>, wt-agent-principal
: "${PRINCIPAL_MODEL:=opus}"            # CLAUDE.md: Opus reviews
: "${PRINCIPAL_BUDGET_USD:=10}"         # per claude invocation
: "${RUN_TIMEOUT:=90m}"                 # per claude invocation
: "${MAX_ROUNDS:=3}"                    # review rounds per cycle
: "${MAX_RESTARTS:=1}"                  # cycles the principal may restart before Ben must decide
: "${WIP_LIMIT:=2}"                     # open PRs per authoring role before it stops starting work
: "${PERMISSION_MODE:=auto}"
: "${MEMORY_MAX:=4500M}"                # cgroup cap so cargo can't OOM the box
: "${MIN_FREE_GB:=6}"
: "${LOCK_WAIT_S:=}"                    # default: work/review 0 (next hour retries), sweep 4 h
: "${DRY_RUN:=0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

# ---------------------------------------------------------------- roles
# Authoring roles. Each has its prompt `<name>.md`, its label `agent::<key>`,
# its branches `agent/<key>/*`, its worktree `$WT_BASE-<key>`, and its log
# issue titled "Agent log: <name>".
#
# A lane is what a role may change without Ben's explicit sign-off, as an
# extended regex over repo paths. A path counts as in a role's lane when it
# matches LANE and not EXCLUDE (ERE has no negative lookahead). A PR with files
# outside its lane is still reviewed, but ends at needs-ben with those files
# listed.
AUTHORS=(ml security routing)
declare -A NAME=([ml]=ml-engineer [security]=security-engineer [routing]=routing-engineer)
declare -A MODEL=([ml]="${ML_MODEL:-sonnet}" [security]="${SECURITY_MODEL:-sonnet}" [routing]="${ROUTING_MODEL:-sonnet}")
declare -A BUDGET=([ml]="${ML_BUDGET_USD:-15}" [security]="${SECURITY_BUDGET_USD:-15}" [routing]="${ROUTING_BUDGET_USD:-15}")
# The router's credential plane (libs/wayfinder/src/auth/ and the fuzz target
# that drives it) sits inside the routing core's crate but is the security
# engineer's: it is keys and the wire, not path selection.
ROUTER_AUTH='^(libs/wayfinder/src/auth/|libs/wayfinder/fuzz/fuzz_targets/verify_ogm\.rs$)'
declare -A LANE=(
  [ml]='^(sim/|ml/|uv\.lock$|docs/design/[0-9]{2}-[^/]+\.md$)'
  [security]='^(libs/wayfinder-auth/|libs/wayfinder-linksec/|libs/wayfinder/src/auth/|libs/wayfinder/fuzz/fuzz_targets/verify_ogm\.rs$|sim/scenarios/red_team\.py$|docs/design/[0-9]{2}-[^/]+\.md$|Cargo\.lock$)'
  [routing]='^(libs/batman/|libs/wayfinder/|libs/interfaces/|libs/wayfinder-test/|docs/design/[0-9]{2}-[^/]+\.md$|Cargo\.lock$)'
)
declare -A EXCLUDE=(
  [ml]='^sim/scenarios/red_team\.py$' # the security engineer's
  [security]='^$'
  [routing]=$ROUTER_AUTH # the security engineer's
)
# Keys, credentials and the wire: whoever touches these, Ben reviews before
# merge even after the principal approves (needs-ben on top of approved).
SENSITIVE='^(libs/wayfinder-auth/|libs/wayfinder-linksec/|libs/wayfinder-tls-mgmt/|libs/wayfinder-protos/|libs/wayfinder/src/auth/)'

L_REVIEW=agent::needs-review
L_CHANGES=agent::changes-requested
L_APPROVED=agent::approved
L_BEN=needs-ben
L_LOG=agent-log
STATE_LABELS=("$L_REVIEW" "$L_CHANGES" "$L_APPROVED" "$L_BEN")

cmd=${1:-}
role=
case $cmd in
ml) cmd=work role=ml ;;
work)
  role=${2:-}
  [[ -n $role && -n ${NAME[$role]:-} ]] || { echo "usage: run-loop.sh work <${AUTHORS[*]}>" >&2; exit 2; }
  ;;
review | sweep | status) ;;
*)
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
  ;;
esac

# Cron and systemd give a bare environment.
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
  # One staging dir per command, so a starting run can't delete the files of
  # one still running (staggered units overlap while one waits on the lock).
  stage=$AGENT_HOME/staged-${cmd}${role:+-$role}
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

RUN_DIR=$AGENT_HOME/runs/$(date +%F)/$(date +%H%M%S)-${cmd}${role:+-$role}
mkdir -p "$RUN_DIR"
log() { printf '%s [%s] %s\n' "$(date -Is)" "${cmd}${role:+ $role}" "$*" | tee -a "$RUN_DIR/loop.log" >&2; }
die() { log "FATAL: $*"; exit 1; }

# Every GitHub write goes through here, so DRY_RUN is honest.
ghw() {
  if [[ $DRY_RUN == 1 ]]; then log "dry-run: gh $*"; else gh "$@" >/dev/null; fi
}

# ---------------------------------------------------------------- preflight
declare -A LOGS=()
preflight() {
  command -v claude >/dev/null || die "claude not on PATH"
  gh auth status >/dev/null 2>&1 || die "gh is not authenticated"
  local free_gb r name missing=()
  free_gb=$(df -BG --output=avail "$(dirname "$WT_BASE")" | tail -1 | tr -dc 0-9)
  ((free_gb >= MIN_FREE_GB)) || die "only ${free_gb}G free (< ${MIN_FREE_GB}G); run 'just clean' in a worktree"
  if systemd-run --user --scope --quiet true 2>/dev/null; then
    SCOPE=(systemd-run --user --scope --quiet -p "MemoryMax=$MEMORY_MAX" -p MemorySwapMax=0 nice -n 10)
  else
    log "warn: no systemd user manager (enable linger); running without a memory cap"
    SCOPE=(nice -n 10)
  fi
  for name in principal-engineer $(for r in "${AUTHORS[@]}"; do echo "${NAME[$r]}"; done); do
    LOGS[$name]=$(log_issue "$name")
    [[ -n ${LOGS[$name]} ]] || missing+=("$name")
  done
  if ((${#missing[@]})); then
    [[ $DRY_RUN == 1 ]] || die "agent log issues missing for ${missing[*]}; run scripts/agents/setup.sh"
    log "dry-run: log issues missing for ${missing[*]} (run setup.sh before a real run)"
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
log_issue() { # <role name>
  gh issue list -R "$REPO" --label "$L_LOG" --state open --json number,title \
    --jq ".[] | select(.title == \"Agent log: $1\") | .number" | head -1
}

role_prs() { # <role|all> [label] → open PR numbers authored by that role
  local prefix filter
  if [[ $1 == all ]]; then prefix=agent/; else prefix=agent/$1/; fi
  filter='select(.headRefName | startswith("'$prefix'"))'
  [[ -n ${2:-} ]] && filter+=" | select([.labels[].name] | index(\"$2\"))"
  gh pr list -R "$REPO" --state open --limit 100 --json number,headRefName,labels \
    --jq "[.[] | $filter | .number] | sort | .[]"
}

author_of() { # <pr> → role key, from the branch prefix
  local r branch
  branch=$(gh pr view "$1" -R "$REPO" --json headRefName --jq .headRefName)
  for r in "${AUTHORS[@]}"; do
    [[ $branch == agent/$r/* ]] && { echo "$r"; return; }
  done
  return 0
}

pr_labels() { gh pr view "$1" -R "$REPO" --json labels --jq '.labels[].name'; }
pr_head() { gh pr view "$1" -R "$REPO" --json headRefOid --jq .headRefOid; }
pr_files() { gh pr diff "$1" -R "$REPO" --name-only; }

# GitHub's PR reads lag its writes by seconds: a label set here can be
# missing from a `gh pr list` or `gh pr view` issued right after. This script
# is the only writer of state labels during a run, so the states it set are
# cached and believed over GitHub's answer.
declare -A STATE=()

pr_state() { # → one of STATE_LABELS, or empty
  local labels s
  [[ -n ${STATE[$1]+x} ]] && { echo "${STATE[$1]}"; return; }
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
  STATE[$pr]=$want
  ((${#args[@]})) || return 0
  log "#$pr → $want"
  ghw pr edit "$pr" -R "$REPO" "${args[@]}"
}

escalate() { # <pr> <reason>: stop the loop on this PR
  log "#$1 escalated: $2"
  set_state "$1" "$L_BEN"
  ghw pr comment "$1" -R "$REPO" --body "🤖 **orchestrator**: stopping the agent loop on this PR: $2. Remove \`$L_BEN\` to hand it back to the loop."
}

flag_ben() { # <pr> <reason>: approved, but Ben must look before merging
  log "#$1 flagged for Ben: $2"
  set_state "$1" "$L_APPROVED"
  ghw pr edit "$1" -R "$REPO" --add-label "$L_BEN"
  STATE[$1]=$L_BEN
  ghw pr comment "$1" -R "$REPO" --body "🤖 **orchestrator**: the principal approved this, but it needs Ben's review before merging: $2."
}

out_of_lane() { # <pr> <role> → files outside that role's lane, one per line
  pr_files "$1" | grep -vE "${LANE[$2]}" || true
  pr_files "$1" | grep -E "${LANE[$2]}" | grep -E "${EXCLUDE[$2]}" || true
}

markers() { # <pr> → one `verdict=… sha=… [notes=N] [next=…]` line per principal review, oldest first
  gh api "repos/$REPO/pulls/$1/reviews" --paginate --jq '.[].body' |
    grep -oE '<!-- agent-review verdict=(approve|changes) sha=[0-9a-f]+( notes=[0-9]+)?( next=(restart|ben))? -->' |
    sed -E 's/<!-- agent-review (.*) -->/\1/' || true
}
reviews() { markers "$1" | grep -c . || true; }
# When Ben last removed needs-ben (empty if never). The script never removes
# that label itself, so every such event is Ben handing the PR back.
handback_at() { # <pr> → ISO timestamp
  gh api "repos/$REPO/issues/$1/timeline" --paginate \
    --jq ".[] | select(.event == \"unlabeled\" and .label.name == \"$L_BEN\") | .created_at" |
    tail -1 || true
}
# Markers since Ben's last hand-back: removing needs-ben starts a fresh
# budget of rounds and restarts, or a PR stopped by the round cap would be
# escalated again on the very next pass and the hand-back would do nothing.
cycle_markers() { # <pr>
  local since
  since=$(handback_at "$1")
  gh api "repos/$REPO/pulls/$1/reviews" --paginate \
    --jq ".[] | select(.submitted_at > \"$since\") | .body" |
    grep -oE '<!-- agent-review verdict=(approve|changes) sha=[0-9a-f]+( notes=[0-9]+)?( next=(restart|ben))? -->' |
    sed -E 's/<!-- agent-review (.*) -->/\1/' || true
}
# Rounds in the current cycle: a `next=restart` review closes a cycle, so
# only the reviews after the last one count.
rounds() { cycle_markers "$1" | awk '/next=restart/ { n = 0; next } { n++ } END { print n + 0 }'; }
restarts() { cycle_markers "$1" | grep -c 'next=restart' || true; }
last_marker() { markers "$1" | tail -1; }
# Only the sha: the marker goes on to `notes=` and `next=`, so a suffix strip
# like `${m##*sha=}` would never equal the head and re-queues every approval.
marker_sha() { sed -nE 's/.*sha=([0-9a-f]+).*/\1/p' <<<"$1"; }
marker_notes() { # <marker line> → its non-blocking note count (0 if absent)
  local n
  n=$(sed -nE 's/.* notes=([0-9]+).*/\1/p' <<<"$1")
  echo "${n:-0}"
}

# True when Ben (an unsigned comment, review or inline comment) has the last
# word on any open PR of <role>, so that role has something to answer.
has_feedback() { # <role>
  local pr
  for pr in $(role_prs "$1"); do
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

# Newly opened agent PRs join the loop.
adopt_new_prs() {
  local pr r
  for pr in $(role_prs all); do
    r=$(author_of "$pr")
    [[ -n $r ]] || continue
    grep -qxF "agent::$r" <<<"$(pr_labels "$pr")" && continue
    log "adopting #$pr (${NAME[$r]})"
    ghw pr edit "$pr" -R "$REPO" --add-label "agent::$r"
    set_state "$pr" "$L_REVIEW"
  done
}

# Put every agent PR back where the loop can see it:
#  - no state label (Ben removed needs-ben after an escalation) → review;
#  - approved or changes-requested, but the head moved past the last reviewed
#    commit (Ben asked for a change and the author pushed it) → review.
reconcile() {
  local pr state m
  for pr in $(role_prs all); do
    [[ -n $(author_of "$pr") ]] || continue
    state=$(pr_state "$pr")
    if [[ -z $state ]]; then
      grep -q '^agent::' <<<"$(pr_labels "$pr")" && set_state "$pr" "$L_REVIEW"
      continue
    fi
    [[ $state == "$L_APPROVED" || $state == "$L_CHANGES" ]] || continue
    m=$(last_marker "$pr")
    [[ -n $m && $(marker_sha "$m") != "$(pr_head "$pr")" ]] && set_state "$pr" "$L_REVIEW"
  done
  return 0
}

# ---------------------------------------------------------------- agents
LAST_RESULT=
run_agent() { # <role name> <worktree> <model> <budget> <task> [extra prompt file]
  local name=$1 wt=$2 model=$3 budget=$4 task=$5 extra=${6:-}
  local out sys status=0
  out=$RUN_DIR/$(date +%H%M%S)-$name
  sys=$(cat "$AGENTS/rules.md" ${extra:+"$AGENTS/$extra"} "$AGENTS/$name.md")
  printf '%s\n' "$task" >"$out.task"
  log "→ $name ($model): $(head -1 <<<"$task")"
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
  local mcp cost
  mcp=$(jq -rR 'fromjson? | select(.type == "system" and .subtype == "init") | [.mcp_servers[]?.name] | join(", ")' "$out.jsonl" 2>/dev/null | head -1)
  [[ -z $mcp ]] || log "WARN: $name session loaded MCP servers despite --strict-mcp-config: $mcp"
  LAST_RESULT=$(jq -rR 'fromjson? | select(.type == "result") | .result // empty' "$out.jsonl" 2>/dev/null |
    grep -E '^RESULT:' | tail -1 || true)
  cost=$(jq -rR 'fromjson? | select(.type == "result") | .total_cost_usd // empty' "$out.jsonl" 2>/dev/null | tail -1)
  log "← $name exit=$status api-equiv=\$${cost:-?} ${LAST_RESULT:-<no RESULT line>}"
}

context() { # <role name> → the shared preamble every task message starts with
  local n logs=""
  for n in "${!LOGS[@]}"; do logs+="$n #${LOGS[$n]}, "; done
  cat <<EOF
You are: $1
Agent log issues: ${logs%, } (yours is the $1 one).
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

author_run() { # <role> <task first line> → runs that role's author session
  local r=$1 wt
  wt=$(prep_worktree "$r")
  run_agent "${NAME[$r]}" "$wt" "${MODEL[$r]}" "${BUDGET[$r]}" "$2

$(context "${NAME[$r]}")" author.md
}

author_respond() { # <pr> <role>
  author_run "$2" "Mode: respond $1
Check the branch out with \`gh pr checkout $1\`."
}

author_notes() { # <pr> <role> <final: 0|1>
  local how
  if (($3)); then
    how="final=yes. This was the last review round: do not push; file an issue or decline each note."
  else
    how="final=no. Fix small in-scope notes on the branch and push; the principal reviews again."
  fi
  author_run "$2" "Mode: notes $1 $how
Check the branch out with \`gh pr checkout $1\`."
}

principal_review() { # <pr> <round> <restarts used> <author role>
  local wt lane_note="" stray sensitive
  wt=$(prep_worktree principal)
  stray=$(out_of_lane "$1" "$4")
  sensitive=$(pr_files "$1" | grep -E "$SENSITIVE" || true)
  [[ -z $stray ]] || lane_note+="
Files outside the ${NAME[$4]} lane (Ben signs off on these regardless; judge whether each is justified by an accepted design doc or the task):
  ${stray//$'\n'/$'\n'  }"
  [[ -z $sensitive ]] || lane_note+="
This PR touches keys, credentials or the wire. Use the full \`mr-review\` skill, and review it as security-sensitive."
  run_agent principal-engineer "$wt" "$PRINCIPAL_MODEL" "$PRINCIPAL_BUDGET_USD" \
    "Mode: review $1 round=$2/$MAX_ROUNDS restarts=$3/$MAX_RESTARTS
Author: ${NAME[$4]}. Head commit to review: $(pr_head "$1"). Check it out with \`gh pr checkout $1\`.$lane_note

$(context principal-engineer)"
}

# After the principal approves: does Ben have to look before merging anyway?
gate_for_ben() { # <pr> <role> → reason, or empty
  local stray sensitive reason=""
  stray=$(out_of_lane "$1" "$2")
  sensitive=$(pr_files "$1" | grep -E "$SENSITIVE" || true)
  [[ -z $stray ]] || reason+="it changes files outside the ${NAME[$2]} lane ($(paste -sd, <<<"$stray")); "
  [[ -z $sensitive ]] || reason+="it touches keys, credentials or the wire ($(paste -sd, <<<"$sensitive")); "
  printf '%s' "${reason%; }"
}

# Drive one PR through review ⇄ response until it is approved, escalated or
# waiting on someone outside the loop. Bounded: every pass adds a review.
review_cycle() { # <pr>
  local pr=$1 r state round total m final head used why
  r=$(author_of "$pr")
  [[ -n $r ]] || return 0
  while :; do
    state=$(pr_state "$pr")
    case $state in
    "$L_REVIEW")
      round=$(($(rounds "$pr") + 1))
      ((round <= MAX_ROUNDS)) || { escalate "$pr" "it has had $MAX_ROUNDS review rounds"; return; }
      total=$(reviews "$pr")
      principal_review "$pr" "$round" "$(restarts "$pr")" "$r"
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
          author_notes "$pr" "$r" "$final"
          if ((!final)) && [[ $(pr_head "$pr") != "$head" ]]; then
            set_state "$pr" "$L_REVIEW"
            continue
          fi
        fi
        why=$(gate_for_ben "$pr" "$r")
        if [[ -n $why ]]; then flag_ben "$pr" "$why"; else set_state "$pr" "$L_APPROVED"; fi
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
      author_respond "$pr" "$r"
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
  adopt_new_prs
  reconcile
  local pr
  # Every agent PR, not a label search: the search would lag the labels that
  # adopt/reconcile just set. review_cycle skips the ones not waiting.
  # shellcheck disable=SC2046  # PR numbers: word-splitting is intended
  for pr in $(fix_first $(role_prs all)); do review_cycle "$pr"; done
}

# ---------------------------------------------------------------- commands
cmd_status() {
  local pr m r
  for pr in $(role_prs all); do
    r=$(author_of "$pr")
    m=$(last_marker "$pr")
    printf '#%-5s %-18s %-26s rounds=%s restarts=%s last=%s\n' "$pr" "${NAME[$r]:-?}" \
      "$(pr_labels "$pr" | grep -xF "$L_BEN" || pr_state "$pr")" "$(rounds "$pr")" "$(restarts "$pr")" "${m:-none}"
  done
}

cmd_work() { # <role>
  local r=$1 open
  # Reviews already waiting come first, so they don't go stale.
  review_all
  open=$(role_prs "$r" | grep -c . || true)
  # Hourly runs: at the WIP limit with nothing of Ben's to answer, a session
  # could only conclude `noop`, so don't start one.
  if ((open >= WIP_LIMIT)) && ! has_feedback "$r"; then
    log "${NAME[$r]} is at the WIP limit ($open/$WIP_LIMIT) with no unanswered feedback; nothing to do"
    return
  fi
  author_run "$r" "Mode: work
Open-PR limit: you have $open open of $WIP_LIMIT allowed$( ((open >= WIP_LIMIT)) && echo '. AT LIMIT: start nothing new').
Your branch prefix: agent/$r/"
  [[ $DRY_RUN == 1 ]] && return
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
work) cmd_work "$role" ;;
review) review_all ;;
sweep) cmd_sweep ;;
esac
log "done"
