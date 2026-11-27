# Agent team

This directory runs wayfinder's autonomous agents headlessly on Ben's server
using `claude -p`, scheduled by systemd user timers. Four roles are live:

| Role | Prompt | Lane | Model |
|---|---|---|---|
| AI/ML + simulation engineer (all sim: adversarial, characterisation, modelling) | [`ml-engineer.md`](ml-engineer.md) | `sim/` (except `red_team.py`), `ml/`, proposed design docs | Sonnet |
| Security engineer | [`security-engineer.md`](security-engineer.md) | `libs/wayfinder-auth`, `libs/wayfinder-linksec`, the router's `libs/wayfinder/src/auth/`, `sim/scenarios/red_team.py` | Sonnet |
| Routing engineer (the routing core only) | [`routing-engineer.md`](routing-engineer.md) | `libs/batman`, `libs/wayfinder` (except `src/auth/`), `libs/interfaces`, `libs/wayfinder-test` | Sonnet |
| Principal engineer | [`principal-engineer.md`](principal-engineer.md) | reviews everything; writes no code | Opus |

- Every prompt is [`rules.md`](rules.md), then (for authors)
  [`author.md`](author.md), the run modes they share, then the role file.
- [`roadmap.md`](roadmap.md) is the backlog. Edit it to steer the team.
- The firmware role is listed at the bottom of the roadmap and is not running
  yet.
- Roles are declared in one table at the top of `run-loop.sh`: name, model,
  budget, lane and exclusions.

**Ben's sign-off, on top of the principal's approval,** is required by the
orchestrator (`needs-ben` alongside `agent::approved`) for any PR that:

- touches keys, credentials or the wire (`wayfinder-auth`, `wayfinder-linksec`,
  `wayfinder-tls-mgmt`, `wayfinder-protos`, the router's `auth/`), whoever
  wrote it, which means every security PR; or
- changes files outside its author's lane.

Such a PR is still reviewed through the full loop first, so it reaches Ben in
its best state.

## The loop

```
run-loop.sh work <role>                          (hourly per role, staggered)
  1. review loop over every agent PR already waiting
  2. at the WIP limit with nothing of Ben's to answer → stop, no session started
  3. the role's "work" run: answer Ben's comments, else fix an in-lane bug,
     else take one backlog task → PR on agent/<role>/…
  4. new agent/* PRs get their role label and needs-review
  5. review loop, per PR, all in this one run:
       needs-review ─principal→ approve, notes=0 ──────────→ approved (Ben's turn)
                              → approve, notes>0 ─author fixes─→ needs-review …
                                                 └author files/declines only─→ approved
                              → changes ─────────author responds→ needs-review …
       approved + (keys/wire or out-of-lane files) → also needs-ben
       round 3 still with changes → the principal decides on a 4th round:
           next=restart → rounds reset, its review is the brief (MAX_RESTARTS=1)
           next=ben     → needs-ben, with what Ben has to decide
       on the last round, notes are filed or declined, never pushed
run-loop.sh sweep    principal comments on whatever the loop missed (daily)
run-loop.sh review   steps 4 and 5 only
run-loop.sh status   agent PRs with author, state and round count
run-loop.sh ml       alias for `work ml`
```

A PR therefore leaves the loop only once every review point has been answered,
either by a fix or by an issue or a decline, and never waits for the next
scheduled run. The principal counts its non-blocking notes in its marker
(`notes=N`), and is told to count only notes worth another round, so that
approval with notes does not turn into a round of nits.

**All state lives in GitHub labels and review markers.** Nothing is kept on
disk, so a crashed or killed run loses nothing, and the next run picks up
where it stopped.

**`needs-ben` is the off switch for a PR.** Remove the label and the PR goes
back into the loop.

The script owns every label. The agents own only content: code, comments and
reviews.

### Why the principal's "approval" is only a comment

Both agents run as `benj2468`. GitHub does not let an account approve, or
request changes on, its own PR, so the principal posts a comment review whose
first line is `<!-- agent-review verdict=approve|changes sha=… notes=N -->`,
and the script reads the verdict from that line.

Merging is gated twice:

- CODEOWNERS plus branch protection require Ben's approval.
- The agents' settings deny `gh pr merge`, pushes to `main`, force pushes and
  label edits.

## Safety rails

| Risk | Rail |
|---|---|
| An agent edits its own rules | Prompts and this script are run from `origin/main`, staged by `git archive`, never from a working tree. `scripts/agents/**` is also edit-denied. |
| Merge, force-push, closing things | `settings.json` deny rules, plus `--permission-mode auto` for everything else |
| Reach beyond the repo (Gmail, Drive, Calendar, browser) | Sessions load **no MCP servers**: `--strict-mcp-config` with an empty config, plus `ENABLE_CLAUDEAI_MCP_SERVERS=false`. Without them a headless session inherits Ben's claude.ai connectors and plugin MCP servers. `loop.log` warns if any server loads anyway. |
| OOM on a 7.7 GB, no-swap box | Each `claude` runs in a `systemd-run --user --scope` capped at `MEMORY_MAX` (4.5 GB), at `nice 10` and `CARGO_BUILD_JOBS=2` |
| Disk | Preflight refuses to start with less than `MIN_FREE_GB` (6 GB) free. Each agent reuses one persistent worktree (`~/sources/wt-agent-{ml,security,routing,principal}`), so `target/` and `.venv` are built once. |
| A runaway session | `RUN_TIMEOUT` (90 min) and `--max-budget-usd` on each invocation |
| Overlapping runs | `flock`. An hourly ML run that finds the lock taken just skips (the next hour retries), and a sweep waits up to 4 h. |
| Hourly sessions with nothing to do | At the WIP limit, with no unanswered comment of Ben's, `ml` ends before starting a session. |
| A review loop that never converges | Three rounds per cycle. After the third, the principal must either restart the cycle (at most `MAX_RESTARTS`, default 1) or hand the PR to Ben. It is told not to raise new nits on code it has already accepted. |
| PR churn spending Actions minutes | Open-PR limit per role (`WIP_LIMIT=2`). Agents open PRs only when they are merge-ready. |

Every knob is an environment variable at the top of [`run-loop.sh`](run-loop.sh).

## Setup (once)

```bash
scripts/agents/setup.sh            # labels + one agent-log issue per role (idempotent)
loginctl enable-linger "$USER"     # a user manager with nobody logged in (timers + the memory cap)
```

Before this directory is on `main`, try it from the branch:

```bash
AGENT_REF=HEAD DRY_RUN=1 scripts/agents/run-loop.sh work security   # prints what it would do
AGENT_REF=HEAD scripts/agents/run-loop.sh status
```

## Scheduling

Each authoring role runs hourly, staggered so they rarely meet: `ml` at :00,
`security` at :20 and `routing` at :40. `sweep` runs daily at 23:30. On Ben's NixOS server
(`gantz`) these are systemd **user timers** declared in
`~/nixconf/host/gantz/default.nix`, with linger on.

- Runs share one lock. An authoring run that finds it taken skips, and its
  next hourly slot retries.

- `Persistent=true` runs a slot that was missed while the VM slept, once it
  wakes.
- A timer never starts a second copy of a still-running oneshot.
- Output goes to `journalctl --user -u wayfinder-agents-<ml|security|routing|sweep>`.
- To pause one role: `systemctl --user stop wayfinder-agents-security.timer`.

```bash
systemctl --user list-timers 'wayfinder-agents-*'
systemctl --user start wayfinder-agents-ml     # run one now
```

On a host without that config, use cron instead:

```cron
0 * * * *   $HOME/sources/wayfinder/scripts/agents/run-loop.sh work ml       >>$HOME/.local/state/wayfinder-agents/cron.log 2>&1
20 * * * *  $HOME/sources/wayfinder/scripts/agents/run-loop.sh work security >>$HOME/.local/state/wayfinder-agents/cron.log 2>&1
40 * * * *  $HOME/sources/wayfinder/scripts/agents/run-loop.sh work routing  >>$HOME/.local/state/wayfinder-agents/cron.log 2>&1
30 23 * * * $HOME/sources/wayfinder/scripts/agents/run-loop.sh sweep >>$HOME/.local/state/wayfinder-agents/cron.log 2>&1
```

The scheduled path only has to locate *a* checkout. The script fetches and re-execs
the `origin/main` copy of itself, so whatever branch the checkout happens to be
on does not matter. Each agent then starts inside `nix develop`, entered in its
own worktree. That gives it the flake's `cargo`, `uv`, `just` and `nix fmt`
rather than the scheduler's bare `PATH`, and the shell hook syncs that worktree's `.venv`
with the `dev` and `sim` groups.

## Logs

`~/.local/state/wayfinder-agents/runs/<date>/<time>-<cmd>/` holds:

- `loop.log`: the orchestrator's decisions and each run's API-equivalent cost;
- `*.task`: the exact task message sent;
- `*.jsonl`: the full stream-json transcript;
- `*.stderr`.

On GitHub, every run also leaves a Done/Next/Blocked comment on its agent's
`agent-log` issue.

## Billing: check before turning cron on

The runs authenticate with the claude.ai subscription (`apiKeySource: none`),
not an API key. The `$` figure in `loop.log` is Claude Code's API-equivalent
estimate (`total_cost_usd`), not a charge.

Whether headless `claude -p` draws from the plan's normal limits or from a
separate monthly credit was announced to change on 2026-06-15, and reports say
the change was later paused. The usage page in claude.ai settings is the
authority: check it after a run. `--max-budget-usd` caps each invocation's
estimate either way.

## Adding a role

1. Write `<name>.md`: lane, backlog, and domain rules. The run modes come
   from `author.md`.
2. Add its key to `AUTHORS` in `run-loop.sh`, with its `NAME`, `MODEL`,
   `BUDGET`, `LANE` and `EXCLUDE`. If it takes files from another lane, add
   them to that role's `EXCLUDE`.
3. Add its `agent::<key>` label and its log issue to `setup.sh`, and run it.
4. Give it a backlog section in `roadmap.md`.
5. Add a staggered hourly timer for `run-loop.sh work <key>`.
