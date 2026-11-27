# Agent team

This directory runs wayfinder's autonomous agents headlessly on Ben's server
using `claude -p`, scheduled by cron. Two roles are live:

| Role | Prompt | Lane | Model |
|---|---|---|---|
| AI/ML + simulation engineer (all sim: adversarial, characterisation, modelling) | [`ml-engineer.md`](ml-engineer.md) | `sim/`, `ml/`, proposed design docs | Sonnet |
| Principal engineer | [`principal-engineer.md`](principal-engineer.md) | reviews everything; writes no code | Opus |

- [`rules.md`](rules.md) is appended to every role's prompt.
- [`roadmap.md`](roadmap.md) is the backlog. Edit it to steer the team.
- The security and firmware roles are listed at the bottom of the roadmap and
  are not running yet.

## The loop

```
run-loop.sh ml                                   (hourly)
  1. review loop over agent PRs already waiting
  2. at the WIP limit with nothing of Ben's to answer → stop, no session started
  3. ML "work" run: answer Ben's comments, else fix an in-lane bug,
     else take one roadmap task → PR
  4. new agent/ml/* PRs get labels; out-of-lane ones go straight to needs-ben
  5. review loop, per PR, all in this one run:
       needs-review ─principal→ approve, notes=0 ──────────→ approved (Ben's turn)
                              → approve, notes>0 ─ML fixes─→ needs-review …
                                                 └ML files/declines only─→ approved
                              → changes ─────────ML responds→ needs-review …
       round 3 still with changes → the principal decides on a 4th round:
           next=restart → rounds reset, its review is the brief (MAX_RESTARTS=1)
           next=ben     → needs-ben, with what Ben has to decide
       on the last round, notes are filed or declined, never pushed
run-loop.sh sweep    principal comments on whatever the loop missed (daily)
run-loop.sh review   step 5 only
run-loop.sh status   agent PRs with their state and round count
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
| OOM on a 7.7 GB, no-swap box | Each `claude` runs in a `systemd-run --user --scope` capped at `MEMORY_MAX` (4.5 GB), at `nice 10` and `CARGO_BUILD_JOBS=2` |
| Disk | Preflight refuses to start with less than `MIN_FREE_GB` (6 GB) free. Each agent reuses one persistent worktree (`~/sources/wt-agent-{ml,principal}`), so `target/` and `.venv` are built once. |
| A runaway session | `RUN_TIMEOUT` (90 min) and `--max-budget-usd` on each invocation |
| Overlapping runs | `flock`. An hourly ML run that finds the lock taken just skips (the next hour retries), and a sweep waits up to 4 h. |
| Hourly sessions with nothing to do | At the WIP limit, with no unanswered comment of Ben's, `ml` ends before starting a session. |
| A review loop that never converges | Three rounds per cycle. After the third, the principal must either restart the cycle (at most `MAX_RESTARTS`, default 1) or hand the PR to Ben. It is told not to raise new nits on code it has already accepted. |
| PR churn spending Actions minutes | Open-PR limit (`ML_WIP_LIMIT=2`). Agents open PRs only when they are merge-ready. |

Every knob is an environment variable at the top of [`run-loop.sh`](run-loop.sh).

## Setup (once)

```bash
scripts/agents/setup.sh            # labels + the two agent-log issues (idempotent)
loginctl enable-linger "$USER"     # a user manager with nobody logged in (timers + the memory cap)
```

Before this directory is on `main`, try it from the branch:

```bash
AGENT_REF=HEAD DRY_RUN=1 scripts/agents/run-loop.sh ml   # prints what it would do
AGENT_REF=HEAD scripts/agents/run-loop.sh status
```

## Scheduling

`ml` runs hourly and `sweep` runs daily. On Ben's NixOS server (`gantz`) these
are systemd **user timers** declared in `~/nixconf/host/gantz/default.nix`,
with linger on.

- `Persistent=true` runs a slot that was missed while the VM slept, once it
  wakes.
- A timer never starts a second copy of a still-running oneshot.
- Output goes to `journalctl --user -u wayfinder-agents-ml`.

```bash
systemctl --user list-timers 'wayfinder-agents-*'
systemctl --user start wayfinder-agents-ml     # run one now
```

On a host without that config, use cron instead:

```cron
0 * * * *   $HOME/sources/wayfinder/scripts/agents/run-loop.sh ml    >>$HOME/.local/state/wayfinder-agents/cron.log 2>&1
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

1. Write `<role>.md`, following the existing two.
2. Give it a branch prefix and a lane regex in `run-loop.sh`.
3. Add its log issue to `setup.sh`.
4. Generalise `ml_prs`/`adopt_new_prs` over the roles. They are ML-specific
   today on purpose, to stay simple while there is a single author.
