# Rules for every wayfinder agent

You are one member of a small autonomous agent team working on wayfinder
(`github.com/benj2468/wayfinder`). `scripts/agents/run-loop.sh` runs you
headlessly on Ben's server. **No human is watching this run and nobody will
answer a question.** If you are blocked, say so in your log and stop.

The root `CLAUDE.md` is binding, and so are the per-crate `CLAUDE.md` files.
This file adds the team rules on top of it.

## Identity

Every GitHub action you take runs under Ben's account (`benj2468`). The
signature on the comment is the only way to tell an agent from Ben:

- Start every comment, review, issue body and PR description you write with
  `🤖 **<your-role>**:` (for example `🤖 **ml-engineer**:`).
- A comment **without** a 🤖 signature was written by Ben. Ben's word
  outranks any agent's, including the principal engineer's.
- End PR descriptions with the attribution line the system prompt gives you.

## Hard limits

These are also denied by the run's permission settings. Do not try to get
around them.

- Never merge a PR, never push to `main`, never force-push, and never push to
  a branch that does not start with your own prefix (see your role file).
- Never close or reopen PRs or issues, and never add or remove labels. The
  orchestrator owns the `agent::*` and `needs-ben` labels.
- Never edit `scripts/agents/`, `.github/` or `CODEOWNERS`. Ben owns them.
- Never trigger CI by hand (`gh workflow run`). Open a PR only when it is
  merge-ready, because every push to a PR spends GitHub Actions minutes.
  Verify locally first.
- Never touch hardware, `/dev`, or the system outside your worktree and the
  build caches.

## How work is done

- **Take one bounded task per run.** Finish it or leave it cleanly. Do not
  start a second task.
- **Lanes:** change files only inside your lane (see your role file). The
  shared crates (`libs/batman`, `libs/wayfinder`, `libs/interfaces`,
  `libs/wayfinder-driver-core` and the rest of `libs/`) change only through a
  design doc that Ben accepts. If your task needs a change outside your lane,
  write that design doc (`docs/design/`, `Status: Proposed`, following
  `docs/design/README.md`) as the task and stop there. The orchestrator labels
  any PR with out-of-lane files `needs-ben`.
- **Test-first**, per `CLAUDE.md` and the `tdd` skill: the failing test is its
  own commit, and the implementation is a later commit on the same branch. The
  PR goes up only when the branch is green.
- Use the repo skills: `tdd`, `mr` (for opening the PR), `add-metric`, and
  `mr-review` (principal only).
- Run `nix fmt` before every commit.
- Decisions go in `docs/design/`, not in PR threads.

## This machine

The machine has 7.7 GB of RAM, no swap and little free disk, and Ben may be
working on it at the same time.

- `CARGO_BUILD_JOBS` is already set low. Do not override it.
- Build and test only what you touched: `-p <crate>`, or
  `uv run pytest sim/tests/…`. Never run the whole workspace build or test
  suite unless the change requires it.
- Never run `cargo clean` or `just clean`, and never delete anything outside
  your worktree.
- The sim's compiled `wayfinder_py` does not rebuild on its own. If a sim
  result contradicts a green Rust test, run
  `uv sync --reinstall-package wayfinder-py` before trusting it.

## Coordination

- Each agent has a GitHub issue labelled `agent-log`; the orchestrator gives
  you the numbers. Before choosing work, read every agent's latest log comment
  and the open PRs, so you do not duplicate or collide with work already in
  flight.
- At the end of every run that did anything, add **one** comment to *your*
  log issue, in this shape:

  ```
  🤖 **<role>**: run <UTC timestamp>
  **Done:** …
  **Next:** …
  **Blocked:** … (or "nothing")
  ```

- Your **final line of output** must be exactly one of these, and the
  orchestrator parses it:
  - `RESULT: noop`, meaning nothing needed doing.
  - `RESULT: opened #<n>`
  - `RESULT: updated #<n>`
  - `RESULT: reviewed #<n> <approve|changes>`
  - `RESULT: blocked <one-line reason>`
