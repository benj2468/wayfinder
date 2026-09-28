---
name: mr
description: Use when the user asks to open/create/ship a pull request for wayfinder, e.g. "create an MR", "open a PR for this branch", "ship this as an MR". Runs the workspace checks, drafts a Conventional-Commits title and templated description, and creates it with gh.
---

# Creating a wayfinder pull request

This project ships through GitHub pull requests on
`github.com/benj2468/wayfinder`, not direct pushes to `main`. Follow these
steps in order.

## 1. Branch sanity

Confirm the branch was cut from `origin/main` (not a stale local `main`) so the
PR diff is exactly the intended change. If it wasn't, say so before proceeding
— don't silently rebase.

## 2. Run the checks CI will run

These block the PR if they fail, so run them first and fix anything broken:

```bash
cargo nextest run --workspace
nix fmt
cargo clippy --workspace
```

If any `.proto` files changed, also run `buf lint` from `libs/wayfinder-protos/`.

## 3. Draft the title

Must be Conventional Commits: `type(scope): summary`.

- Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`,
  `ci`, `chore`, `revert`.
- Scope (optional but encouraged): the crate/area, e.g. `metrics`, `batman`,
  `tui`, `driver`, `auth`.
- Summary: lowercase, imperative, no trailing period, <=100 chars.
- The `lint-pr-title` CI job pipes this exact title through `commitlint` — a
  non-compliant title (missing type, sentence-case, trailing period) fails the
  workflow. It checks the PR title, not individual commit messages.

## 4. Draft the description

Use `.github/pull_request_template.md` as the structure: Summary,
What's included, Key design decisions, Testing, Deferred/follow-ups. Delete any
section that genuinely doesn't apply rather than leaving it empty. Explain the
*why* and trade-offs — a reviewer should be able to judge the design from the
description alone. State test results honestly; don't claim green if `cargo
test --workspace` wasn't actually run clean.

## 5. Create the PR

```bash
gh pr create \
  --base main --head <branch> \
  --title "type(scope): imperative lowercase summary" \
  --body-file <path-to-drafted-description>
```

`gh` needs to be authenticated against `github.com` (`gh auth login`, or
`GH_TOKEN`/`GITHUB_TOKEN` in the environment) — the SSH agent only covers `git
push`/`pull`, not the PR-creation API. If `gh pr create` fails on auth, tell
the user rather than trying to work around it.

## 6. Second-opinion review for complex PRs

If the change is non-trivial logic, security-sensitive, introduces a new wire
format, or spans multiple crates, invoke the `mr-review` skill once the PR is
pushed. Skip this for trivial PRs (small fixes, doc tweaks, mechanical
refactors).
