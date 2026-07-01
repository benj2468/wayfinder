---
name: mr
description: Use when the user asks to open/create/ship a GitLab merge request for wayfinder, e.g. "create an MR", "open an MR for this branch", "ship this as an MR". Runs the workspace checks, drafts a Conventional-Commits title and templated description, and creates it with glab.
---

# Creating a wayfinder merge request

This project ships through GitLab MRs on `git.haganah.net`, not direct pushes
to `main`. Follow these steps in order.

## 1. Branch sanity

Confirm the branch was cut from `origin/main` (not a stale local `main`) so the
MR diff is exactly the intended change. If it wasn't, say so before proceeding
— don't silently rebase.

## 2. Run the checks CI will run

These block the MR if they fail, so run them first and fix anything broken:

```bash
cargo test --workspace
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
- The `lint:mr-title` CI job pipes this exact title through `commitlint` — a
  non-compliant title (missing type, sentence-case, trailing period) fails the
  pipeline. It checks the MR title, not individual commit messages.

## 4. Draft the description

Use `.gitlab/merge_request_templates/Default.md` as the structure: Summary,
What's included, Key design decisions, Testing, Deferred/follow-ups. Delete any
section that genuinely doesn't apply rather than leaving it empty. Explain the
*why* and trade-offs — a reviewer should be able to judge the design from the
description alone. State test results honestly; don't claim green if `cargo
test --workspace` wasn't actually run clean.

## 5. Create the MR

```bash
glab mr create \
  --source-branch <branch> --target-branch main \
  --title "type(scope): imperative lowercase summary" \
  --description "$(cat <<'EOF'
## Summary
...
EOF
)"
```

`glab` needs a personal access token configured for `git.haganah.net` (in
`~/.config/glab-cli/config.yml`) — the SSH agent only covers `git push`/`pull`,
not the MR-creation API. If `glab mr create` fails on auth, tell the user
rather than trying to work around it.

## 6. Second-opinion review for complex MRs

If the change is non-trivial logic, security-sensitive, introduces a new wire
format, or spans multiple crates, invoke the `mr-review` skill once the MR is
pushed. Skip this for trivial MRs (small fixes, doc tweaks, mechanical
refactors).
