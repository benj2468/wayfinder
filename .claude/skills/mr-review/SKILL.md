---
name: mr-review
description: Use after pushing a wayfinder MR/branch that is non-trivial logic, security-sensitive, introduces a new wire format, or spans multiple crates — e.g. "review this MR", "get a second opinion on this branch", "is this ready for review". Decides whether CLAUDE.md's review bar is met, then runs pr-review-toolkit:review-pr against the branch diff and gates human review on findings being addressed.
---

# Second-opinion review for a complex wayfinder MR

CLAUDE.md requires this for any MR that is non-trivial logic,
security-sensitive, introduces a new wire format, or touches multiple crates.
Trivial MRs (small fixes, doc tweaks, mechanical refactors) don't need it —
say so and stop if the branch clearly falls in that bucket.

## 1. Confirm the diff scope

Identify the branch and note the diff it would produce as an MR:

```bash
git diff origin/main...<branch>
```

This is the scope that matters — not the working-tree diff, and not against a
possibly-stale local `main`. `pr-review-toolkit:review-pr` defaults to
`git diff --name-only` (uncommitted changes only), which shows nothing once a
branch is fully committed and pushed, so it must be told explicitly to use
`origin/main...<branch>` as its comparison range rather than its default.

## 2. Run the review toolkit

Invoke `pr-review-toolkit:review-pr all`, briefing it to diff against
`origin/main...<branch>` instead of its default working-tree diff. Its `gh pr
view` step is a no-op here (this repo has no GitHub PR) — that's fine, ignore
any failure from it. Let it run its full agent set (comment accuracy, test
coverage, silent-failure hunting, type design, general code review, then
simplification) rather than a single pass — that breadth is the reason to use
it instead of a hand-rolled reviewer.

Flag anything the toolkit's generic agents wouldn't know to look for but this
codebase cares about: state that should live in the `no_std` `CentralRouter`
but got added to the host driver instead (see CLAUDE.md's Metrics section), or
a routing-engine change that breaks a `no_std`/heapless invariant.

## 2a. Also run a skeptic pass (devil's advocate)

The toolkit's agents are good at "is this code correct?" but weak at "should
this code exist at all?" So *in addition* spawn one `sonnet` sub-agent as a
skeptic whose default posture is that new code is **guilty until proven
necessary**. Brief it to diff `origin/main...<branch>` and push back on:

- **Over-engineering** — abstractions, traits, generics, sum types, or state
  machines more elaborate than the problem needs. For each, ask "could this be a
  plain function, a `bool`, or three fewer lines?"
- **Speculative generality / YAGNI** — extension points, parameters, or features
  added "in case" that no current caller uses.
- **Premature configuration** — new config knobs or CLI flags most operators
  will never touch and that could be a sensible hardcoded default.
- **Redundant state** — data stored in two places, or stored when it could be
  derived.
- **Ceremony without payoff** — confirmation steps, wrapper types, or error
  variants that add code without protecting against a real failure.
- **Scope creep** — anything in the branch that isn't part of the one logical
  change the MR is supposed to be (CLAUDE.md: one logical change per MR).

Tell it to cite file:line, argue *why* each thing may be unnecessary, and
propose the simpler alternative — its job is to push back, not rubber-stamp. It
may note genuinely-justified complexity, but the burden of proof is on the code.
Prefer the simpler design the skeptic proposes unless there's a concrete reason
the complexity earns its keep; record that reason if you keep it.

## 3. Address the findings

For each finding: fix it, or write down why it's not being fixed (false
positive, out of scope, intentional trade-off already covered in the MR
description). Do not request human review with unaddressed, unexplained
findings outstanding.
