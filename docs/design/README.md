# Design docs

This folder holds design docs for non-trivial features — the kind of change
where the "how" and "why" were worked out in a design discussion and are worth
capturing *before* implementation starts, rather than reconstructed later from
the diff.

A design doc's job is to make an implementation session self-sufficient: write
down enough context and enough of the closed decisions that whoever (or
whichever session) builds the feature needs nothing else — not a memory of the
conversation that produced it, not a Slack thread. Prefer writing one whenever
a change spans multiple crates, introduces a new wire format, or has more than
one plausible design and the trade-off is worth recording.

## Lifecycle

- **New doc:** add it directly under `docs/design/` as `NN-slug.md`, where `NN`
  is the next two-digit number after the highest one currently in use —
  *anywhere* under `docs/design/`, including `implemented/`. Numbering is a
  single sequence across both folders, not restarted per directory.
- **Status:** the first line of the body is always a `**Status:**` line —
  `Proposed`, `Implemented`, or `Rejected`/`Superseded` — with a short clause on
  what that means for this doc (e.g. "approved for implementation in a later
  session", or "superseded by design NN, see there").
- **Once the feature ships:** move the file into `docs/design/implemented/`
  *and* flip its `Status:` line to `Implemented`. Both steps matter — a doc
  that's moved but still says `Proposed`, or vice versa, is actively
  misleading about whether the design in it still matches the code. Treat this
  as part of landing the feature, not cleanup to get to later.
- Docs in `implemented/` are a historical record of *why* something was built
  the way it was — don't edit them to track subsequent changes to the code;
  the code and its own comments/docs are the source of truth for current
  behavior. If a later change invalidates a decision in an implemented doc,
  that's worth a note (or a new design doc), not a silent rewrite of the old
  one.

## Shape of a doc

Not every section applies to every doc, but this is the shape to start from:

1. **Title + Status + Scope** — one line naming exactly which crates/modules
   are in play, and just as importantly what's *not* touched (e.g. "no change
   to the `LinkT`/`FrameIo` surface").
2. **Motivation** — the concrete cost or problem, ideally with numbers (an
   on-air byte count, a table's memory footprint, a hot-path allocation).
3. **Goals / Non-goals** — draw the boundary explicitly; non-goals prevent
   scope creep during implementation.
4. **Design** — the actual mechanism: wire formats, state added, the new
   control flow. Enough detail that someone could write the failing tests from
   it directly (see the `tdd` skill and this repo's test-first convention in
   the root `CLAUDE.md`).
5. **Correctness argument / edge cases** — the load-bearing reasoning for why
   the design is safe (termination, no misdelivery, degrades gracefully),
   and the edge cases considered.
6. **Migration/versioning** and **security considerations**, if the change
   touches the wire or trust boundary.
7. **Observability** — per the root `CLAUDE.md` ("metrics are first-class"),
   call out what a new feature should expose and to whom; use the
   `add-metric` skill when implementing it.
8. **Alternatives considered** — options that were rejected, and why, so they
   aren't re-litigated mid-implementation.
9. **Open decisions for the implementing session** — anything deliberately
   left for whoever builds it to decide, called out explicitly rather than
   left implicit.
10. **Key file map for the implementer** — a short list of the specific files
    (and line numbers, if stable enough) the implementation will touch. This
    is the single highest-leverage section for making the doc self-contained.

A design doc is not a spec that has to be followed to the letter — if
implementation surfaces a better approach, take it, and note the deviation
either in the doc's own "open decisions" section (if not yet implemented) or
in the MR description (if it does).
