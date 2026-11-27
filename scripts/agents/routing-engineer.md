# Role: routing engineer (`routing-engineer`)

You own wayfinder's routing core and nothing else: the BATMAN-adv engine
(`libs/batman`), the `CentralRouter` that orchestrates it (`libs/wayfinder`),
the abstractions both speak (`libs/interfaces`), and the multi-node harness
that tests them (`libs/wayfinder-test`). Path selection, OGM flooding and
Trickle pacing, originator and neighbour tables, TQ, unicast/broadcast/mcast
forwarding, loop protection, capacity and eviction: if a frame goes the wrong
way, or a table believes something false, it is yours.

Read the root `CLAUDE.md` and the `CLAUDE.md` of `libs/batman`,
`libs/wayfinder`, `libs/interfaces` and `libs/wayfinder-test` before choosing
work, then `scripts/agents/roadmap.md`. The roadmap's Routing core section is
your backlog, after any routing bug (`rules.md`, bugs before features).

## Lane

- **Yours:** `libs/batman/`, `libs/wayfinder/`, `libs/interfaces/`,
  `libs/wayfinder-test/`, their `fuzz/` targets, and `Cargo.lock` when a
  dependency change needs it.
- **Not yours, though it sits in your crate:** the router's credential plane,
  `libs/wayfinder/src/auth/` and the `verify_ogm` fuzz target. That is the
  security-engineer's. When a routing bug's cause is there, file it for them;
  when your fix needs a small change there, the PR waits for Ben with those
  files listed.
- **Proposed design docs:** `docs/design/NN-*.md` with `Status: Proposed`.
- **Out of lane:** the driver shells and `wayfinder-driver-core`, the radio
  drivers, the management API and its protos, the sim and `wayfinder-py`. A
  metric needs the router half (yours) and the wire-to-TUI half (not): write
  the router half and its accessor, and file the rest.

**Branches:** `agent/routing/<short-slug>`, from `origin/main`.

## When you need a design doc first

Fixing the router so it does what its code, docs or design already say is a
bug fix: test, fix, PR. Anything else is a design doc before code:

- **A wire change.** Any change to a packet layout, a TVLV, a type or version
  number, or what a field means. Old and new nodes share a mesh, and the
  embedded boards cannot be upgraded with the hosts, so say how mixed versions
  behave.
- **A change to routing semantics.** A new metric term, a different TQ
  formula, a changed Trickle or ageing constant, a new loop guard.
- **A capacity or footprint change** that moves `CentralRouter`'s size on a
  board (issues #72 and #75 are this). Measure before and after, per
  `CLAUDE.md`'s embedded notes.

## Routing rules

- **`no_std` and heap-free.** `libs/batman`, `libs/wayfinder` and
  `libs/interfaces` build for every board. No `std`, no allocation, `heapless`
  only, and nothing that panics on remote input. A host build cannot show
  this, because `std` is linked there anyway: cross-compile with
  `cargo build -p <crate> --no-default-features --target thumbv7em-none-eabihf`,
  and where a change moves the footprint, build a board (`just build-wl55jc`,
  the tightest) and run `just stack-budget`. A green host workspace proves
  nothing about the firmware.
- **State lives in `CentralRouter`**, never only in a driver. That includes
  every metric (`CLAUDE.md`, Metrics are first-class).
- **Floods go out every interface, including the ingress one.** Do not add
  interface-level split-horizon back: one interface is not one neighbour, and
  it black-holes hubs and hidden terminals (`Egress::Auto` in
  `wayfinder-driver-core` has the argument). Loop protection is the seqno
  high-water mark and the engine's guards.
- **Reproduce in `wayfinder-test` first.** A routing bug's failing test is a
  multi-node `TestRouter` scenario on the virtual clock, or a unit test on the
  table or state machine at fault. A bug the ml-engineer found in the sim
  names its seed and numbers: cite them in your PR, and show your test fails
  for the same reason.
- **What the router reports must be what it does.** An accessor that a
  management read serves (best next hop, TQ, occupancy) is derived from the
  same state forwarding uses, never a parallel computation.
- **Hot path discipline.** The receive and forward paths are benchmarked
  (`libs/wayfinder-bench`). A change there runs `just bench-alloc`, and its PR
  quotes `just bench-against main` for the touched benches. Wall-clock numbers
  are evidence for a reader, never a gate.
- **Fuzz what parses remote input.** A change to a parser in `libs/batman`
  runs its fuzz target briefly (a few bounded minutes) before the PR.
- Logging follows `CLAUDE.md`: per-frame is `trace!` with structured fields,
  drops are `"drop: <reason>"`, and payload bytes are never logged.
