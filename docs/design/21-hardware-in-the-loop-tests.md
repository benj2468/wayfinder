# Design: tests that run on real silicon

**Status:** Tier B implemented, on `main` in `ee95c92` — `libs/wayfinder-hil`
and `just hil`, with the first tests in §5 written. **Tier A is not built**: no
crate uses `embedded-test`, so §4.1 remains a proposal and this doc stays here
rather than moving into `implemented/`.

Design 20 (`docs/design/implemented/20-embedded-clock-independence.md`) landed
on `main` in `a2d2cb5`; §2.3 and half of §5 are about verifying its board
claims on the hardware they are about.

**Sequenced: Tier B first, as its own MR; Tier A second.** §4.2 needs no
firmware change and carries the value (§9's last two entries), so splitting
there costs nothing and keeps the `embedded-test` question (§10) off the
critical path. Both tiers are specified here so the second MR does not need a
second design.

Establishes a fourth test tier. Nothing in this document changes shipped
behaviour; it adds a harness, a board inventory format, and a first set of
tests. It also records two things the survey turned up that are true of `main`
today and are not written down anywhere else: §7.1 (the board's management port
takes credential-mutating requests with no authorization) and §2.4 (two stale
doc claims).

## 1. Scope

**In play:**

*First MR (Tier B):*

- **`libs/wayfinder-hil` (new crate)** — the host-side harness: board
  discovery, flashing, reset, and a management-API client bound to a named
  board. A root-workspace member whose tests are all `#[ignore]`d.
- **`justfile`** — `hil`, `hil-list`, `hil-flash`.
- **`.config/nextest.toml`** — a test group that serialises access to boards.
- **`libs/wayfinder-server/CLAUDE.md`, `docs/design/06-...`** — correct §2.4's
  stale claim.

*Second MR (Tier A):*

- **`bins/wayfinder-hil-nrf52840` (new crate)** — an on-target test firmware,
  its own `[workspace]` beside the three board binaries.

*Neither:*

- **`.github/workflows/ci.yml`** — nothing now; §4.6 records what a job
  pinned to a `[self-hosted, hardware]` runner needs so standing one up later
  is not a research project.

**Explicitly not touched:**

- **Any shipped crate's behaviour, API or wire format.** If a test cannot be
  written without changing the firmware, that change is its own MR with its own
  argument — see §6.3.
- **The shared GitHub Actions runner.** It has no boards and never will; §4.6.
- **`bins/wayfinder-stm32f411`.** No management port at all
  (`bins/wayfinder-stm32f411/src/main.rs:7-8`) and no `runner` configured, so
  Tier B cannot reach it and Tier A would be greenfield. Out of scope here and
  cheap to add later — §10.
- **The docker sim, the nix VM tests, `libs/wayfinder-test`.** Unchanged. This
  tier sits beside them, not over them.

## 2. Motivation

### 2.1 What the existing tiers cannot see

Four tiers of test exist and none executes an instruction on a microcontroller:

| tier | what it proves |
|---|---|
| host unit tests | logic, against mocked peripherals and a fake clock |
| `libs/wayfinder-test` (tick driver) | multi-node routing, virtual clock, synchronous |
| `libs/wayfinder-shark` pytest, docker sim | wire format, host-binary topologies |
| nix VM tests | host node deployment |

Plus two static firmware gates, and they are the good kind — `build-embedded`
(cross-compile + clippy) and `build-stack-budget`, which reads a linked ELF and
fails if a task's poll frame reserves more stack than `memory.x` can spare.
Root `CLAUDE.md:100-109` holds these up as the pattern to reach for first, and
that advice stands: anything decidable from the image should stay decidable
from the image.

What is left over is everything that is only true of a running part:

- **Peripherals.** RTC1 driven by the internal RC oscillator, the RADIO, USB
  enumeration, flash erase/program.
- **Real cancellation and interrupt latency.** `select` dropping a link's
  `recv` mid-frame is host-tested against a mock; against a real radio task it
  is a different program. Design 19 §4 says so outright.
- **Reboot.** The retained fault record, the durable store's A/B ping-pong,
  and — the moment #54 lands — design 20's clock checkpoint.
- **Resource exhaustion at real sizes.** The 32 KiB heap
  (`libs/wayfinder-nrf/src/lib.rs:83`), against real response sizes.
- **RF.** Fragmentation under loss, range, the N² OGM cost on a shared segment.

### 2.2 Two open bugs, both in that surface, both found by hand

The strongest argument for this tier is that the two unresolved hardware bugs
on record are each squarely inside it, and each was found by a human at the
bench noticing a board misbehave:

- **A management client attaching HardFaults the board.** Not a panic — a
  HardFault. Stack overflow was ruled out by measurement (~40 KB of 145 KB
  used). The firmware now self-reports through a `FAULT_RECORD` in `.uninit`,
  so the CFSR is readable after the fact.
- **A dashboard refresh resets the dongle.** A full-ring `GetLogs` response
  OOMs the 32 KiB heap. The USB transaction error observed alongside it is
  downstream of the reset, not its cause — a distinction that cost real time to
  establish and that an automated reproduction would have handed over for free.

Both are *reproducible over the management port*. Neither is reachable from any
existing test. A tier that can drive `GetLogs` against a real board with a full
record ring turns the second into a red test in minutes, and the first into a
harness that reports a CFSR instead of "the board stopped responding".

### 2.3 Design 20's board claims are proven with a fake clock

The MR this follows is about what a node does when it *cannot tell the time*,
and every claim it makes about a board is currently checked on a host against a
`WallClock` fed a `Duration` by hand. Its own §10 test list ends with:

> 13. A board whose anchor is lost keeps routing — the regression test for the
>     whole objection.

That test exists and passes, in `libs/wayfinder-auth`, on x86. The objection it
answers is about an nRF52840 in a field with no operator nearby.

One number in that design is a datasheet quote and wants to be a measurement.
§2.1 argues from "roughly ±250 ppm, about 20 seconds a day" — the LFCLK
internal RC, which is what both nRF boards use because the dongle has no 32.768
kHz crystal. Because the posture is a **floor** (`Clocked::AtLeast`), the two
drift directions are not symmetric: a slow clock is harmless and a fast one
expires live peers early. So *the sign and magnitude of the drift on real
parts* is what says how long a board may free-run before §5.2's "dropping peers
whose certificates it can prove expired" starts happening. That is measurable
only against an off-board reference, which is precisely what this tier is.

### 2.4 Two documentation claims that are already false

Recorded here because an implementing session will otherwise trust them:

- `libs/wayfinder-server/CLAUDE.md:373-378` and
  `docs/design/06-management-api-authentication.md:203-211` both say the nRF
  boards' management wiring "was removed during BLE bring-up and has not
  returned". It has returned. `libs/wayfinder-nrf/src/node.rs:278-284` brings
  up the CDC-ACM management port unconditionally whenever USB init succeeds, on
  both nRF boards, with no feature flag or config gate.

  And the first of those is not merely out of date — it states a **requirement**
  that the code now violates, in bold, addressed to exactly the person who
  wired the port back up:

  > What follows is a requirement on whoever wires the port up: **bring it up
  > only when a board is configured to, never unconditionally.**

  So this is not a doc that drifted behind the code. It is a doc that says
  "don't do X", followed by a commit doing X, and the sentence immediately
  after it — "nothing enables it today" — is what made the requirement read as
  hypothetical. That is worth naming precisely because the correction in §10 is
  otherwise easy to mistake for tidying.

  This is load-bearing for the whole design: **Tier B needs no firmware change
  at all.** It is also a security fact, and §7.1 treats it as one.

- Root `CLAUDE.md:100` says HIL "is not set up in this repo" and names
  `defmt-test` + `probe-rs` as the shape it would take. The first half is what
  this document changes; the second half needs revisiting, because there is no
  `defmt` anywhere in the workspace and its absence is deliberate — §4.1.

## 3. Goals and non-goals

**Goals**

1. A claim that is only true on hardware can be written as a test that fails
   when it stops being true.
2. The harness compiles on every machine, including one with no boards
   attached, and is compiled by the ordinary workspace build.
3. Running it needs one command and no per-session setup beyond plugging boards
   in.
4. A failure reports enough to diagnose from: logs, alarms, the retained fault
   record, stack high-water — not a bare assertion.
5. The rig is portable from a desk to a self-hosted runner without rewriting
   the tests.

**Non-goals**

- **Gating merges on a shared runner.** §4.6.
- **Covering every board.** The nRF52840 DK is the only part with an onboard
  probe, so it is the only one Tier A can target; the dongle is reachable over
  Tier B only. STM32 is out of scope entirely (§1).
- **Replacing the static gates.** `build-stack-budget` stays. A property
  decidable from the ELF should be decided from the ELF: it runs on every PR,
  needs no hardware, and cannot be flaky.
- **Replacing hand bring-up.** Design 19 §12 is a hand-written hardware log —
  real MACs, boot output, a fragmentation-vs-loss table. That kind of
  exploratory session is how you find out what to assert. This tier is for
  keeping what was found.

## 4. Design

Two layers, because "runs on hardware" covers two genuinely different things:
code that runs *on* the part, and a host driving a part *from outside*. They
need different toolchains, catch different bugs, and Tier B is worth more.

### 4.1 Tier A — on-target tests

A firmware image whose `main` is a list of assertions, flashed to a DK and run
under `probe-rs run`, which already is the DK's configured cargo runner
(`bins/wayfinder-nrf52840/.cargo/config.toml:15`).

**Where it lives: `bins/wayfinder-hil-nrf52840`**, its own `[workspace]`, beside
the three board binaries and copying their shape — `memory.x`, `flip-link`,
`panic = "abort"`, `.cargo/config.toml`. Not a prettier path like `tests/hil/`,
for one concrete reason: `just build-embedded` and CI's `build-embedded` walk
the board workspaces, so a crate that lives there is cross-compiled and
clippied on every PR *for free*. That is goal 2 applied to Tier A, and it is
the whole difference between a harness that survives between sessions and one
that rots.

**The harness crate: `embedded-test`, if it can be made to speak `log`.**

`CLAUDE.md:100` suggests `defmt-test`, and that is the wrong shape here.
There is no `defmt` in this workspace and the reason is recorded in
`libs/wayfinder-log/Cargo.toml:57-58`: `defmt` defers formatting to a host
decoder, whereas `wayfinder-log` installs a `log` sink on the RTT channel it
already owns, so RTT output is readable with no decoder in the loop. Adopting
`defmt` for tests alone would mean a second logging stack in the one crate
whose job is that there is only one.

`embedded-test` is the successor and reportedly carries a `log` feature beside
its `defmt` one, communicating pass/fail to `probe-rs run` over semihosting.
**Decision criterion for the implementing session:** does `embedded-test` with
`defmt` off route its output through the existing RTT `log` sink, and does
`probe-rs run` return a non-zero exit code on a failing test? Verify that
before writing tests against it.

**Fallback, if it does not:** a plain `#[no_main]` firmware that runs the
assertions itself and exits through semihosting with a status. That costs one
small runner module and no new dependency, and `probe-rs run` already surfaces
a semihosting exit. Naming the fallback matters because a design whose first
step is an unvalidated third-party crate is a design that stalls at step one.

**What Tier A is for.** Only properties reachable from *inside* the firmware
and not observable over the management port:

- `Clock::now` is monotone across a long read sequence, including across the
  RTC's 24-bit rollover that embassy's time driver extends.
- `WallClock` free-run advances and never decreases, on the real timer rather
  than a hand-fed `Duration`.
- `FlashStore`'s A/B ping-pong against real flash: write, read back, write
  again, read; and a reader never sees a torn mix when a page is erased
  mid-sequence.
- A node's durable identity record is stable across a reset (design 22; this
  said "FICR-derived identity" before a board had a seed of its own).
- The largest response the log ring can produce fits the 32 KiB heap — §2.2's
  second bug, bounded from inside as well as reproduced from outside.

Note what is *not* here: drift characterisation. A board cannot measure its own
oscillator's error, because it has no better reference than the oscillator.
Drift is a property of board silicon that only an off-board clock can see, so
despite appearances it belongs in Tier B (§5.2). This is the one place the
two-layer split is not obvious, and getting it wrong would produce a test that
measures nothing while looking authoritative.

### 4.2 Tier B — a host driving a real node over the management API

The higher-value layer, and the one that needs no firmware change (§2.4).

Both nRF boards expose an unauthenticated CDC-ACM management port over USB.
`wayfinder_client::Client::connect_serial`
(`libs/wayfinder-client/src/lib.rs:462-470`) speaks the ordinary prost envelope
with 4-byte BE length framing over `tokio_serial` — the same request set as
TLS, no handshake. The board answers it from `handle_router`
(`libs/wayfinder-embedded-driver/src/lib.rs:558-575`).

So a host test can already: read `GetNodeInfo`, `GetRoutingTable`,
`GetLinkQualityTable`, `GetAlarms`, `GetLogs`; and write `SetTime`, `SetAuth`,
`SetLogLevel`, `SetConfig`. That is the entire observable surface of a node,
and it is exactly the surface design 20 extended.

**`libs/wayfinder-hil` provides three things and no test logic:**

- **`Board`** — one attached part. Flash (`probe-rs download` for a DK;
  `nrfutil device program --traits nordicDfu` for a dongle, reusing
  `bins/wayfinder-nrf52840-dongle/runner.sh`'s package step) and reset. *(RTT
  attach was specified here and not built — see §12.)* Addressed by **probe serial number**, never by enumeration order.
- **`Node`** — a `wayfinder_client::Client` bound to that board's management
  port, found by matching the USB device's serial number to its `/dev/ttyACMn`,
  again never by ordering. Device nodes reorder between plugs and across a
  reset, and a rig that indexes them is a rig that fails on the day a second
  board is added.
- **`Rig`** — the inventory (§4.3), plus the diagnostic dump (§4.5).

Tests are ordinary `#[tokio::test] #[ignore]` functions in that crate.

### 4.3 The board inventory is configuration, and its absence is a skip

A `hil.toml` at the repo root (gitignored; `example.hil.toml` checked in),
overridable by `WAYFINDER_HIL_CONFIG`:

```toml
[[board]]
role  = "alpha"          # what tests ask for
kind  = "nrf52840-dk"    # dk | dongle
probe = "001050288335"   # J-Link serial; absent for a dongle
usb   = "F4CE3684..."    # USB serial, for finding the CDC-ACM node
```

Two rules:

- **A role a test asks for and the inventory does not name is a skip with a
  stated reason, not a failure.** `just hil` on a laptop with nothing plugged
  in must exit clean. Goal 2 is what keeps the harness alive between hardware
  sessions, and a harness that fails loudly on every developer machine gets
  disabled within a week.
- **Roles, not device paths, in test code.** A test says `rig.board("alpha")`.
  Which physical part that is stays in one file, which is what makes the same
  tests run on a desk and on a runner (goal 5).

### 4.4 Always compiled, never run by default

`libs/wayfinder-hil` is a **root-workspace member**, so `cargo build
--workspace` and `cargo nextest run --workspace` compile it and its tests. Every
test is `#[ignore]`.

The point is API drift. A harness kept out of the workspace — a separate
directory, a feature nothing turns on — compiles only on the rig, so it breaks
silently on the first refactor of `wayfinder-client` and is discovered weeks
later by whoever next has boards on the desk. Compiling it on every MR turns
that into a build error on the MR that caused it. The repo already has the
precedent in the other direction (`bins/wayfinder-web`'s empty default features
build a stub so `--workspace` does not fail); this is the same instinct applied
to a crate that *can* always compile.

```
just hil       # cargo nextest run -p wayfinder-hil --run-ignored all
just hil-list  # probe-rs list + resolved inventory, for diagnosing a rig
```

Flashing is **not** a harness concern: `cargo run` in a board's own directory
already flashes it and attaches RTT, which is strictly more than a harness
command would do. Selecting a probe by serial is the only thing this crate
could add, and that matters only once two boards are attached.

**Boards are a singleton resource and nextest runs in parallel.** Two tests
flashing the same part is a failure mode that looks like flaky hardware, which
is the worst thing a hardware rig can look like — it is unfalsifiable, and it
teaches people to re-run. Serialise it explicitly in `.config/nextest.toml`:

```toml
[test-groups]
hil = { max-threads = 1 }

[[profile.default.overrides]]
filter = "package(wayfinder-hil)"
test-group = "hil"
```

One group for all boards is the honest starting point. Per-board groups are a
later optimisation and only worth it once tests outnumber boards.

### 4.5 A failure has to say why

An assertion failure against a board is nearly useless on its own: the
interesting state is on the part, and the part may have reset. Every test runs
its body through a helper that, on failure, collects and attaches:

- the tail of `GetLogs`,
- `GetAlarms` — the latched conditions, which survive the burst that caused
  them where a log line does not,
- the **retained fault record** if one is present. This is the piece that turns
  §2.2's first bug from "the board stopped responding" into a CFSR, and the
  firmware already writes it (`.uninit`, read at boot by `init_platform`).
- the stack high-water mark, which `stack::report()` already emits on
  management-client disconnect (`libs/wayfinder-nrf/src/usb_mgmt.rs:302-333`).

If the port is gone, the helper resets the board and reads the fault record on
the next boot — a HardFault is exactly the case where the diagnostic is only
reachable after a reset, and it is also exactly the case worth diagnosing.

### 4.6 Never on the shared runner; what a self-hosted one needs

The shared GitHub Actions runner has no boards, so this is not a merge gate.
That is the same call the benchmarks made and for the same reason: a job that
cannot run where CI runs either fails constantly or is quietly disabled.

Recorded so a runner can be stood up without rediscovery:

- **udev.** The user needs read/write on the probe's USB node *and* on
  `/dev/ttyACM*` — `probe-rs list`'s own hint on a machine without it is "most
  likely a permissions problem", and the CDC-ACM half is the one people forget
  because it is not the probe.
- **A container gets the devices passed in**, or the self-hosted runner's job
  runs directly on the host. Enumeration inside a container also has to
  survive a board re-enumerating after a reset.
- **Job shape:** `runs-on: [self-hosted, hardware]`, triggered only by
  `workflow_dispatch` (never `push`/`pull_request`), `continue-on-error:
  false`, and no other job's `needs` may point at it.
- **A power-cycle path.** Reset over the probe covers most of it, but a wedged
  USB stack needs the bus cut. A switchable hub is the cheap answer, and until
  there is one, §5's reboot tests are reset-only — stated in §6.2.

## 5. The first tests

Ordered by what they would have caught. All are Tier B unless marked.

**Design 20 on real silicon**

1. **A fresh, unanchored board routes.** `GetNodeInfo` reports
   `clock_posture = Unknown`, and `GetRoutingTable` shows a neighbour. Design
   20 §10's test 13 — the regression test for the whole objection — against the
   hardware it is about.
2. **`SetTime` moves the floor and cannot roll it back.** Above
   `MIN_PLAUSIBLE_UNIX` → `AtLeast`; a *lower* subsequent `SetTime` leaves the
   posture where it was; below the floor is refused. Design 20 §4.7's three
   rules, on the path that actually carries them.
3. **A reset returns the board to `Unknown`.** True today, because nothing
   persists a checkpoint. **This test is written to be flipped**: it is the
   executable form of design 20 §4.5's constraint on #54, and it is the thing
   that will fail loudly if a credential is persisted without a checkpoint, or
   with one that boots from the certificate's `not_before` instead — the
   rollback §4.4 forbids in bold. Its doc comment must say so, or someone will
   "fix" it by deleting it.
4. **Interop with a clocked peer, over real RF.** A `wayfinder-tap` host node
   and an unanchored board converge over 802.15.4: OGMs verify, keep-alives
   verify both directions. Design 20 §10's test 7 proves this in-process; the
   claim is about a mesh.
5. **`ClockUnsynchronized` is raised** while the board holds a credential and
   is `Unknown` — design 20 §7's stated way for a board with no probe attached
   to say "I am routing and not judging expiry".

**The two open bugs**

6. **`GetLogs` against a full record ring does not reset the board.** Fill the
   ring (`SetLogLevel trace` plus traffic), request logs, assert the node still
   answers `GetNodeInfo`. Direct reproduction of §2.2's OOM.
7. **Attach/detach/reattach a management client N times without a fault.** On
   failure this is the test that reports a CFSR (§4.5). It may well be red on
   the first run — that is the point, and a known-red test with a ticket is
   worth more than an unreproducible bug report.

**Regressions the static gates cannot see**

8. **Stack headroom after a soak.** `build-stack-budget` bounds one task's poll
   frame statically; this bounds *actual* peak use after real traffic, read
   from `stack::report()`.
9. **Fragmentation across payload sizes.** Design 19 §12's hand-made
   16/64/200/400-byte table, re-run as an assertion with a loss ceiling.

**Design 24 on real silicon**

10. **A board inside its renewal window asks, unattended, over the mesh.**
    Design 24's claim is that a board's problem was never reaching its
    authority — it routes to one already — but speaking to it, since every
    management conversation here is TLS over TCP. `libs/wayfinder-hil/tests/
    renewal.rs` puts the asking half on the part: a real board, free-running on
    an internal RC oscillator with a credential in its own flash, decides it is
    due, builds a request, puts it on real RF, and reports what it did.

    The *answering* half is deliberately not here, and the reason is a gap in
    this rig rather than in the design: it needs a certificate authority on the
    mesh, which means a host node carrying both a radio and a `CertAuthority` —
    the `wayfinder-ca` posture with an 802.15.4 link, for which §3 defines no
    board role. The exchange end to end lives on x86, in `wayfinder-test`,
    against the same `CertAuthority` a provider runs. What this rig adds is the
    half x86 cannot have, plus the case a partitioned board actually
    experiences: asking, not being answered, and saying so.

**Tier A**

11. The five in §4.1.

**Measurement rather than assertion**

11. **Clock drift characterisation.** `SetTime` a board, wait, read its
    estimate back against the host clock, report ppm and sign. Not a pass/fail
    — the part-to-part spread is real and a threshold would be arbitrary. It
    turns design 20 §2.1's datasheet figure into a number from these parts, and
    the sign is the operationally interesting half (§2.3). Emit it as a
    recorded artifact the way the benchmarks emit theirs.

## 6. What this tier cannot do, and what it costs

### 6.1 It is not a substitute for the static gates

A hardware test is slower, needs a part, and can fail for reasons unrelated to
the change. `build-stack-budget` runs on every PR in seconds and cannot be
flaky. The rule stays as `CLAUDE.md:100-109` states it: **reach for the ELF
first**, and use this tier for what is genuinely undecidable without a running
part.

### 6.2 Reset is not a power cycle

Until the rig has switchable power (§4.6), "reboot" means a probe reset or a
`SYSRESETREQ`. RAM contents, some peripheral state, and anything the SoftDevice
holds do not necessarily behave as they would across a real power cut — which
matters for exactly the state §5's test 3 is about. Test 3 is honest under a
reset and *stronger* under a power cut; the gap should be named in its doc
comment rather than papered over.

### 6.3 A test that needs a firmware change is a different MR

Non-goal by construction (§1). The temptation on a rig is to add a debug
request kind, or a test-only build, to reach some state — and that is how a
management API grows a surface that exists only for tests and ships anyway. If
a property is unreachable over the shipped RPC surface, that is either a real
observability gap (make the case, use `add-metric`) or a job for Tier A, which
runs inside the firmware and needs no new wire surface at all.

### 6.4 Flakiness is the failure mode to design against

A hardware rig that is 95% reliable trains people to re-run, and a re-run
culture makes the tier worthless because a real regression is indistinguishable
from a bad day. Three of the decisions above exist for this and should not be
relaxed casually: addressing by serial rather than enumeration order (§4.2),
serialising board access (§4.4), and skipping rather than failing when the
inventory is absent (§4.3).

## 7. Security considerations

### 7.1 The management port takes credential writes with no authorization

Recorded because it is true of `main` today, is not written down, and this
design depends on it.

The board's CDC-ACM management port has **no handshake and no authorization**.
`connect_serial` performs none by design (`libs/wayfinder-client/src/lib.rs:452-461`
contrasts it with `connect_tls`'s pinned-key handshake), and the embedded
serve path dispatches straight to `handle_router`
(`libs/wayfinder-embedded-driver/src/lib.rs:558-575`) — no tier check, no
`authz`. Anyone with the cable can `SetAuth` and `SetTime`.

That is defensible: physical possession of a board is already total control of
it, the port is USB rather than network, and the same reasoning already admits
the node's own seed at the self-key tier. Design 20 leans on it deliberately —
`SetAuth` over a board's port was unusable before this MR because the path
rejected every certificate as not-yet-valid.

Two things follow, and the second is the one that matters:

- The rig needs no credentials, which is why Tier B costs nothing to stand up.
- **This tier must not become the reason the port stays unauthenticated.**
  Design 06's F7 asks that bringing the port up be an explicit, auditable act,
  and `libs/wayfinder-server/CLAUDE.md` records it as a requirement on whoever
  wires the port up (§2.4) — a requirement the current wiring does not meet.
  Tracked as **#59**, which also carries the three options (gate it,
  authenticate it, or accept it and say so) rather than presuming the answer.

  Whichever is chosen, the rig follows: the tests in §5 are written against
  `wayfinder_client::Client`, not against the absence of auth, so authenticating
  the transport is a harness change and not a rewrite. What must not happen is
  the reverse — the port staying open because a test rig came to depend on it.

### 7.2 The rig handles real key material

The clock tests need a mesh: a trust anchor, a CA, and certificates. These are
test keys minted per run and held **only in memory** for the process's
lifetime — never written to disk and never checked in — and the inventory file
is gitignored because probe serials are hardware identifiers. No
part of this runs against a production trust anchor.

## 8. Observability

- **A HIL failure is a diagnostic bundle, not a message** — §4.5.
- **Drift is reported, not asserted** — §5's test 11, emitted as an artifact
  the way the criterion reports are.
- **`GetAlarms` is the primary assertion surface for anything latched.** A test
  that greps logs for a condition the alarm board already tracks is testing the
  wrong thing: the alarm survives the burst and the log line does not
  (`libs/wayfinder-alarm`).
- **No new metric is proposed here.** If a §5 test cannot observe what it needs,
  that is a real gap — `add-metric`, and it belongs in the router's state per
  the root `CLAUDE.md` rule, not in the harness.

## 9. Alternatives considered

- **A QEMU or Renode simulation instead of parts.** Attractive for CI, and it
  fails at the thing this is for: §2.1's list is peripherals, real timing, real
  RF, and real flash — the four things a model is least likely to get right,
  and where the two open bugs live. Worth revisiting for *reproducing* a
  failure once found, not for finding one.
- **Extending the docker sim to drive real boards.** The sim's value is that it
  runs many nodes in one process with no hardware; giving it a hardware
  dependency compromises exactly what it is for. It also already assumes host
  binaries throughout (`scripts/topology.py`).
- **`defmt-test`, as `CLAUDE.md:100` suggests.** Rejected in §4.1: it would put
  a second logging stack in the workspace whose logging crate exists so there
  is one.
- **Keeping the harness out of the workspace** (a `tests/` directory, a
  disabled feature). Rejected in §4.4 — it stops compiling and nobody finds
  out. This is the single decision most likely to be reversed for convenience
  and most costly to reverse.
- **Tier A only.** Cheaper, and it misses both open bugs, all five design 20
  claims, and everything about a host talking to a node. Tier B is where the
  value is; Tier A covers the residue Tier B cannot see.
- **Tier B only.** Tempting, since it needs no firmware change. But the
  properties in §4.1 are unobservable over RPC, and a board that cannot be
  tested from the inside has no way to check an invariant that never surfaces
  in a response.
- **Making it a merge gate on a self-hosted runner immediately.** A rig with
  no track record blocking merges produces §6.4's re-run culture on day one.
  Manual first; promote it when its failure history says it is trustworthy.

## 10. Decisions taken at proposal time

Recorded here rather than left open, because each one changes what the first MR
contains.

- **Sequencing: Tier B first, Tier A second**, per the Status note. The
  consequence worth naming is that **`embedded-test` is not on the critical
  path** — §4.1's verification question is deferred with Tier A rather than
  answered now, and the first MR ships without resolving it.
- **The first rig assumes one DK and one dongle.** Tests 1-3 and 5-8 run on the
  DK; the dongle is in from the start because §2.2's OOM is a *dongle* report,
  so the part that reproduces the bug is the part that must be attached. Test 4
  needs the DK plus a `wayfinder-tap` host node on the same machine; test 9
  needs two parts and skips per §4.3 until a second DK is attached.

  The cost taken on deliberately: the dongle has no probe, so it brings DFU
  flashing and reset-by-re-enumeration into the harness on day one rather than
  later. That is the fiddly half of §4.2's `Board`, and deferring it would have
  meant building `Board` twice.
- **Test 3 (reset → `Unknown`) runs**, with the doc comment §5 asks for. Its
  value is in failing later; a test held back until the change it guards
  against is not a guard.
- **The unauthenticated management port (§7.1) is ticketed, not fixed here** —
  **#59**, which revisits design 06's F7 — bringing the port up should be an
  explicit, auditable act, and the wiring is currently unconditional. The rig is
  built against `Client`, so when auth arrives it is a harness change and not a
  rewrite. The two stale doc claims in §2.4 are corrected in this MR regardless,
  since they are wrong either way and are how the next session gets misled.
- **STM32 stays out of scope** (§1). Adding it means a `probe-rs` runner and,
  for Tier B, a management port that board does not have.

### Still genuinely open, for the Tier A MR

- **`embedded-test` with `log`, or the hand-rolled semihosting runner.** §4.1
  states the criterion; verify before building on it.

## 11. File map

| File | MR | Change |
|---|---|---|
| `libs/wayfinder-hil/` | B | **new** — `Rig`, `Board`, `Node`, the diagnostic dump; tests in `tests/` |
| `libs/wayfinder-hil/src/inventory.rs` | B | `hil.toml` parsing, role → board, skip-when-absent |
| `example.hil.toml` | B | checked-in template; `hil.toml` gitignored |
| `.config/nextest.toml` | B | `[test-groups] hil = { max-threads = 1 }` + package override |
| `justfile` | B | `hil`, `hil-list` |
| `Cargo.toml` | B | add `libs/wayfinder-hil` to workspace members |
| `CLAUDE.md:100` | B | replace "not set up in this repo" with a pointer here |
| `libs/wayfinder-server/CLAUDE.md:376`, `docs/design/06-...:207` | B | correct §2.4's stale claim |
| `bins/wayfinder-hil-nrf52840/` | A | **new workspace** — on-target tests, copying `bins/wayfinder-nrf52840`'s shape |

### Failing tests to write first

Per `CLAUDE.md`, the harness itself is developed test-first where it has logic
of its own. Most of `wayfinder-hil` is I/O against real parts, but two pieces
are pure and belong under ordinary host unit tests:

1. **Inventory resolution.** A role the file names resolves to a board; a role
   it does not is a skip carrying a reason naming the role; a malformed file is
   an error, not a skip. The distinction between "no boards" and "broken
   config" is the one that decides whether `just hil` on a laptop is clean.
2. **USB serial → device-node matching**, against a fixture of enumerated
   devices: the right node is chosen when ordering is reversed, and an ambiguous
   match is an error rather than a first-hit. This is §6.4's flakiness rule in
   its most concrete form.

## 12. What the Tier B MR built

Recorded as it landed, so the Tier A session knows what it inherits.

**Built:** `libs/wayfinder-hil` — `Inventory`/`Rig` (roles, skip-when-absent),
`Board` (probe-rs flash and reset), `Node` (a `Client` bound to a board, with
readiness as a successful `GetNodeInfo` rather than a successful `open`),
`Diagnostics` (§4.5's dump), the `hil-devices` listing, the nextest test group, the
`just hil*` targets, and §2.4's two doc corrections. §5's tests 1, 2, 3, 6 and 7
plus a rig smoke test, all `#[ignore]`d.

**Two ergonomic decisions, because they shape what a test looks like:**

- **`Node` derefs to `Client`.** A test writes `node.set_time(t)`, not
  `node.client().set_time(t)`. The wrapper exists to bind a client to a *board*,
  not to curate the request surface, and re-exporting sixty methods by hand
  would have been a second surface to keep in sync.
- **`with_diagnostics` and `report` are methods on `Node`, not helpers each
  test file defines.** They started as per-file copies, which is the shape that
  quietly diverges — and the dump is precisely the thing a test author forgets
  to ask for, since the test that most needs it is the one that failed
  unexpectedly. Putting them in the harness means the test files contain test
  functions and nothing else.

**What the first bench session changed.** Recorded because every item was
invisible until a board was attached, which is the argument for this tier in
miniature:

- **The first clock test was passing vacuously.** `clock_posture` is read from
  the router's auth state, so a board with authentication *off* reports
  `Unknown` whatever its wall clock holds — and asserting `Unknown` there would
  have kept passing with design 20 reverted. Tests now install a credential
  first, which pulled `TestMesh` forward from the deferred list below.
- **Credentialed-and-`Unknown` needs a certificate that cannot date the board.**
  Install floors the anchor at `max(installer_unix, cert.not_before)`, so an
  ordinary credential always anchors; `not_before = 0` is what leaves a node
  undated, and it is the state §5's tests 1 and 5 are both about — so they
  merged into one test.
- **The board was running stale firmware**, reporting `clock_posture`
  `Unspecified` (the absent-field zero) rather than `Unknown`. The rig
  diagnosed it, and the test now names that case explicitly instead of failing
  with a confusing comparison.
- **Two harness bugs of the kind only a bench finds:** `probe-rs --probe` takes
  a `VID:PID:Serial` selector and rejects the bare serial an inventory names;
  and the inventory has to be *discovered* by searching upward, because cargo
  runs a test with its working directory at the package root — which made every
  test skip as though no boards were attached, on a bench where one was. The
  second is the more dangerous shape: it fails by looking exactly like success.
- **A finding in the firmware, not the harness: #60.** A board accepts a
  credential naming a MAC it does not route under, silently. Its peer-visible
  consequence is reasoned rather than observed, because confirming it needs the
  second board §5's test 4 wants.

**Deferred, and why:**

- **§5's test 4 needs a second node.** Test 5 is done — it merged into test 1,
  since `ClockUnsynchronized` is raised in exactly the credentialed-and-
  `Unknown` state that test arranges. Minting the mesh turned out to be a
  prerequisite for tests 1-3 rather than deferrable work, and is built.
- **§5's tests 8 and 9** (stack headroom after a soak, the fragmentation table)
  need two parts and a way to read `stack::report()` back, which currently
  reaches only the log ring.
- **RTT attach**, listed in §4.2 and not built. Nothing needed it: the board's
  log ring is readable over `GetLogs`, which is the same records RTT would
  carry and works on a dongle with no probe. Worth revisiting only if a
  pre-`main` boot failure ever needs watching, which is Tier A's territory.
- **Design §4.5's "reset the board and re-read the fault record".** The dump
  re-runs its four RPCs over the connection it has; it does not reset and
  reconnect. The fault record *is* reachable — the firmware logs it at the next
  boot (`previous boot ended in a hardfault … cfsr=…`), so it arrives through
  `GetLogs` — but only after a reset the harness does not perform. The
  HardFault test's doc comment says so rather than claiming a CFSR it cannot
  produce.
- **Dongle flashing.** `Board::flash` refuses it with a message pointing at
  `runner.sh`. DFU needs `nrfutil nrf5sdk-tools pkg generate`, which runs under
  qemu-user on this host; wiring it blind would waste a bench session. Reset is
  refused permanently rather than deferred — a dongle has no probe, so there is
  no host-side reset to build.

**One observability gap, which §8 predicted:** `GetNodeInfo` reports the clock
*posture* but not the *floor*, so "the estimate did not move" is not directly
readable. Design 20 §4.4's monotonicity invariant is testable only because
`SetTime` **reports** a refused anchor rather than swallowing it
(`adapter.rs`'s "reported, not swallowed"). That is enough for the test, and it
is worth knowing that the property is observable through an error message and
not through state — if that error is ever softened to a no-op success, the test
guarding monotonicity silently stops guarding it.
