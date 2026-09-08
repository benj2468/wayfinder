# Design: authentication that does not depend on a bare-metal node's clock

**Status:** Implemented. Supersedes an earlier draft of this number
(`20-embedded-wall-clock.md`, never merged) which made an authority-anchored
wall clock *load-bearing* on a board.

One piece is deliberately carried forward rather than built here: §4.5's
**persisted checkpoint**, which belongs with the credential #52 persists and is
stated there as a constraint on that work. Everything else in this document is
in the code, including the two decisions §6.2 and §9 left to the implementing
session — recorded in §11 below.

Owns GitLab #51, subsumes #54, unblocks #53, and imposes a hard constraint on
#52 (§4.5). Two latent bugs in `main` are recorded in §2.2.

## 1. Scope

**In play:**

- `libs/wayfinder/src/auth.rs` — `OgmAuth` gains an explicit time *posture*
  instead of an overloaded `now_unix == 0`; its duration-based bookkeeping moves
  onto monotonic time; the keep-alive trailer's eight bytes change meaning.
- `libs/wayfinder-auth/src/cert.rs` — `verify_cert` takes that posture. No
  change to `MembershipCert`'s bytes. Gains `MIN_PLAUSIBLE_UNIX`, hoisted.
- `libs/wayfinder-embedded-driver` — a `WallClock`, advisory rather than
  gating, and the loop feeding it.
- **`libs/wayfinder-clock-trust` (new crate)** — `clock_trust.rs` lifted out of
  `wayfinder-server` so a client can reach it (§4.6).
- `libs/wayfinder-protos` — `SetAuthRequest` gains `installer_unix`; a new
  `SetTime` request kind (§4.7).
- `libs/wayfinder-client`, `bins/wayfinder-ctl` — stamp the time, and refuse to
  when the host cannot vouch for it.

**Explicitly not touched:**

- **The certificate format, the trust anchor, the OGM signature scheme, the
  pairwise tag.** No change to what is signed or how.
- **Keep-alive frame *size*.** §4.3 changes what eight already-reserved bytes
  mean, not how many there are.
- **Host routing behaviour.** A host with a working clock behaves as today.
- **Cert renewal on embedded.** A board still cannot renew itself.

## 2. Motivation

### 2.1 The objection

A bare-metal node has no RTC and no NTP. What it has is `RTC1`, a counter
peripheral driven by LFCLK — and LFCLK sits on the **internal RC oscillator**,
because the DK has a 32.768 kHz crystal and the dongle does not, so `InternalRC`
is the only setting that works on both. That is roughly ±250 ppm, about 20
seconds a day, and it counts from reset with no notion of a date. Nothing
survives a power cut.

Making a node's ability to route depend on that is brittle in the direction that
hurts most, because the two failure directions are not symmetric:

| board clock | consequence | who is harmed |
|---|---|---|
| **slow** | certificates verify past their true expiry; revocation-by-expiry is delayed | bounded — §5.1 |
| **fast** | the board rejects its peers and is rejected; goes inert | **itself, in the field, with no operator nearby** |

A design whose failure mode is "the remote node bricks itself because its
oscillator drifted" is the wrong design for this hardware.

### 2.2 Two bugs the objection surfaced

Neither is reachable today — no board runs auth — and both fire the moment #53
lands.

**Bug A — the unclocked posture is applied inconsistently.** Four places treat
`now_unix == 0` as *judge no window*: `live_neighbor` (`auth.rs:2176`,
`now == 0 || n.cert.not_after >= now`), `prune_expired`,
`evict_expired_neighbors`, `identity_conflict`. `has_live_key`'s doc states the
rule outright — "An unclocked node judges no validity window at all … a node
that cannot tell the time must not tear down its own routes on a guess."

Two places fail *closed* instead, and nothing reconciles them:

- `TrustAnchor::verify_cert` (`cert.rs:390`) — `now_unix < not_before` is
  `NotYetValid`, so an unclocked node refuses every certificate a real authority
  issues.
- `verify_ogm`'s cached-certificate fast path (`auth.rs:1661`) — the same window
  re-checked against the current clock. At zero this rejects **every** OGM from
  a neighbour whose certificate is already cached.

So an unclocked node does not skip validity as documented; it half-skips it, and
the half it enforces is the half that partitions it.

**Bug B — clock-free bookkeeping is gated behind the clock.** `prune_expired`
(`auth.rs:722`) returns early when `now_unix == 0`. Two of the three things it
does need a clock. The third does not:

```rust
self.in_flight.retain(|r| r.attempts < MAX_CERT_REQUEST_ATTEMPTS);
```

That is pure attempt-count reclamation, and its own comment says what happens
without it: a target that never answers "permanently pins a slot … and
`MAX_IN_FLIGHT_CERT_REQUESTS` such dead entries would permanently block fetching
any further originator's cert." On every board, the exact denial that `retain`
exists to prevent is live, because it sits behind a guard about a different
concern.

Bug B is the whole problem in miniature: *elapsed*-time logic and
*absolute*-time logic are tangled, so the absence of absolute time disables
things that never needed it.

## 3. The idea: three kinds of clock, one irreducible

Every consumer of `now_unix` falls into exactly one bucket:

**(a) Absolute wall time.** Certificate `not_before`/`not_after`; revocation
record windows. Genuinely needs to know the year. **Irreducible.**

**(b) Elapsed time only.** `CERT_REQ_RATE_LIMIT_SECS`, `next_attempt_unix`
backoff, `PENDING_REPLY_TTL_SECS`, `in_flight` reclamation. Durations. A
monotonic clock — which every board has, and which cannot drift or reset
backwards — serves them strictly better. Using `now_unix` is arguably wrong on a
host too: an NTP step perturbs a rate limit for no reason.

**(c) Time *shared* between two peers.** The keep-alive replay bucket. Needs the
ends to **agree**, which is not the same as needing either to be **right**.

Move (b) to monotonic time, replace (c) with a mechanism needing no clock, and
make (a) *advisory* where it cannot be judged. What remains:

> **Signature always, window when known.**

The signature check is the real trust boundary — it segregates one mesh from
another and binds a key to a MAC — and is entirely clock-free. The window check
is a revocation *optimisation*, which §5.1 argues the mesh enforces collectively
whether or not any individual board can.

## 4. Design

### 4.1 (b) — duration bookkeeping moves to monotonic time

`OgmAuth` gains a monotonic `now: Duration` beside `now_unix`, fed by the
`CentralRouter::set_auth_time(now, now_unix)` that already receives both and
currently forwards only the second. The four sites in §3(b) switch to it, and
`in_flight` reclamation moves out of `prune_expired` onto a path that runs
unconditionally.

Fixes Bug B, independently correct on a host, no wire impact. The
uncontroversial part; it could land first on its own.

### 4.2 (a) — a three-valued posture, applied uniformly

Replace the overloaded sentinel with a type that distinguishes *knowing the
time* from *knowing a bound on it*:

```rust
/// What a verifier knows about the time, and therefore which of a
/// certificate's guarantees it can check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Clocked {
    /// An authoritative reading. Both ends of every window are enforced.
    At(u64),
    /// A lower bound: "it is at least this". Proves expiry; never proves
    /// not-yet-validity.
    AtLeast(u64),
    /// No usable clock. Signature, mesh id and key-to-MAC binding still
    /// checked; windows not judged.
    Unknown,
}
```

`TrustAnchor::verify_cert` takes a `Clocked`:

| posture | `now < not_before` | `now > not_after` |
|---|---|---|
| `At(t)` | `NotYetValid` | `Expired` |
| `AtLeast(f)` | **never checked** | `Expired` when `f > not_after` |
| `Unknown` | not checked | not checked |

Everything else — signature, mesh id, key↔MAC binding, reserved-MAC refusal —
is performed identically under all three. Only *expiry* varies.

`verify_ogm`'s cached-cert fast path (`auth.rs:1661`) takes the same posture,
which is what makes Bug A's two fail-closed sites agree with the four advisory
ones. The already-advisory sites keep their behaviour and gain an honest
spelling. That is the whole of #54: with the posture explicit,
`identity_conflict`'s early return stops being an accident of sentinel choice
and becomes a stated rule.

**Why `AtLeast` rather than a boolean "skip windows".** A board's clock is a
floor, not a point — §4.4 shows every source of it under-counts. Modelling that
honestly buys three things at once:

- **It cannot partition the node.** There is no `not_before` comparison an
  `AtLeast` node can fail, so it can never reject a healthy peer for being "too
  early". §2.1's fast-clock disaster becomes *unreachable*, not merely unlikely.
- **It still enforces expiry** whenever it has evidence — the property passive
  revocation rests on.
- **It is monotone by construction**, so latching at the maximum makes rollback
  impossible rather than detected.

The asymmetry is the right one: accepting a certificate slightly early is
benign; honouring a revoked one is not, and `AtLeast` can only err the first
way.

A host constructs `At` from a trusted reading and `Unknown` from an untrusted
one (§4.6). Only a board constructs `AtLeast`.

### 4.3 (c) — keep-alives move onto the replay counter that exists

`augment_keepalive` signs a 30-second time bucket and puts it on the wire;
`verify_keepalive` requires it within one bucket of the receiver's own. Between
a clocked node and an unclocked one this fails **both** directions — the
unclocked end sends bucket 0 and computes `now_bucket` 0, so every real bucket
is `> now_bucket` and every bucket it sends is astronomically stale. This is the
one clock use that cannot be made advisory unilaterally, because it is a
*signature input carried on the wire*, not a local policy check.

It also need not exist. The comment introducing it (`auth.rs:97`) says the
bucket bounds replay "without needing per-neighbor replay counters" — but
directed and fan-out frames have since grown exactly that, and three properties
make adopting it nearly free:

1. **The trailer is already the right size.** `KEEPALIVE_TRAILER_LEN = 8 + SIG_LEN`
   and `FANOUT_TRAILER_LEN = 8 + SIG_LEN` are identical. The eight bytes change
   meaning from a bucket to a counter; **no frame grows**.
2. **The sender side is already shared.** `send_counter` is "the node's
   **single** outgoing directed-frame counter, shared by every destination and
   by fan-out frames alike".
3. **The receiver side already admits a new class.** `send_counter`'s doc
   establishes the property that makes this sound: "`accept_recv_counter` keys
   on `src` alone, and any subsequence of a strictly increasing sequence is
   strictly increasing." A third class drawing from the same sequence is another
   subsequence. **No receiver change.**

Keep-alives become the fan-out shape — counter plus the sender's signature,
verified against the cached certificate as now. Replay is bounded by a
high-water mark rather than a shared clock: *stronger* than a 30-second window
as well as clock-free.

This is the one wire change; see §6.2 for rollout.

### 4.4 The board's clock: a monotone floor

The board keeps a `WallClock` producing `Clocked::AtLeast`, from exactly two
inputs, in this order of preference:

1. **An anchor**, supplied by whoever installs a credential (§4.7) — the only
   way an absolute time ever enters the node.
2. **A persisted checkpoint**, written by the board itself.

Between updates it free-runs: `estimate = anchor + (rtc1_now − rtc1_at_anchor)`.
The anchor is refused below `MIN_PLAUSIBLE_UNIX` (`1_735_689_600`, 2025-01-01),
which catches a source that was never set and reads as 1970.

**Two invariants, and the whole design rests on them:**

- **The estimate never decreases** — not while running, not across a reboot.
  Free-running advance is monotone by construction; the checkpoint is a
  high-water mark; a new anchor is taken as `max` against the current estimate.
- **Nothing arriving over the radio may move it.** Not a peer's certificate, not
  a signed beacon from the authority. §8 records why.

**At install**, the anchor is floored at the certificate's own start:

```
anchor = max(current_estimate, installer_unix, verified_cert.not_before)
```

applied **after** the certificate verifies, so an unverified field can never
move the clock. `not_before` is CA-signed where `installer_unix` is merely
trusted, which matters because the two are stamped by *different machines at
different times*: a certificate minted three weeks ago and hand-carried on a USB
stick is the intended out-of-band flow, not an edge case. That is also why the
field is named for the **installer**, not the issuer (§4.7).

**At boot**, the estimate is restored from the checkpoint and **nothing else**:

> **Never anchor from the node's own `not_before` at boot.** It would reset the
> expiry clock on every power cycle, by an amount that grows with the
> certificate's age, and anyone who can power-cycle the board triggers it. The
> damage is not mainly to its own credential — clocked peers reject that anyway
> — but to its judgement of *everyone else's*: a board with a one-year
> certificate rebooting at month eleven would believe it is month zero and
> honour any peer certificate valid then, including ones revoked-by-expiry ten
> months earlier.

The checkpoint under-counts, always in the safe direction: the board cannot
measure how long it was powered off, so on restore it can claim only "at least
the last thing I wrote down". The deficit is *powered-off time plus time since
the last checkpoint*, and it persists for the session. Behind is safe; ahead is
not. This is precisely why the posture is `AtLeast` and not `At`.

### 4.5 The checkpoint is a hard prerequisite on #52

Today nothing survives a reset, because `identity.rs` persists only the `Mac`.
A board boots uncredentialed and must be enrolled, which re-anchors it — so the
reboot story is vacuous in the shipped scope and §4.4's boot rule has nothing to
restore from.

It stops being vacuous the moment #52 persists a credential, and that is the
constraint this design hands forward:

> **#52 must persist the clock checkpoint in the same blob as the credential,
> written, loaded and erased with it.** A board that reloads a credential
> without a checkpoint boots credentialed-and-`Unknown`, which is a supported
> state but a needless one — and any attempt to fill the gap from the
> certificate or from peers reintroduces exactly what §4.4 and §8 forbid.

The checkpoint also needs a periodic rewrite, not just a write at shutdown,
because a board loses power without warning. The interval is a **wear trade-off,
not a correctness one**: a coarser interval only widens the deficit, and can
never make the clock wrong in the other direction. Two 4 KiB pages at roughly
10 000 erase cycles is the budget; flash wear, rotation and erasure are already
#52's questions, which is why the checkpoint belongs there rather than being
split across two designs.

### 4.6 The host side: only a clock that can be vouched for

An absolute time reaches a board from an operator's machine, so the honesty of
the whole scheme rests on that machine's clock. `MIN_PLAUSIBLE_UNIX` alone is
not enough — it catches a clock that was *never set*, and
`wayfinder-server`'s `clock_trust` module names the case it cannot catch:

> a clock that is plausible and wrong — off by hours because the node booted
> before NTP reached it, which is the ordinary condition of a field-deployed
> mesh with no upstream.

That module already answers it, by reading the kernel's NTP status word through
`ntp_adjtime(2)` (`STA_UNSYNC` plus a `maxerror` bound, default 5 s). It is
self-contained — no intra-crate imports, `std` and `libc` only, the syscall
already `cfg`-gated with a non-Linux fallback.

**Extract it into `libs/wayfinder-clock-trust`.** `wayfinder-client` must not
depend on `wayfinder-server`; that is the same constraint `wayfinder-tls-mgmt`
already exists to satisfy ("neither management-TLS crate depends on the other"),
and this follows the precedent. Both crates then depend on the new one, so the
*same* verdict gates a CA issuing a certificate and a client stamping the time
that installs it.

**Policy: `wayfinderctl` fails closed.** A command that carries a time refuses
to run while the host clock is untrusted, unless the operator passes
`--unsafe-allow-untrustworthy-clock`, which maps to the existing
`ClockTrust::Assume` and mirrors the node's own `require_time_sync = false`
opt-out. The flag is deliberately long and ugly: it should be unpleasant to
type and obvious in shell history.

Failing closed is affordable *because of* §4.2 — under "signature always, window
when known" a board that ends up `Unknown` still routes, and raises
`ClockUnsynchronized` so the state is visible. Under the superseded design the
same refusal bricked the enrolment. The rewrite is what makes strictness cheap.

`ClockSync::Unsupported` (a macOS operator machine, which the devShell supports)
counts as trusted, per the existing policy.

**The footgun that will actually bite**, from the module's own header:

> `chronyd` clears `STA_UNSYNC` only when its `rtcsync` directive is set … which
> makes it very easy to leave off. A chrony without it is *locked to a source and
> reporting microseconds of offset* while this module correctly reads
> `TIME_ERROR`.

On a node that is handled — `nix/modules/wayfinder.nix` sets it. On an
**operator's arbitrary laptop nothing sets it**, so a correctly-synchronised
stock Ubuntu or Fedora machine will commonly read as untrusted. The refusal must
therefore be *diagnostic*, not merely a failure: name the verdict
(`ClockSync::name()`), and on `Unsynchronized` say that `rtcsync` may be the
cause. `Unreadable { errno }` exists precisely to distinguish a seccomp-blocked
syscall from an undisciplined clock, because "an operator told the wrong one
will fix the wrong thing".

### 4.7 Carrying the time: `installer_unix`, and a `SetTime` of its own

`SetAuthRequest` gains one field:

```protobuf
  // The wall clock of the machine performing this install, in unix seconds.
  // Stamped by the installer, NOT by the signer: in the out-of-band enrolment
  // flow the certificate may have been minted weeks earlier and hand-carried.
  uint64 installer_unix = 5;
```

Absent on the wire it decodes as `0`, the sentinel every credential path already
refuses, so an older client fails closed. The name matters: `issuer_unix` — the
first draft's name — invited a future change to read it off the CSR bundle,
which would be a silent fail-open proportional to how long the bundle sat in a
drawer.

**A distinct `SetTime` request kind is added, reversing this design's earlier
position.** The first draft rejected one for two reasons; the rewrite dissolved
the load-bearing half:

- *"It reopens the bootstrap ordering problem"* — no longer true. That objection
  was that the clock gates the credential which authenticates the clock-setter.
  Under §4.2 a node verifies its management client's credential **without a
  clock**, so the circularity is gone.
- *"It needs its own tier, audit class and rate-limit bucket"* — still true, and
  now just one `rpc_table!` entry against a real operational need.

That need: **correcting a drifted board, or re-anchoring one that lost its
checkpoint, without re-issuing a certificate.** Install-only anchoring makes the
certificate authority a participant in what is purely local maintenance, and
20 s/day means a long-lived board will need it.

`SetTime` carries the same value under the same rules: `access: [Admin,
SelfKey]` (matching `SetAuth` — anyone who could lie about the time can already
install an arbitrary credential, which is strictly more powerful), refused below
`MIN_PLAUSIBLE_UNIX`, taken as `max` against the current estimate so it cannot
roll the node back, and floored against the **currently held** certificate's
`not_before` — the node holds a valid credential, so `now ≥ its not_before`
holds just as it does at install.

Both paths are gated identically by §4.6. Two entry points sharing one rule is
the residual cost, and §10's tests pin both.

## 5. Correctness

### 5.1 Why advisory windows are safe: enforcement is distributed

Every clocked node independently verifies every certificate it sees. So for a
board that judges no windows:

- **It honours an expired or revoked-by-expiry peer.** That peer's other
  neighbours — hosts with real clocks — still refuse it. Blast radius is the
  board's own links.
- **Its own certificate lapses unnoticed.** Its clocked peers reject its OGMs,
  and it falls out of the mesh without needing its own cooperation.

A node with no clock is therefore mostly a hazard **to itself**, and the mesh's
guarantee does not rest on the least capable participant holding the most
fragile state. This is the argument the design turns on; it is stated here so a
later change that centralises enforcement knows what it would break.

What is genuinely given up: on a segment where *every* node is unclocked, expiry
stops being a revocation mechanism. Active `RevocationRecord`s still flood in
OGM tails and are still enforced — and whether a record cancels a certificate
compares the record's `not_before` against the certificate's, two CA-signed
instants with no wall clock involved. So an all-board segment keeps active
revocation and loses passive. §7 makes that visible rather than silent.

### 5.2 Edge cases

- **Unanchored board, host peer.** OGMs verify (signature checked, window
  skipped), keep-alives verify (counter, no bucket), directed frames verify
  (pairwise tag and counter, already clock-free). The node routes.
- **Board anchored, then drifting fast.** Under the superseded design this
  expired live peers and partitioned the node. Under `AtLeast` the `not_before`
  comparison is never made, so the worst case is dropping peers whose
  certificates it can prove expired — recoverable by `SetTime`, and alarmed.
- **A revocation record arrives at an unclocked node.** Unchanged and still
  deliberately deferred: `take_self_revoked` refuses to act without a clock,
  because a long-dead record could otherwise brick a freshly booted board with
  no way to garbage-collect it.
- **Two unclocked boards.** Both `Unknown`; signatures, counters and pairwise
  tags all function. Neither judges expiry — §5.1's given-up case.
- **Monotonic wraparound.** `embassy_time`'s `Instant` is 64-bit microseconds;
  not reachable in any deployment lifetime.

## 6. Security and migration

### 6.1 What is and is not weakened

**Unchanged:** mesh segregation, key-to-MAC binding, OGM authorship, pairwise
data-plane authenticity, next-hop proof, active revocation. All clock-free
already or made so here.

**Weakened, deliberately and only on a node that cannot judge time:** passive
revocation-by-expiry, per §5.1. The alternative is not "expiry is enforced" — a
board has no clock to enforce it with — but "the board refuses everyone", which
is today's behaviour and worse in every operational respect.

**Strengthened:** keep-alive replay is bounded by a monotonic counter rather
than a 30-second window. A board's clock is monotone and cannot be rolled back
by anything on the wire, by its own certificate, or by a reboot. And a host now
refuses to stamp a time it cannot vouch for, where previously it stamped any
reading past a 2025 floor.

### 6.2 Rolling out the keep-alive change

The only wire change. Old and new read the same eight bytes differently, so a
mixed mesh silently drops keep-alives between mismatched nodes — degrading
liveness detection rather than corrupting anything, but not something to do by
accident. In preference order:

1. **Version the trailer** — a reserved OGM TVLV/flag bit, or a distinguishing
   high bit in the eight, so a receiver can tell which it holds.
2. **Flag day** — acceptable only while the deployed set is small and entirely
   operator-controlled, which is true today and will not stay true.

Decide explicitly and record the choice; this is the one place the design defers
something that reaches the wire. **Decided: option 1** — see §11.

## 7. Observability

- **`GetNodeInfo` reports the posture honestly.** `clock_trusted` already
  exists; it must reflect `At` / `AtLeast` / `Unknown` rather than defaulting to
  `true`, which on an unanchored board would be "reporting clock fine while
  refusing every credential operation on the grounds that it is not" — the
  failure `with_clock_trusted`'s own doc warns against. Three states want more
  than a bool; widen the field rather than lying by rounding.
- **Raise `AlarmKind::ClockUnsynchronized`** while a node holds a credential and
  is `Unknown`. Under this design that is a *supported* running state, so the
  alarm is how a board with no probe attached says "I am routing, and I am not
  judging expiry" — the condition an operator needs and cannot otherwise see.
- **A counter of certificates admitted without a window check.** The direct
  measure of how much passive revocation is not being enforced; §5.1's given-up
  case is invisible without it.
- **`wayfinderctl` reports the clock verdict it acted on** whenever it stamps a
  time, not only when it refuses — an operator who used
  `--unsafe-allow-untrustworthy-clock` should see it echoed.

## 8. Alternatives considered

- **The superseded draft: an anchored clock as a hard dependency.** Rejected per
  §2.1. It also rested on "clocked iff credentialed", an invariant that held only
  while nothing persisted a credential — i.e. it would have been broken by #52,
  the very next task in the epic.
- **Skip *every* clock-specific operation on a board.** Fails on exactly one
  thing: §4.3's keep-alive bucket is a signed wire field, so one-sided skipping
  cannot work — the board's outgoing keep-alives are rejected by clocked peers
  no matter what the board skips. Replacing the mechanism rather than skipping
  the check is what rescues the idea, and is why (c) is its own category.
- **Anchoring from the node's own `not_before` at boot.** Rejected in §4.4: a
  rollback that grows with the certificate's age and is triggered by anyone who
  can power-cycle the board.
- **Deriving a floor from *peers'* certificates.** Attractive, and genuinely
  better-behaved than it first appears — a `max` over signature-verified certs is
  monotone within a session, bounded above by real time, and any floor admits a
  strict subset of what `Unknown` admits, so it can never be *worse* than no
  floor. Rejected anyway, on two grounds. **It is defeated in the case it exists
  for:** the max resets on reboot, so an attacker who isolates a booting node
  chooses which certificates it hears and therefore picks its floor. **And one
  misissued certificate poisons the mesh permanently:** a far-future
  `not_before` is public, replayable forever, and would pin every board where
  nothing verifies, with no revocation path — because the poisoning works through
  a field read *before* anything can be judged. The persisted checkpoint (§4.5)
  solves the same problem locally, monotonically across reboots, and
  unreachably from outside.
- **A signed time beacon flooded by the authority.** Rejected: it makes the CA a
  **liveness dependency for the data plane**. A mesh routes today with the CA
  offline, which is what lets it be a cloud VM with no local egress; a beacon
  nodes needed periodically would quietly reverse that.
- **An external RTC.** Neither board has one and the dongle has no header to add
  one. A design that works only on the DK does not serve the board that most
  needs it.

## 9. Open decisions for the implementing session

*(All resolved; the answers are in §11.)*

- **Keep-alive trailer versioning** — §6.2. The one wire decision.
- **Where `Clocked` lives.** `wayfinder-auth` is the natural home (a property of
  certificate verification); `interfaces` if a second crate needs it.
- **Whether `GetNodeInfo`'s `clock_trusted` bool widens to an enum** or gains a
  sibling field. §7 requires the information, not the encoding.
- **Checkpoint interval.** A wear question, deferred to #52 with the note that
  it is not a correctness knob (§4.5).
- **Whether the STM32 board takes this at once.** Nothing here is nRF-specific.

## 10. Key file map for the implementer

| File | Change |
|---|---|
| `libs/wayfinder-auth/src/cert.rs:390` | `verify_cert` takes `Clocked`; gains `MIN_PLAUSIBLE_UNIX` (hoisted from `authority.rs:301`) |
| `libs/wayfinder/src/auth.rs:474` | `OgmAuth` gains monotonic `now: Duration` beside `now_unix` |
| `libs/wayfinder/src/auth.rs:722` | `prune_expired`: `in_flight` reclamation out from behind the clock guard (Bug B) |
| `libs/wayfinder/src/auth.rs:1661` | cached-cert window check takes the posture (Bug A) |
| `libs/wayfinder/src/auth.rs:1806` | `augment_keepalive` / `verify_keepalive` → counter (§4.3) |
| `libs/wayfinder/src/auth.rs:1895`, `:2079`, `:2117` | rate limit, backoff, parked TTL → monotonic |
| `libs/wayfinder/src/auth.rs:2176` | `live_neighbor`'s `now == 0` → the posture |
| `libs/wayfinder-clock-trust/` | **new crate** — `clock_trust.rs` moved out of `wayfinder-server` (§4.6) |
| `libs/wayfinder-embedded-driver/src/lib.rs:108` | `WallClock` producing `AtLeast`; boot restore; loop feeding |
| `libs/wayfinder-protos/.../wayfinder.proto:877` | `installer_unix = 5`; new `SetTime` message |
| `libs/wayfinder-protos/src/rpc.rs:375` | `SetTime` entry: `RouterWrite`, `Mutation`, `[Admin, SelfKey]` |
| `libs/wayfinder-client/src/lib.rs:832` | stamp `installer_unix` from the clock-trust verdict; `set_time` |
| `bins/wayfinder-ctl/src/csr.rs:239`, `src/auth.rs:163` | the gate + `--unsafe-allow-untrustworthy-clock` |

### Failing tests to write first

Per `CLAUDE.md`, these land before the implementation they specify.

**(b) — monotonic bookkeeping**
1. `in_flight` entries at `MAX_CERT_REQUEST_ATTEMPTS` are reclaimed on a node
   that has never had a clock. **Fails today** — Bug B.
2. A rate limit measured across a wall-clock step is unaffected.

**(a) — the posture**
3. `verify_cert` under `Unknown` accepts a signature-valid certificate whose
   window has not opened, and still refuses a forged one, one for another mesh,
   and one whose MAC does not derive from its key.
4. `verify_cert` under `AtLeast(f)`: accepts when `f ≤ not_after`; refuses as
   `Expired` when `f > not_after`; **never** returns `NotYetValid` for any `f`.
5. `verify_ogm` accepts an OGM from a cached-cert neighbour under `Unknown`.
   **Fails today** — Bug A.
6. `live_neighbor` still reports a lapsed neighbour live under `Unknown`.

**(c) — keep-alives**
7. A keep-alive from an unclocked node verifies at a clocked one, and the
   reverse. **Both fail today**; the pair proves the mesh interoperates.
8. A replayed keep-alive is refused on the counter.

**The board's clock**
9. Unanchored → `Unknown`; anchored → `AtLeast`; below `MIN_PLAUSIBLE_UNIX`
   refused and left unanchored; free-running advance never decreases.
10. An anchor is taken as `max` against the current estimate — a lower one does
    not move it backwards.
11. The install anchor is floored at the verified certificate's `not_before`, so
    a stale `installer_unix` cannot drag the clock back.
12. **Boot restores from the checkpoint only** — given a persisted credential
    whose `not_before` is older than the checkpoint, the estimate comes up at
    the checkpoint. The regression test for §4.4's boot rule.
13. A board whose anchor is lost keeps routing — the regression test for the
    whole objection.

**Host side**
14. An untrusted clock verdict yields a stamp of `0`, not a host reading.
15. `wayfinderctl` refuses a credential install on an untrusted clock, and
    proceeds with `--unsafe-allow-untrustworthy-clock`.
16. `ClockSync::Unsupported` counts as trusted, so a macOS operator machine is
    not blocked.

Tests 7 and 8 need `wayfinder-server`'s `embedded` feature, which per GitLab #22
**never runs in CI**. That is a one-line CI fix and belongs in this MR;
otherwise the tests proving the interop claim are the ones nothing runs.

## 11. What the implementing session decided

The four questions §6.2 and §9 left open, and one deviation worth naming.

**Keep-alive trailer versioning (§6.2): a tag bit, not a flag day.**
`KEEPALIVE_COUNTER_TAG` is bit 63 of the eight-byte counter. Every bucket the
previous build emitted was `now_unix / 30` — around 5.8e7 in 2026, or zero on an
unclocked node — so the bit was always clear, and setting it lets a receiver
name what it is holding (`drop: legacy time-bucket keep-alive trailer`) instead
of reporting a signature mismatch an operator has to diagnose from. It is signed
with the counter, so it cannot be flipped off in flight, and **stripped before
the counter reaches the replay guard**: that guard shares one high-water mark
with directed and fan-out frames, and a tagged value would push the mark past
2^63 and make every subsequent directed frame look stale. That interaction is
the reason a naive "set the high bit" would have been a bug rather than a
version marker.

**Where `Clocked` lives: `wayfinder-auth`,** as §9's first option, in a new
`clock.rs` beside `MIN_PLAUSIBLE_UNIX` (hoisted there from
`wayfinder-server`'s `authority.rs`) and `WallClock`. Nothing needed a second
crate to see it.

**`GetNodeInfo`: a sibling field, not a widened bool.** §7 asked for the
information and §9 left the encoding open; `clock_posture` is a new
`ClockPosture` enum next to `clock_trusted` rather than a replacement for it,
because the two are different questions that genuinely come apart. `clock_trusted`
is *may this node make a credential decision*; `clock_posture` is *which validity
windows does its router judge*. A host can hold an authoritative reading while
refusing credential decisions on an undisciplined NTP verdict, and a board has no
NTP concept at all while holding a usable floor. It is read from the router's own
auth state — the very value `verify_cert` is handed — so the report and the check
it describes cannot disagree; authentication off answers `Unknown`, which is
exactly true.

**The STM32 board takes it at once**, per §9's last question: `WallClock` lives
in `wayfinder-embedded-driver`'s `Driver`, which every board shares, so nothing
was nRF-specific to hold back.

**§5.1's promise needed code that did not exist.** The document says active
revocation survives on a node that cannot judge windows — "whether a record
cancels a certificate compares the record's `not_before` against the
certificate's, two CA-signed instants with no wall clock involved". That is true
of the *cancellation* test and not of `cancels_cert_for`, which also required
`not_before <= now < not_after`. At `now = 0` no valid record satisfies the
first half, so an unclocked node enforced nothing at all — harmless while §4.2's
Bug A kept it from admitting anyone, and live the moment that was fixed.
`RevocationRecord::cancels_under` splits the clock-free half (`names_cert`) from
the enforcement window, and a posture that cannot place the window now enforces
a held record unless it can prove it spent. This inverts the previous behaviour
for a future-dated record on an unclocked node — it is enforced early rather
than ignored — which is the right direction of error here and the opposite of a
certificate's: admitting a certificate early is benign, failing to drop a revoked
peer is the harm.

**One deviation from §4.2, stated so it is not read as an oversight.** §4.2 says
a host constructs `At` from a trusted reading and `Unknown` from an untrusted
one. The *router's* clock (`AuthClock::wall`) is deliberately **not** gated on
the NTP verdict: it reports `At` for any reading past `MIN_PLAUSIBLE_UNIX` and
`Unknown` only below it. Rounding every ordinary Linux node whose chrony lacks
`rtcsync` — which §4.6 notes is the common case on a stock distribution — down to
`Unknown` would switch passive revocation-by-expiry off across the whole host
fleet to guard against an error of hours, and §1 says host routing behaves as
today. The NTP gate stays where `AuthClock::Host`'s own doc already put it and
where §4.6 asks for it: on *credential decisions* — `credential_unix`,
`RouterAdapter::wall` (which does answer `Unknown` on an untrusted clock, so
`SetAuth` installs without judging a window), and the client's `stamp_unix`.
