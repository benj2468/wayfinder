# Design: Node alarms (a raise-anywhere, storm-safe condition board)

**Status:** Implemented — the raising mechanism landed as `libs/wayfinder-alarm`
and this document is retained as the historical record of why it is shaped this
way. Note the boundary: what shipped is the mechanism and its tests. The
detectors that decide *when* a condition holds (§4.7) and the management-API
read path (§7) are described here as the design intends them, and are deliberate
follow-ups rather than part of what landed.

**Scope:** one new `no_std`-first crate, `libs/wayfinder-alarm`, plus two
`pub(crate)` → `pub` widenings in `libs/wayfinder-log` (`Lock`, `uptime_ms`) so
the two pieces of process-global state share one lock decision and one timebase.
No change to `CentralRouter`, to any driver shell, to the `LinkT`/`FrameIo`
surface, or to the management-API wire format. Nothing on any hot path calls
into this crate yet.

---

## 1. Motivation

A wayfinder node is already *observable*. `GetMetrics` reports here-and-now
gauges, `GetSecurityStatus` reports the auth posture, `GetLogs` serves a
bounded record ring. What a node cannot do is **flag** anything — say, without
being asked the right question, "something is wrong, here is what and since
when."

The gap shows up exactly when it matters most. Suppose an unauthorized source
starts flooding a link. Today the evidence is:

- `trace!("drop: directed frame failed pairwise auth")` in
  `wayfinder-driver-core`, one line **per frame**;
- a `warn!("drop: management authentication denied")` in
  `wayfinder-server`'s transport, one line per attempt.

Both land in the same 512-record ring (64 on a board) that `GetLogs` serves. A
flood is precisely the load that rolls that ring over in seconds, so the
evidence of the flood is what destroys the record of the flood. And reading it
at all requires an operator who is already watching, already at `trace`
verbosity, and already knows the drop string to grep for.

Two properties follow, and they are what this design is for:

- **Survival.** An alarm must outlive the burst that caused it, so an operator
  who attaches *after* the incident still learns it happened. That is the same
  argument that made the log ring polled rather than streamed.
- **Boundedness.** An alarm raised once per dropped frame is the flood, wearing
  a different hat. Whatever records it must cost O(1) in the number of
  observations, not O(n).

Neither is achievable by adding more log lines.

## 2. Goals / Non-goals

**Goals**

- One place a node records the conditions it believes are wrong, readable long
  after the traffic that caused them stopped.
- Raisable from *anywhere* in the stack — the routing core, a link's receive
  path, the management transport — with no handle threaded to the call site,
  because several of those sites have no owner to thread one from.
- Identical behaviour on `no_std` and `std`, allocation-free on the raise path.
- Bounded in every dimension: rows, bytes per row, and log records emitted.
- Per-node attribution when many nodes share one process (the simulator).

**Non-goals**

- **Detection.** Nothing here decides when a flood is a flood. `AlarmKind`
  names the conditions; a detector lives next to the state it watches.
- **Notification.** No push, no stream, no email. A node holds alarms; a client
  polls. Same reasoning as `GetLogs`.
- **Acknowledgement workflow.** Considered and rejected in §8.
- **Encrypting or authenticating the alarm itself.** It rides the management
  API, which is already authenticated; it adds no trust boundary of its own.

## 3. The model

An alarm is a **latched `(kind, subject)` condition**:

```rust
pub struct Alarm {
    pub kind: AlarmKind,       // closed enum + stable u16 code
    pub subject: Subject,      // Node(NodeId) | Interface(u8) | None
    pub severity: Severity,    // Info < Warning < Critical
    pub first_ms: u64,         // when the condition started
    pub last_ms: u64,          // most recent observation
    pub count: u32,            // how many raises folded in, saturating
    pub detail: heapless::String<DETAIL_CAP>,   // newest rendering
}
```

The row is the condition's *existence*; `count` is its *magnitude*. Splitting
those two is what makes the whole thing bounded — see §4.1.

`Subject` is deliberately not a `Mac`, a `MeshIdentifier`, or a
`wayfinder-auth` fingerprint. `NodeId` holds up to 8 raw bytes, which covers a
6-byte MAC, a 1-byte short address, and enough of a key fingerprint to identify
a key in practice. Two reasons, and the second is the load-bearing one:

1. The management API already takes this line with its `bytes node_id` fields —
   address-family agnostic, rendered by the client.
2. `wayfinder-auth` is one of the most likely future raise sites. A dependency
   on it here would become a cycle the moment it wants to raise an alarm.

## 4. Design

### 4.1 Coalescing is the mechanism, not an optimisation

The dedup key is the whole `(kind, subject)` pair. Raising a condition already
on the board folds into its row: `count` and `last_ms` advance, `detail` is
replaced. **It does not add a row and it does not emit a log record.**

This is what lets a detector be naive. A detector may call `raise` once per
frame, from inside the flood, and the board answers with one row and a count.
Ten thousand raises produce one row and one log line. Without this property
every detector would have to carry its own rate limiter, and every one of them
would carry a slightly different bug.

Splitting the key on *both* halves matters:

- same kind, different subjects → separate rows, so one misbehaving peer can
  never mask another by coalescing into its row;
- same subject, different kinds → separate rows, so a peer doing two wrong
  things is two conditions.

`detail` is last-writer-wins. `first_ms` and `count` already carry the history,
so the useful thing for the detail to carry is the newest observation rather
than whichever happened to be first.

### 4.2 Severity ratchets up, never down

A coalescing raise raises the row's severity to meet it, and never lowers it. A
later, milder observation of a condition must not talk the node down from what
it already saw — an attacker who can make a `Critical` condition also *look*
`Info` could otherwise erase it.

The raise reports which happened: `Raised::{New, Coalesced, Escalated,
Dropped}`. Returning the outcome rather than `()` is what lets the layer above
gate its side effects on it (§4.5), and lets a test assert the board's decision
rather than infer it from the table.

### 4.3 Latched, with staleness computed at read

Nothing expires on a timer. There is no timer to hang one on inside the `no_std`
core, and a board that needed a background task to stay correct would be wrong
on every target with no executor to spare.

Instead `Alarm::is_active(now_ms)` is `now_ms - last_ms <= severity.hold_ms()`,
evaluated by whoever asks. This is the same trick `RateEstimator::rate` uses in
the routing core, and CLAUDE.md's "prefer bounded here-and-now signals" rule is
the same rule.

A stale alarm **stays on the board**. That is the point of latching: an operator
who polls after a burst ended still learns it happened. A snapshot therefore
distinguishes "firing now" from "fired recently and stopped", which auto-expiry
could not.

`hold_ms` is longer for worse severities (1 / 5 / 15 minutes). It is a de-assert
delay, not a guess at duration: the node keeps claiming a condition until it has
been quiet for that long, and being wrong in the "still firing" direction costs
far less than being wrong in the other. A client polling on a slow cadence
cannot miss the serious ones between polls.

### 4.4 Capacity is severity-aware, and that is a security property

The table is fixed-capacity (16 rows on bare metal, 64 on a host). A full board
facing a *new* condition picks a victim: the least severe row, and among those
the stalest. The victim gives way only to something **strictly worse than
itself**.

Both halves of that rule are load-bearing, in opposite directions:

- A critical alarm always lands, so an attacker cannot fill the board with
  cheap `Info` noise and hide a real attack behind it. A naive "drop when full"
  policy has exactly that hole.
- Nothing already held is displaced by more of the same, so a flood of fresh
  subjects cannot scroll a standing alarm off the board. A naive LRU has
  exactly *that* hole.

Either outcome — an eviction or a refusal — increments `dropped`, reported on
every snapshot. A row that silently vanished would be indistinguishable from a
condition that never happened, which is the same reasoning behind
`LogSnapshot::dropped`.

Capacity governs **new** conditions only. A raise for something already tracked
needs no room and always coalesces, so a full board never freezes a standing
alarm at a stale count.

### 4.5 Two layers, so the logic is testable and the ergonomics are ambient

`AlarmBoard` is plain owned state: no globals, no locks, no side effects, and an
explicit `now_ms` on every method. All of §4.1–§4.4 lives there, so it is
deterministic on a virtual clock and testable without a global, a subscriber, or
a running node.

`SharedBoard` wraps one in `wayfinder-log`'s `Lock`, stamps it from
`wayfinder_log::uptime_ms()`, and owns the one side effect: mirroring a **new or
escalated** alarm into the log at `warn!` (or `info!` for `Severity::Info`).

Not `error!`, deliberately. CLAUDE.md reserves `error!` for failures originating
in *this* node and not reachable by arbitrary peer input, and most alarms are
precisely the opposite — a remote party's behaviour is what raises them. The
alarm's own severity travels as a structured field instead.

A *coalesced* raise mirrors nothing, which is the storm-safety property. A
*dropped* raise mirrors nothing either, and that is the less obvious half: a
full board under a storm of fresh subjects is exactly when a per-raise record
would do the most damage. What a drop costs is carried by `dropped`, which is a
count and cannot flood.

The log mirroring also means **this design needs no journal ring of its own.**
The log ring already is the journal, and an alarm's record sits in it next to
the frames that caused it — which is the whole reason both crates must share one
timebase (§4.6).

### 4.6 Why `wayfinder-log` exports `Lock` and `uptime_ms`

Two pieces of `wayfinder-log`'s plumbing went from `pub(crate)` to `pub` rather
than being copied:

- **`uptime_ms`.** A second private copy on the host would be a separate
  `OnceLock<Instant>` fixed at a different first use, so alarm and log
  timestamps would sit on origins skewed by however far apart those two moments
  fell. Correlating an alarm with the records around it is the main thing an
  operator does with one; that skew would be a real bug, and a silent one.
- **`Lock`.** It carries the `critical-section`-versus-`std::sync::Mutex`
  decision and the reasoning about how long a board's interrupts stay masked.
  One copy, not two that can drift.

No cycle: `wayfinder-log` has no in-workspace dependencies.

### 4.7 The ambient board, and why there is a scope

The raise site is the constraint. A detector lives wherever the state it watches
lives — deep in the `batman` engine, in a link's receive path, in
`wayfinder-server`'s authentication check. Threading a board reference to all of
those means changing every signature in between, and on an embedded node several
of those call sites have no owner to thread one from.

So the board is ambient, the way a `tracing` subscriber is: a process-global
`PROCESS_BOARD`, and free functions that target it.

On a real node that is the whole story — a board, or a host running one
`wayfinder-tap`, is one node per process, so the process board *is* the node's
board and nothing ever sets a scope.

The simulator is the exception, and it is not a hypothetical one: it runs many
nodes in one process, each a `PyDriver`, and `sim/scenarios/red_team.py` is the
adversarial scenario this whole feature is shaped for. A single merged board
would answer "somebody saw a flood" — erasing exactly the per-node attribution
that scenario exists to show. `with_board(&board, || node.tick())` restores it.

That is `tracing`'s `Dispatch` model exactly: a global default plus a scoped
override. The scope is host-only (`cfg(not(target_os = "none"))`) — bare metal
has neither threads to scope per nor a thread-local to hang one on, and every
consumer that needs one is a host. It holds an `Arc` rather than a borrowed
reference because the simulator's boards are owned by node objects with no
`'static` lifetime, and a raw pointer would need `unsafe` to justify what a
refcount justifies for free. It restores on `Drop`, so a panicking node's scope
cannot leak into whichever node ticks next.

### 4.8 The raise site

```rust
alarm!(Severity::Critical, AlarmKind::TrafficFlood, peer, "fps={}", 4200);
```

No handle, no clock, no `&mut` anything. The detail renders through a
`core::fmt::Write` that fills the fixed string to capacity and discards the
rest, splitting only on character boundaries — `heapless::String`'s own
`write_str` rejects a whole write that does not fit, which would silently turn a
long detail into *no* detail. Raising an alarm is infallible by construction: a
detail too long is truncated, never rejected.

## 5. Correctness argument and edge cases

- **Bounded work per raise.** A raise is a linear scan of at most
  `ALARM_CAPACITY` rows plus a bounded format. No allocation, no I/O, no
  unbounded loop. Safe to call per frame.
- **Bounded memory.** `ALARM_CAPACITY` rows of `~100` bytes: ~1.6 KiB on a
  board, where it competes with the router for 256 KiB.
- **Bounded log output.** One record per new or escalated alarm. A condition
  can escalate at most twice (`Info → Warning → Critical`), so the lifetime
  record count for one row is at most 3, regardless of observation count.
- **No unbounded counters.** `count` and `dropped` saturate rather than wrap; a
  wrap would silently reorder or understate.
- **Truncation is UTF-8-safe.** The detail lands in a protobuf `string`, so the
  writer walks back to a character boundary. Covered by a test that puts the
  byte budget mid-character deliberately.
- **`first_ms <= last_ms` always**, asserted by `assert_invariants()`.
- **At most one row per `(kind, subject)`**, also asserted — a raise that failed
  to coalesce would be the bug that reintroduces the flood.
- **Scope restoration survives panics**, by `Drop` rather than an explicit
  restore.
- **Re-entrancy.** `scope::current` clones the `Arc` out rather than lending
  from inside the `RefCell`: a raise runs arbitrary formatting code, which could
  re-enter, and a live borrow across that would be a panic instead of an alarm.

## 6. Security considerations

The alarm board is attacker-facing by construction — most of what raises an
alarm is a remote party's behaviour — so the adversary's goals are (a) flood the
node through it and (b) hide a real alarm in it. §4.1 answers the first and §4.4
the second; both are covered by tests rather than left as reasoning.

Two further notes:

- **Alarm contents are metadata only.** Same rule as the logging conventions:
  rates, counts, windows, identifiers — never payload bytes. Reading a node's
  alarms must disclose no more than reading its routing table does.
- **The board is not a trust boundary.** It records what a detector claimed. A
  detector that can be induced to raise a false alarm produces a false alarm;
  nothing here launders that into a stronger claim.

## 7. Observability (the follow-up)

Per CLAUDE.md's "metrics are first-class", the board is exactly the kind of
state an operator and an app on top of the mesh want, and it is *only* useful
once it is readable. The intended path is the `add-metric` one, mechanically:

`GetAlarmsRequest`/`Alarms` in `wayfinder.proto` → `WayfinderDataProvider` →
`RouterAdapter` (which reaches the global directly, exactly as it does for
`GetLogs` — no reference threaded through the router) → `wayfinder-client` → a
TUI tab and the corresponding `wayfinder-web` view.

`Severity` and `AlarmKind` project onto proto enums; `AlarmKind::code` exists so
that projection is not tied to declaration order. `AlarmSnapshot::now_ms` rides
along so a client can compute `is_active` without its own clock, and `dropped`
so a gap stays visible as a gap.

## 8. Alternatives considered

**A board owned by `CentralRouter`.** Philosophically the closest fit — it is
what CLAUDE.md's "state lives in the `no_std` core, never only in the driver"
rule prescribes for metrics, and it gives per-node attribution for free.
Rejected because the raise sites do not line up: the management-API
authentication-failure path in `wayfinder-server`'s transport — one of the two
conditions that motivated this whole feature — holds no router handle, and
neither do the link I/O paths. Threading one to them would change signatures
across four crates to serve a call that must not fail.

**A bare global with no scope.** Simpler, and correct on every real node.
Rejected for one concrete reason: the simulator runs many nodes per process, and
`red_team.py` is the scenario this feature exists for. Merging its nodes' alarms
would break the tool that would otherwise be the best test of it.

**Auto-expiry instead of latching.** Keeps the table to genuinely-current
conditions and self-limits memory. Rejected because a burst that ends before the
operator polls would leave nothing but a log line — reintroducing the exact
problem in §1.

**Latch until acknowledged over the API.** The standard alarm-panel behaviour,
and the strongest "you will not miss this" guarantee. Rejected for now on two
counts: it needs an ack RPC, which pulls the entire read path into a change
meant to be the mechanism alone; and an unattended node — which is most of them
— fills its table with unacked history and then cannot record anything new.
Worth revisiting once the read path exists, as a policy on top of `clear`.

**A separate journal ring of alarm transitions.** Rejected as redundant: the log
ring already is that journal (§4.5), and a second ring would double the fixed
memory cost on the target where it is scarcest to store a strictly weaker
version of records the node already keeps.

**A module inside `wayfinder-log`.** It would share the sync/clock/ring
machinery with no new exports. Rejected because "the logging plumbing" is a
coherent thing and alarms are not part of it; the two exports in §4.6 are a
smaller price than a crate that does two jobs.

## 9. Open decisions

- **Virtual-clock alignment in the simulator.** `SharedBoard::raise` stamps from
  host uptime; `raise_at` exists for a caller holding its own clock, but no
  raise site uses it yet. If the simulator wants its alarms on sim time, the
  clock likely belongs on the board rather than at the call site — deferred
  until a detector exists to need it.
- **Whether `clear` should be reachable over the management API.** It is the
  natural half of an acknowledgement workflow (§8), but only worth adding
  alongside a decision about who is allowed to clear an alarm.
- **`ALARM_CAPACITY` on a host.** 64 is a guess sized against a plausible
  neighbour count, not a measurement. Revisit once real detectors show what the
  steady-state occupancy actually is.

## 10. Key file map

| File | What it holds |
| --- | --- |
| `libs/wayfinder-alarm/src/lib.rs` | `Severity`, `AlarmKind`, `Subject`, `NodeId`, `Raised`, crate docs |
| `libs/wayfinder-alarm/src/board.rs` | `Alarm`, `AlarmBoard`, coalescing / ratchet / eviction / staleness, the truncating writer, `assert_invariants` |
| `libs/wayfinder-alarm/src/global.rs` | `SharedBoard`, `PROCESS_BOARD`, the ambient free functions, `with_board` + its thread-local scope, log mirroring |
| `libs/wayfinder-alarm/src/macros.rs` | the `alarm!` macro |
| `libs/wayfinder-log/src/lib.rs` | re-exports `Lock` and `uptime_ms`, and the note on why |
| `libs/wayfinder-log/src/sync.rs`, `clock.rs` | the widened items themselves |

For the follow-up in §7, the pair to copy the shape of is `GetLogs`:
`libs/wayfinder-protos/protos/wayfinder/v1alpha/wayfinder.proto`,
`libs/wayfinder-protos/src/service.rs`, and `RouterAdapter::get_logs` in
`libs/wayfinder-server/src/adapter.rs`.
