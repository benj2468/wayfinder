# Design: the management API on a 256 KB part

**Status:** Proposed. It records measurements and a recommended order of work
for #75. Nothing here is built. The decision it asks for is in §9.

**Scope:** `bins/wayfinder-wl55jc` (where the management port has to fit),
`libs/wayfinder-log` (ring capacity), `libs/wayfinder-protos` and
`libs/wayfinder-server` (the codec and dispatch the port links), and,
depending on §9, a codec spike. **Not touched:** the wire protocol. Every
option below keeps the management API byte-compatible with
`wayfinder-client`, `wayfinderctl`, the TUI and the web dashboard, and keeps
`rpc_table!`'s declare-once contract.

## 1. Motivation

Design 25 left the WL55 as a LoRa relay with no management port. Without
one, the board:

- cannot be reached by `libs/wayfinder-hil`;
- cannot be enrolled or renew a certificate (design 24);
- is observable only through RTT with a debug probe attached.

#75 put the gap at 28.8 KiB of flash in September, against an older relay
image. This doc re-measures against the image the relay now ships:
- #93's bounded radio waits;
- #94's durable identity;
- #71's float-formatting fix, already on main.

## 2. The budget, measured

All figures are `opt-level = "z"`, fat LTO, profile `wl55jc`, measured with
`size` and `cargo bloat`. The management-port image is the WIP arm from
`bjc/wl55jc-mgmt-port` ported onto #94. It has a real `RecordSettings` store,
the `GetLogs` ring, and a 12 KiB heap, and is linked against a temporarily
widened `memory.x`. The local branch `measure-wl55-mgmt` reproduces it.

| image | flash (text+data) | statics (data+bss) |
|---|---|---|
| relay (#94) | 219,348 | 28,008 |
| relay + management port | **301,140** | **57,176** |
| available | 258,048 (252 KiB; 4 KiB is the identity store) | 65,536 |

So the port does not fit: it is **42.1 KiB over in flash**, and its statics
leave **~8 KiB of stack**. The gap is larger than in September because the
durable store (+14 KiB including its pages) and the ring are now counted.

### 2.1 Where the port's flash goes

`.text` delta, relay → port, by crate:

| crate | Δ KiB | |
|---|---|---|
| `wayfinder_protos` | +23.5 | message types, `handle_router`, response encoding |
| `prost` | +11.9 | the generic codec |
| `std` (core/alloc) | +6.9 | `Vec`/`String` growth, `fmt` behind error strings |
| `embassy_executor` | +6.1 | the mgmt task's poll and the larger main poll |
| `wayfinder_embedded_driver` | +5.6 | `run_once_with_mgmt` (23.5 KiB total, inlined) |
| `wayfinder_alarm` + `wayfinder_log` | +5.8 | `GetAlarms`/`GetLogs` readers |
| `bytes` | +2.3 | prost's buffer trait |

**The protobuf layer (`wayfinder_protos` + `prost` + `bytes`) is 37.7 KiB,
about the size of the whole gap.**

### 2.2 Where the statics go

Of the port's +29 KiB of statics:
- **16,416 bytes is `wayfinder_log::ring::RING`** at its default 256 records;
- 10 KiB is the heap grown from 2 to 12 KiB;
- the rest is the query channel, UART buffers and the mgmt task pool.

## 3. Goals and non-goals

**Goals.**
- A WL55 image that serves the management API, fits flash, and passes `just
  stack-budget-wl55jc`.
- It answers at least the reads `libs/wayfinder-hil` needs and the writes
  enrollment needs (`SetAuth`, `SetTime`, `SetLogLevel`).

**Non-goals.**
- A second wire format.
- Splitting the management API per board in a way a client can observe other
  than a stated refusal.
- Releasing the CM0+. It shares the same flash, so it buys nothing here.

## 4. RAM: size the ring per board

This part is settled and cheap. Design 25 §4.7 already decided it: a 16-record
ring on this board. The `WAYFINDER_LOG_RING_CAPACITY` build knob landed and
was reverted in `720e1c81`, *"until a board uses it"*. The management port is
that board. Restoring the knob at 16 records takes the ring from 16 KiB to
about 2.5 KiB (16 × the 160-byte message cap plus headers). That puts the
stack back near 22 KiB, and the gate passes with room.

It is the first commit of the port, and it does not depend on §5.

## 5. Flash: the levers, measured where possible

### 5.1 Answering fewer request kinds: measured, and not enough

#75 called this "the larger lever and the worse precedent". It has now been
measured. The router facet has 21 request kinds; the other 24 are the CA's
and are never linked on a board. Deleting 10 of the 21 arms from
`handle_router_read`/`handle_router_write` saves **8.1 KiB**.

Prost's decode of the full `WayfinderRequest` oneof and encode of the full
response oneof stay regardless. A further experiment confirmed this: refusing
those kinds at the top of `handle_router` without deleting their arms saved 4
bytes. A dispatcher is not something LLVM prunes by proving a discriminant.

So the route that breaks `rpc_table!`'s invariant buys **under a fifth of the
gap**. **Rejected as the primary lever.** It stays available as a last few KiB
only behind a stated-refusal design, never a missing arm.

### 5.2 A smaller codec on the embedded side: the recommended spike

The codec is the cost. `prost` is a general, `alloc`-based codec: every
message carries generic `merge`/`encode` loops plus `bytes`' buffer
machinery, and every response is built into a `Vec`.

A **no-alloc, codegen-based protobuf implementation** for the embedded server
side is wire-identical by construction, because it is still protobuf from the
same `.proto`. `micropb` is the candidate: `no_std`, fixed-capacity fields and
generated code per message. Host crates keep `prost`. The `.proto` files and
`rpc_table!` stay the single declaration.

What is unknown is the size, and that is what a spike answers:

1. Generate `micropb` types for `WayfinderRequest`, `WayfinderResponse` and
   the router-facet messages, with capacities taken from the board's profile.
2. Implement `handle_router` against them for **one** read (`GetNodeInfo`)
   and **one** write (`SetLogLevel`), behind a feature in a scratch crate.
3. Link both versions into the WL55 measurement image and compare the
   protobuf layer.

**Exit criterion:** if the micropb layer is at least 20 KiB smaller than
prost's 37.7 KiB at full surface, the codec route closes most of the gap and
is worth the dual-codec maintenance. Below that it isn't, and §5.3 has to
carry the gap.

The maintenance cost is real and should be priced before starting. It is a
second set of generated types, and a conformance test (encode with one codec,
decode with the other, for every message) to stop the two drifting. That test
is cheap to write and is the condition for adopting the route at all.

### 5.3 Making the node itself smaller: #72, #73, #74

These benefit every board, which is why they should happen anyway. But none of
them has a measured win of the size this needs:

- **Crypto (#73).** `sha2` is 10.8 KiB, almost all of it `compress512`, which
  is Ed25519's hash. `curve25519_dalek` is 15.0 KiB. A size-optimised SHA-512
  is the obvious first measurement.
- **Routing core (#72).** `wayfinder` is 22.3 KiB and `batman` 12.9 KiB.
  `handle_frame_with_metrics` alone is 15.9 KiB. The split recorded in #25
  would make that measurable per path.
- **Platform (#74).** `embassy_executor` is 15.3 KiB, nearly all of it
  task-poll bodies inlined into `TaskStorage::poll`. The `build_node` change
  in #94 showed how much moving work out of a poll can recover there.
- **`run_once_with_mgmt` is not a lever, despite its size.** It is
  23.5 KiB in one symbol, but `handle_router` is already a separate 14 KiB
  symbol. What the 23.5 KiB holds is the event loop (`handle_link_result`,
  `dispatch`, `poll_due_all`) inlined, which the relay pays as `run_once`
  too: the crate grew only 5.6 KiB with the port. Outlining moves code rather
  than removing it, unless something is duplicated, and nothing here is.

## 6. Correctness and edge cases

- Nothing in §4 or §5 changes what a client sees. A codec swap is checked by
  the cross-codec conformance test. A ring of 16 records changes only how far
  back `GetLogs` reaches, and its batch-byte budget already handles a short
  ring.
- The 12 KiB heap is the row most likely to be wrong. The nRF's full-ring
  `GetLogs` OOM is the failure a small heap invites, and a 16-record ring cuts
  that response's worst case 16-fold. The port should land with a test that
  issues a maximal `GetLogs` against the board through `libs/wayfinder-hil`.

## 7. Security

Unchanged. The embedded management port is unauthenticated by decision
(#57). This board adds one more part with that property; it does not widen
it.

## 8. Alternatives considered

- **Trim request kinds.** See §5.1: measured at 8.1 KiB, and it costs the
  declare-once invariant.
- **A different part.** The WL55JC is already the largest flash in its family,
  and the NUCLEO board has no external flash. Moving the management API off
  the node (e.g. a host tether that proxies it) is design 25's milestone-1
  posture, not a fix.
- **Execute-in-place from external flash.** The board has none.
- **Shrink `max_frame_len` or the capacity profile.** Design 25 §4.2 pinned
  `max_frame_len` to the link's reassembly ceiling for correctness. The
  profile costs RAM, and RAM is not the binding constraint once §4 lands.

## 9. Decision requested

1. **Approve §4 now.** It is independent, small and already designed.
2. **Choose the flash route:**
   - (a) run the §5.2 codec spike, with its 20 KiB exit criterion; or
   - (b) work #72–#74 first, then re-measure.

   The recommendation is **(a)**. The protobuf layer is the only single item
   the size of the gap. #72–#74 are worth doing for every board, but none has
   a measured win near 42 KiB, and §5.3's `run_once_with_mgmt` turned out not
   to be one.

## 10. File map

| File | Change |
|---|---|
| `libs/wayfinder-log/build.rs`, `src/ring.rs` | restore `WAYFINDER_LOG_RING_CAPACITY` (reverted in `720e1c81`) |
| `bins/wayfinder-wl55jc/.cargo/config.toml` | `WAYFINDER_LOG_RING_CAPACITY = "16"` |
| `bins/wayfinder-wl55jc/src/mgmt.rs`, `main.rs`, `identity.rs` | the port, from `bjc/wl55jc-mgmt-port` / `measure-wl55-mgmt`, with `RecordSettings` as the store |
| scratch crate (spike only) | `micropb` codegen for the router facet; cross-codec conformance test |
