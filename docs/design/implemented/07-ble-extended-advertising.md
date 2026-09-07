# Design: Extended BLE advertising for `libs/blue`

**Status:** Implemented (2026-09-06), with the deviations recorded in §11 —
one of which contradicts a non-goal in §2 and is not optional, so read that
section before trusting §2 or §3.1's arithmetic. The *mechanism* shipped in
full; the *validation* did not, and cannot without hardware: every timing
constant and the `MAX_EXTENDED_ADV_DATA_LEN` value remain unmeasured
(§7.1–7.3), which is why `BleSendMode` defaults to `Legacy` and why a real
node's first extended send is still an experiment.

**Scope:** `libs/blue` only (`src/ad.rs`, `src/frame.rs`,
`src/generic_link.rs`, `src/nrf_link.rs`, `src/std_link.rs`). No change to
`libs/wayfinder-link-utils` (the shared `Reassembler`/`FragHeader`/
`pack_header` machinery, whose 4-bit index/count fields and `MAX_FRAGMENTS
= 15` ceiling are untouched — each wire format gets its own instantiation
of the same generic type, per §3.5, rather than a change to the type
itself), no change to `LinkT`/`FrameIo`, no change to `wayfinder-shark`
(its dissector works on the reassembled Ethernet-shaped frame and the
`wf-carrier` ethertype, not per-transport AD framing — grep confirms
nothing in `libs/wayfinder-shark` references BLE AD structures or
manufacturer data).

## 1. Motivation

`libs/blue`'s on-air fragment payload is capped by **legacy** (non-extended)
BLE advertising's 31-byte total advertising-data budget (Core Spec, Vol 6,
Part B, §2.3.4.9), enforced today by `ad::MAX_LEGACY_ADV_DATA_LEN = 31`.
After this crate's own framing is subtracted — 4 bytes of AD-structure
header (`ad::AD_HDR_LEN`), 2 bytes of fragment header (`FRAG_HDR_LEN`), and
6 bytes of embedded sender `Mac` carried in *every* fragment
(`frame::ORIGIN_LEN`, needed because BlueZ draws a fresh random advertiser
address per registration — see `libs/blue/CLAUDE.md`) — each fragment
carries only **19 bytes** (`frame::FRAG_PAYLOAD`) of actual frame content.

That is small enough to matter for this mesh's actual traffic:

| frame | size | fragments today (19 B/fragment) | BlueZ dwell cost (150 ms/fragment) | nRF dwell cost (~80 ms/fragment) |
|---|---|---|---|---|
| lazy-auth OGM (header + fingerprint TVLV + signature TVLV) | ~100 B | 6 | 900 ms | 480 ms |
| full-cert OGM | ~250 B | 14 | 2.1 s | 1.12 s |

A full-cert OGM's 14 fragments already sit one fragment below
`wayfinder-link-utils::MAX_FRAGMENTS` (15) — the wire format's 4-bit `count`
field ceiling. Any frame content beyond `15 * 19 = 285` bytes cannot be sent
over this link *at all* today (`frame::MAX_REASSEMBLED_LEN = 280` is chosen
to stay under that with a few bytes of margin), and `send` blocks the
driver's event loop for `dwell × fragment_count` on both backends — the
single largest per-message latency cost this link has.

Bluetooth 5's **extended advertising** raises the effective per-advertisement
budget well past 31 bytes. Both backends' underlying libraries already
expose it:

- **`nrf-softdevice`** (pinned to the `s140` SoftDevice variant, per
  `libs/blue/Cargo.toml:82` / `libs/wayfinder-nrf/Cargo.toml:95`) defines
  `NonconnectableAdvertisement::ExtendedNonscannableUndirected { set_id,
  anonymous, adv_data }` in `peripheral.rs`, gated
  `#[cfg(any(feature = "s132", feature = "s140"))]` — satisfied today. The
  S140 bindings (`nrf-softdevice-s140-0.1.2/src/bindings.rs`) define
  `BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_MAX_SUPPORTED = 255` (238 for
  connectable extended) versus `BLE_GAP_ADV_SET_DATA_SIZE_MAX = 31` for
  legacy — an ~8x larger per-advertisement budget on the exact chip already
  targeted.
- **`bluer` 0.17.4**'s `Advertisement` struct (`src/adv.rs`) has a
  `secondary_channel: Option<SecondaryChannel>` field (`OneM`/`TwoM`/`Coded`)
  — BlueZ's D-Bus knob for registering an extended, rather than legacy,
  advertising set.

Neither backend uses either of these today. `libs/blue/CLAUDE.md` currently
states there was "no path to extended advertising's larger per-PDU budget
without deeper, harder-to-verify-without-hardware changes" — that statement
is stale: the API surface exists on both sides and is a small, mechanical
change on the transmit side (see §3). What's actually unresolved is real
hardware validation, not API availability — which is why this is a scoping
document, not an implementation.

## 2. Goals / Non-goals

**Goals**
- Raise the extended path's per-fragment payload (`frame::
  FRAG_PAYLOAD_EXTENDED`, §3.1) enough that a lazy-auth OGM fits in a
  **single** fragment and a full-cert OGM fits in **one or two**, cutting the
  `dwell × fragment_count` cost proportionally (e.g. a full-cert OGM's BlueZ
  cost from 2.1 s to ≤300 ms at 2 fragments).
- Preserve on-air interop between `NrfBleLink` and `StdBleLink` — both
  backends must speak the same framing, the same design constraint the
  existing legacy format already lives under.
- Preserve `frame::ORIGIN_LEN`-based reassembly keying exactly as-is: the
  BlueZ RPA-per-registration behavior that motivated it is unrelated to
  legacy vs. extended advertising, so it stays regardless of this change.
- Keep the change mechanically small: new constants in `ad.rs`/`frame.rs`,
  a new advertisement variant in `nrf_link.rs`'s `send`, a new field on
  `std_link.rs`'s `build_advertisement`, and (per §3.5) a second
  `Reassembler` instance plus a one-byte mode-tag demux in `generic_link.rs`
  and `nrf_link.rs`'s `recv` — the one piece of new control flow this
  design needs, isolated to a single dispatch point.
- Let a node run both formats simultaneously via a per-node `BleSendMode`
  config (§3.5), so no fleet-wide flag day is required — an operator
  upgrades nodes to `Both` (later `Extended`) opportunistically, and any
  not-yet-upgraded peer keeps working throughout.

**Non-goals**
- **Not chasing the 1650-byte theoretical maximum.** That figure is the
  upper bound across chained `AUX_ADV_IND` PDUs a controller *could* support;
  neither backend's library reports anywhere near it as a floor — SoftDevice
  S140's own ceiling is 255 bytes nonconnectable / 238 connectable, and
  BlueZ's practical ceiling is whatever the *host's specific controller*
  reports via `max_advertisement_length`, which is not guaranteed to be
  anywhere close to 1650 on arbitrary hardware. This design targets a modest,
  conservative budget (see §3) comfortably under both ceilings, not the
  theoretical maximum.
- **Not increasing `MAX_FRAGMENTS`** or touching `wayfinder-link-utils`'s
  4-bit index/count wire encoding. This design shrinks fragment *count* for
  a given frame; it does not need more addressable fragments.
- **Not building a *live* capability-negotiation handshake between peers.**
  `libs/blue` is a connectionless, fire-and-forget broadcast medium by
  design — no ACK, no retry, no round trip in the shared `LinkT` trait
  (`feedback_minimal_link_abstraction`: this project deliberately keeps that
  trait minimal). There is no wire mechanism to ask a peer "can you hear
  extended advertising?" before sending it, and this design doesn't add one.
  What it does add — see §3.5 — is a **static, locally-configured send
  policy** (legacy / extended / both) plus wire-level tagging so a receiver
  can demux either format without needing to already know which one is
  coming. That's a per-node config decision an operator makes, not a
  negotiation between nodes.
- **Not required to change `frame::MAX_REASSEMBLED_LEN` (280)** as part of
  this work. A larger `FRAG_PAYLOAD` alone already collapses fragment counts
  dramatically at the existing frame-size ceiling; raising the ceiling
  itself is a separate, independent decision better made once real airtime
  numbers exist for the larger PDU size.
- **Not a rollout/migration plan for a live deployed mesh.** This document
  scopes the mechanism (§3.5) and a two-phase rollout shape (§5); §9's open
  decisions cover what a real mixed-fleet rollout would still need pinned
  down, but designing that rollout in full is left to whoever picks this up
  next, once real hardware answers §7's open questions.

## 3. Design

### 3.1 New constants

`ad.rs` keeps `MAX_LEGACY_ADV_DATA_LEN = 31` (still the value the crate's
own tests and any future legacy fallback would reference) and adds a
parallel extended constant:

```rust
/// Conservative total advertising-data budget for one *extended* BLE
/// advertisement, well under both backends' reported ceilings (SoftDevice
/// S140: 255 nonconnectable; BlueZ: whatever the host controller's
/// `max_advertisement_length` reports, unvalidated on real hardware as of
/// this writing). Not the theoretical 1650-byte maximum — see design 07 §2.
pub const MAX_EXTENDED_ADV_DATA_LEN: usize = 200;

pub const MAX_EXTENDED_FRAGMENT_LEN: usize = MAX_EXTENDED_ADV_DATA_LEN - AD_HDR_LEN;
```

`200` is a starting proposal, not a validated number — see the open
question in §7 about actually measuring the lowest common ceiling across
real hardware before locking this in. `frame.rs`'s derived constants follow
mechanically from whichever AD-length constant is selected, minus one more
byte than before for the mode tag §3.5 introduces:

```rust
pub(crate) const MODE_TAG_LEN: usize = 1;
pub(crate) const FRAG_PAYLOAD_LEGACY: usize =
    ad::MAX_LEGACY_FRAGMENT_LEN - MODE_TAG_LEN - FRAG_HDR_LEN - ORIGIN_LEN;
    // 27 - 1 - 2 - 6 = 18
pub(crate) const FRAG_PAYLOAD_EXTENDED: usize =
    ad::MAX_EXTENDED_FRAGMENT_LEN - MODE_TAG_LEN - FRAG_HDR_LEN - ORIGIN_LEN;
    // 196 - 1 - 2 - 6 = 187
```

At `FRAG_PAYLOAD_EXTENDED = 187`: a ~100-byte lazy-auth OGM fits in **1**
fragment (was 6 at legacy's 19); a ~250-byte full-cert OGM fits in **2**
(was 14). `MAX_FRAGMENT_BYTES` grows to
`MODE_TAG_LEN + FRAG_HDR_LEN + ORIGIN_LEN + FRAG_PAYLOAD_EXTENDED`
accordingly, and `RawReport::data`'s backing array is sized for the larger
of the two so it can hold either format's fragment — a size-only change, no
logic change, since `RawReport::new`'s clamp-to-capacity behavior is already
length-agnostic (`frame.rs`).

Note `FRAG_PAYLOAD_LEGACY` drops from today's 19 to 18 — the mode tag costs
one byte even in the unchanged legacy path. This is the one place this
design touches the *existing*, already-deployed wire format, not just adds
a new one alongside it — see §3.5 and §5 for why that's still the right
trade and what it implies for rollout.

`ad::build_ad_structure`/`find_mesh_fragment` need almost no logic change:
both already operate on a length-prefixed AD structure up to `u8::MAX`
(`ad::MAX_FRAGMENT_LEN`), independent of whether the surrounding
advertisement is legacy or extended. The one addition is the mode tag
§3.5 introduces — a single leading byte inside the bytes `find_mesh_fragment`
already returns, peeled off by a new, trivial helper before the existing
`parse_fragment_with_origin` runs, so the wire-scanning logic itself is
unchanged.

### 3.2 `nrf_link.rs`: make the `send` path format-aware

`LinkT::send` (`nrf_link.rs:213-245`) today unconditionally builds one
legacy advertisement per fragment:

```rust
let advertisement = NonconnectableAdvertisement::NonscannableUndirected {
    adv_data: &ad_buf[..n],
};
```

Per §3.5, this becomes format-driven by a configured `BleSendMode` (`Legacy`
/ `Extended` / `Both`): for each mode `send` is configured to use, the frame
is fragmented independently at that mode's own `FRAG_PAYLOAD` and each
fragment goes out as that mode's advertisement variant —

```rust
// Legacy fragment:
NonconnectableAdvertisement::NonscannableUndirected { adv_data: &ad_buf[..n] }
// Extended fragment:
NonconnectableAdvertisement::ExtendedNonscannableUndirected {
    set_id: 0,
    anonymous: false,
    adv_data: &ad_buf[..n],
}
```

`ad_buf` is sized for the larger, extended case
(`ad::MAX_EXTENDED_ADV_DATA_LEN`) regardless of which mode(s) are active.
`set_id: 0` is safe to hard-code: this link only ever runs one advertising
set of each kind at a time (mirroring how `peripheral.rs`'s single `static
mut ADV_HANDLE` is already shared, not per-set), and `anonymous: false`
preserves today's identity semantics — this crate never relied on
SoftDevice's anonymous-advertising mode, and `frame::ORIGIN_LEN` already
carries identity at the application layer regardless of what the medium's
own address does. `BleSendMode::Both` costs roughly double the airtime of
`Legacy`-only per frame (two independent fragmentation passes, two sets of
advertising sessions) — an explicit, operator-visible trade, not a hidden
cost, and the one this design pays during a transition period in exchange
for never needing a synchronized flag day (§3.5, §5).

**The receive side needs no change to *listen* for extended PDUs at all,
only to demux them once heard.** `ble_scan_task`'s `ScanConfig`
(`nrf_link.rs:165-171`) is built with `..Default::default()` for every field
it doesn't explicitly set, and `nrf-softdevice`'s
`ScanConfig::default()` (`central.rs`) already sets `extended: true`:

> "If true, the scanner will accept extended advertising packets. If false,
> the scanner will not receive advertising packets on secondary advertising
> channels, and will not be able to receive long advertising PDUs."

So `NrfBleLink` has been extended-advertising-capable on receive since day
one; only the transmit variant was ever legacy-only. `central::scan`'s
report callback already hands `find_mesh_fragment` a single assembled
`report.data` slice regardless of how many air-interface PDUs the
SoftDevice chained to deliver it — no reassembly-of-reassembly logic is
needed at this layer.

`AdvConfig`'s `primary_phy`/`secondary_phy` (`Config::default()`, both `M1`)
are left unchanged as a first pass. Extended advertising's *primary* channel
is restricted by the Core Spec to `M1` or `Coded` (never `M2`) regardless;
the *secondary* channel (which actually carries the larger payload) could
use `M2` for extra throughput at the cost of requiring `M2` support on
whatever's listening — left as a tuning knob for later, not adopted here,
so this change's first cut changes only the data budget, not the radio PHY.

### 3.3 `std_link.rs`: request extended advertising from BlueZ, per mode

`build_advertisement` (`std_link.rs:132-145`) becomes mode-aware the same
way `nrf_link.rs`'s `send` does: a legacy-mode registration is built exactly
as today, and an extended-mode registration adds one field:

```rust
Advertisement {
    advertisement_type: AdvertisementType::Broadcast,
    manufacturer_data: BTreeMap::from([(MESH_COMPANY_ID, fragment.to_vec())]),
    timeout: Some(advertise_dwell),
    min_interval: Some(ADVERTISING_INTERVAL),
    max_interval: Some(ADVERTISING_INTERVAL),
    secondary_channel: Some(bluer::adv::SecondaryChannel::OneM), // extended only
    ..Default::default()
}
```

`SecondaryChannel::OneM` matches `nrf_link.rs`'s unchanged `secondary_phy:
Phy::M1` default — both sides should agree on PHY, same as they already
agree on `ADVERTISING_INTERVAL`/`ADV_INTERVAL_625US`. Under `BleSendMode::
Both`, `BluerAdvertiser::advertise` registers and holds both forms in turn
for each fragment of each mode's own fragmentation pass, same as §3.2's nRF
side. Everything else in `std_link.rs` — `mesh_monitor()`'s
duplicate-filtering setup, `DiscoveryFilter { duplicate_data: true, .. }`,
the property-change-driven receive path in `scan_once`/`read_mesh_report`
— is transport-agnostic to legacy vs. extended and needs no change beyond
the mode-byte demux §3.5 adds at the point fragment bytes are handed to the
reassembly layer: BlueZ hands back whatever `ManufacturerData` bytes it
assembled from the air, the same way regardless of PDU type.

### 3.4 What does *not* need to change

- `wayfinder_link_utils::Reassembler`/`FragHeader`/`pack_header`: untouched,
  per Scope above — each mode gets its own `Reassembler` instantiation
  (§3.5), so nothing about that crate's generic machinery changes.
- `addr.rs` (`BleAddr`): unaffected — it was already diagnostics-only, not
  load-bearing for reassembly.
- `ad::build_ad_structure`/`find_mesh_fragment`'s core AD-structure framing
  (length/type/company-id scanning): unchanged, per §3.1.

### 3.5 Running both wire formats concurrently, tagged and demuxed

This is the mechanism that avoids the flag-day problem in the original
version of this document: legacy and extended are treated as **two
independent, simultaneously-live formats**, not one format with a size that
varies per node.

**Why a bare size flag isn't safe on its own.** `wayfinder_link_utils::
Reassembler::accept` places each fragment's bytes at `hdr.index as usize *
FRAG_PAYLOAD` (`lib.rs:221`) — `FRAG_PAYLOAD` is a compile-time const
generic, not a value carried in the 2-byte fragment header. A receiver
built around one `FRAG_PAYLOAD` has no way to correctly reassemble
fragments a peer cut at a *different* `FRAG_PAYLOAD`: the offsets would be
wrong, and nothing in the header says otherwise. So the two formats need
their own `Reassembler` instantiations, each internally consistent, and a
way to tell which incoming report belongs to which.

**The tag.** One new leading byte inside the Manufacturer-Specific-Data
payload, after `company_id` and before the existing `[frag_header][origin]
[body]` blob:

```text
[len][0xFF][company_id LE][mode: u8][frag_header][origin][body]
                            ^^^^^^^^ new
```

`mode` is a small enum (`Legacy = 0`, `Extended = 1`), read by a new
`ad::split_mode_tag`-style helper immediately after `find_mesh_fragment`
returns the manufacturer-data bytes, before either backend's scan path
calls `parse_fragment_with_origin`. This costs `MODE_TAG_LEN = 1` byte in
*both* formats (§3.1) — a real, if small, cost paid by the existing legacy
format too, which is the trade-off called out there.

**Two `Reassembler`s, one demux point.** `BleLink`/`NrfBleLink` each hold
`legacy: Reassembler<Mac, MAX_REASSEMBLIES, FRAG_PAYLOAD_LEGACY,
MAX_REASSEMBLED_LEN>` and `extended: Reassembler<Mac, MAX_REASSEMBLIES,
FRAG_PAYLOAD_EXTENDED, MAX_REASSEMBLED_LEN>` side by side. `recv`'s report
loop reads the mode tag first and feeds the rest of the fragment to
whichever table matches — the only new control flow in either backend's
`recv`, and it's a two-way `match`, not new radio I/O.

**Send policy: a per-node config, `BleSendMode`.**

```rust
pub enum BleSendMode {
    /// Transmit legacy-format advertisements only (today's behavior, plus
    /// the mode tag). Every peer, upgraded or not, receives every frame.
    Legacy,
    /// Transmit extended-format only. Smallest fragment count and airtime,
    /// but a peer whose local controller cannot receive extended PDUs
    /// never hears this node at all — see §7.1 before choosing this.
    Extended,
    /// Transmit both, independently fragmented at each format's own
    /// `FRAG_PAYLOAD`. Roughly 2x the airtime of `Legacy` alone, paid
    /// deliberately during a rollout so every peer keeps working
    /// regardless of whether it has been confirmed extended-capable yet.
    Both,
}
```

Exposed the same way `BleLinkParams::advertise_dwell` already is — a
deployment-time config value, not a runtime-negotiated one (§2's non-goal
on live negotiation still holds: nothing asks a peer which mode it wants,
an operator decides).

**What this buys, concretely:** once every node in the mesh has taken the
(comparatively low-risk) update that adds the mode tag to the existing
legacy format — a wire change, but not a PDU-type change, so it doesn't
depend on any node's extended-advertising hardware support — further
rollout of extended advertising becomes fully incremental. Each node
independently flips its own `BleSendMode` to `Both` (safe net-positive: it
gains extended-format reception wherever a peer's controller supports it,
loses nothing, at the cost of extra airtime) and, once every peer in range
is confirmed capable, to `Extended` (dropping the legacy copy and its
airtime cost entirely). No two nodes' upgrades are coupled to each other's
timing. §5 restates this as the two-phase rollout.

Receiving both formats needs no second scan loop on either backend — as
§3.2/§3.3 note, the physical scan already surfaces both PDU types
(assuming controller support, §7.1); this section is purely about what
happens in software once a report arrives.

## 4. Correctness / edge cases

- **A frame that fits in one fragment today still fits in one fragment.**
  Nothing about extended advertising changes single-fragment framing; it
  only raises the point at which `frame::fragment_count` needs a second
  fragment at all.
- **`MAX_FRAGMENTS` (15) is never approached by realistic traffic after this
  change.** At `FRAG_PAYLOAD_EXTENDED = 187`, `MAX_FRAGMENTS *
  FRAG_PAYLOAD_EXTENDED = 2805` bytes — far past any OGM this mesh sends —
  removing the near-miss motivation in §1 as a live concern (independent of
  whether `MAX_REASSEMBLED_LEN` itself is ever raised).
- **A node whose local controller cannot do extended advertising can still
  fully interoperate**, as long as at least one side (or both, transiently)
  is configured `BleSendMode::Legacy` or `Both` (§3.5) — this is the actual
  point of running both formats rather than cutting over. The residual risk
  is narrower than the original all-or-nothing version of this document: a
  node permanently stuck `Extended`-only (by misconfiguration) is invisible
  to an incapable peer with no link-layer signal of why, same failure mode
  as before, but that's now an operator misconfiguration, not an inherent
  property of adopting extended advertising at all.
- **A malformed or unrecognized mode tag** (neither `Legacy` nor `Extended`,
  e.g. a future third mode this receiver predates) is dropped at the demux
  point (§3.5), the same "fail closed on garbage" posture
  `find_mesh_fragment`/`parse_fragment` already take for other malformed
  input from the air.
- **Reassembly correctness is untouched.** `frame::ORIGIN_LEN`'s embedded
  `Mac`-keyed reassembly does not care how many fragments a message split
  into or what advertising mode carried them; the existing interoperability
  argument in `libs/blue/CLAUDE.md` (BlueZ's RPA rotates per registration
  regardless of PDU type) applies identically here.

## 5. Migration / versioning

Thanks to §3.5's tagged dual-format design, this is a **two-phase rollout**,
not a flag day — the two phases have very different risk profiles and are
worth keeping distinct:

**Phase 1 — add the mode tag to the existing legacy format, fleet-wide.**
This changes the on-air *bytes* of the format every node already speaks
(`FRAG_PAYLOAD_LEGACY` 19 → 18, §3.1) but not the PDU *type* — every node
stays on ordinary legacy advertising, so it depends on nothing about a
node's extended-advertising hardware support. This is still a coordinated
update (an old node's parser and a new node's tagged bytes disagree on
layout, the same "must move together" problem the original version of this
document described for the whole change), but it is a much lower-risk one:
no new radio mode, no new hardware dependency, just a one-byte reshuffle of
an already-well-understood format. This phase is the prerequisite that
makes Phase 2 flag-day-free.

**Phase 2 — opportunistic per-node adoption of extended advertising.**
Once every node speaks the tagged format, an operator flips individual
nodes' `BleSendMode` from `Legacy` to `Both` whenever convenient — this is
strictly additive from that node's perspective (it starts also sending an
extended copy; every existing peer still gets the legacy copy unchanged)
and never depends on any other node's state or timing. Once *every* node in
a given radio neighborhood is confirmed receiving extended PDUs correctly
(§7.1), senders there can move to `Extended`-only to stop paying `Both`'s
airtime cost. Nothing in Phase 2 requires a single fleet-wide cutover
instant; it can proceed node-by-node, indefinitely, at whatever pace an
operator is comfortable validating.

**What doesn't change from the original analysis:** a node's local BLE
controller either can or cannot receive extended PDUs at the hardware
level, full stop — no software change here makes an incapable radio capable
(§7.1). What Phase 1 + `BleSendMode::Both` removes is the need to *already
know, fleet-wide and in advance*, which nodes are capable before shipping
anything — capability can be confirmed and adopted incrementally instead,
with the legacy path as a live fallback throughout rather than a thing that
has to be abandoned all at once.

## 6. Security considerations

None beyond what already applies to the existing legacy-advertising format:
payloads on this medium are never encrypted (per `wayfinder-auth`'s
"authenticity + segregation only" model, unaffected by advertising mode),
and `MESH_COMPANY_ID = 0xFFFF` marker-based filtering is unchanged. Extended
advertising does not add or remove any authentication surface — a member
node's OGM signature verification happens identically regardless of which
PDU type carried the bytes.

## 7. Feasibility unknowns (why this is scoped, not implemented, yet)

**Update (2026-09-06): §7.0 below records an API-level verification pass done
against the exact pinned dependency revisions. It closes the parts of items
1–3 that could be settled by reading the libraries, and leaves standing only
the parts that genuinely need hardware.**

### 7.0 What an API-level pass confirmed

Read against the versions this workspace actually pins — `nrf-softdevice` at
git rev `b0ac850` (`Cargo.lock`) with the `s140` feature, and `bluer` 0.17.4 —
in the same "confirmed by reading the API, not assumed" spirit
`libs/blue/CLAUDE.md` applies to the legacy 31-byte figure:

- **The nRF transmit variant §3.2 names exists and is reachable.**
  `NonconnectableAdvertisement::ExtendedNonscannableUndirected { set_id,
  anonymous, adv_data }` is defined in `nrf-softdevice`'s `ble/peripheral.rs`
  behind `#[cfg(any(feature = "s132", feature = "s140"))]`, and maps to
  `BLE_GAP_ADV_TYPE_EXTENDED_NONCONNECTABLE_NONSCANNABLE_UNDIRECTED`. `s140`
  is already enabled in `libs/blue/Cargo.toml`, so §3.2's snippet compiles as
  written — no feature change, no dependency bump.
- **The nRF receive path is already sized for extended reports.**
  `central::scan`'s static scan buffer is `BUF_LEN = 256` bytes, and
  `ScanConfig::default()` sets `extended: true` (both in
  `nrf-softdevice`'s `ble/central.rs`). S140's own
  `BLE_GAP_SCAN_BUFFER_EXTENDED_MIN` is 255, so the buffer clears the
  minimum. This is a stronger version of what §3.2 already claimed: the
  receive side is not merely willing to accept extended PDUs, it has room for
  a full-size one.
- **255 bytes is a hard ceiling on both halves, and chaining is not on the
  table.** S140's bindings give
  `BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_MAX_SUPPORTED = 255` on transmit and
  `BLE_GAP_SCAN_BUFFER_EXTENDED_MAX_SUPPORTED = 255` on receive — the latter
  against a spec maximum (`BLE_GAP_SCAN_BUFFER_EXTENDED_MAX`) of 1650. The
  SoftDevice does not support chained `AUX_CHAIN_IND` reassembly at all, so
  §2's "not chasing the 1650-byte theoretical maximum" non-goal is not merely
  conservative — it is the only option on this radio, and no
  reassembly-of-reassembly logic can ever be needed at this layer because
  the stack will never deliver more than one buffer's worth.
- **The BlueZ side's fields and probes exist as §3.3/§9.1 assume.**
  `bluer::adv::Advertisement::secondary_channel:
  Option<SecondaryChannel>` (`OneM`/`TwoM`/`Coded`) is a real field, and the
  runtime probe §9.1 calls for is
  `Adapter::supported_advertising_capabilities()` →
  `Capabilities::max_advertisement_length`, alongside
  `Adapter::supported_advertising_secondary_channels()`. Both back
  **optional** D-Bus properties on `LEAdvertisingManager1`, which is itself
  the useful signal: a controller with no extended-advertising support
  reports neither, so `None` is the capability answer rather than an error to
  interpret.
- **`set_id: 0` is not merely safe, it is the only legal value.**
  S140 defines `BLE_GAP_ADV_SET_COUNT_MAX = 1` — one advertising set, full
  stop. This confirms §3.2's hard-coded `set_id: 0` and, more importantly,
  pins down what `BleSendMode::Both` can mean on the nRF backend: the legacy
  and extended passes must run **sequentially through the one set**, never
  concurrently. That is what §3.2's per-mode loop already does, so no design
  change follows — but an implementer must not "optimize" it into two
  parallel advertising sets, which this radio cannot do.

**A structural airtime win §1 does not claim.** Legacy advertising repeats the
whole 31-byte payload on all three primary channels every advertising event.
Extended advertising puts only a small `ADV_EXT_IND` pointer on the three
primary channels and carries the payload once, on a secondary channel, in
`AUX_ADV_IND`. So the larger payload is not just fragmented less — the bytes
themselves stop being transmitted three times. The per-frame airtime
improvement is therefore better than the fragment-count ratio in §1's table
alone suggests. This cuts the other way for reception, though, and is part of
why item 2 below still stands: a scanner now has to catch the primary-channel
pointer *and* follow it to the secondary channel, which is a different
capture probability than catching one self-contained legacy PDU.

### 7.1–7.4 What still needs hardware

1. **Real controller support on the *BlueZ* end is still unconfirmed**, and
   is the only capability question §7.0 could not close: not every Linux
   host's controller supports LE extended advertising (needs a BT5-capable
   controller plus a recent enough kernel/BlueZ). The nRF end's capability is
   now settled at the API level (§7.0) but still unexercised on a board.
   Querying and logging `supported_advertising_capabilities()` /
   `supported_advertising_secondary_channels()` at `StdBleLink::new`
   startup, on the actual host `bins/wayfinder-tap` deploys to, remains the
   first concrete step before writing any of §3's code. As a pre-code
   one-liner on a deployment-target host:

   ```console
   $ busctl get-property org.bluez /org/bluez/hci0 \
       org.bluez.LEAdvertisingManager1 SupportedCapabilities
   ```

2. **No `btmon`/hardware validation exists for extended advertising's
   timing behavior on this project's radios**, unlike legacy advertising,
   which already had two real bugs found and fixed this way (the 1280 ms
   default-interval bug, the per-registration RPA-rotation bug — both
   documented in `libs/blue/CLAUDE.md`). `ADV_EVENTS_PER_FRAGMENT`,
   `advertise_dwell`, and `ADVERTISING_INTERVAL` were all tuned against
   legacy advertising's timing; nothing here says they carry over unchanged
   to extended PDUs, which have materially different air-interface timing
   (a primary-channel PDU pointing at a secondary-channel `AUX_ADV_IND`
   rather than one immediate broadcast). **This is now the largest remaining
   unknown in this document** — §7.0 removed the capability questions but
   changes nothing about timing, and the two bugs cited above are the
   precedent for why that matters.
3. **The `MAX_EXTENDED_ADV_DATA_LEN = 200` proposed in §3.1 is still a
   guess** — but a better-bounded one after §7.0. The nRF ceiling is now a
   known 255, so 200 is confirmed safe on that end with headroom; what
   remains unmeasured is the *BlueZ host controller's*
   `max_advertisement_length`, which is the binding constraint and could in
   principle come back below 200. Measure it (item 1's `busctl` line) before
   fixing the constant. Note that if the measurement comes back at 255 on
   both ends, the value is still worth leaving below the ceiling rather than
   at it, so a future third mode tag or a scan-response byte has somewhere
   to go.
4. **Phase 1 (§5) is still a coordinated fleet-wide update, even though it
   doesn't touch PDU type.** It's lower-risk than a full flag day, but it's
   not zero-risk: every node's parser must agree on the tagged layout before
   any node starts sending it. Sequencing that rollout (all-at-once vs.
   staged, and how a node signals it's ready) is left open (§9).

## 8. Alternatives considered

- **Increasing `MAX_FRAGMENTS`'s wire encoding instead of the per-fragment
  payload** (e.g. widening `pack_header`'s nibbles to a wider count field).
  Rejected as the wrong lever: it would let a frame span more legacy
  fragments without raising the per-fragment 19-byte payload, which does
  nothing for the `dwell × fragment_count` latency cost that's the actual
  problem in §1 — more small fragments is strictly worse for airtime and
  latency than fewer larger ones.
- **Jumping straight to the 255-byte SoftDevice ceiling** rather than a
  conservative 200. Rejected for this scoping pass: BlueZ's actual ceiling
  on arbitrary host hardware is unknown and could be lower, and picking the
  tightest number that still comfortably fits realistic OGM sizes (§3.1)
  leaves headroom without needing to already know the true minimum across
  every deployment target.
- **Doing nothing and living with 19-byte fragments.** Rejected as the
  starting premise of this document — the 14-fragment, 2.1-second full-cert
  OGM cost on BlueZ is a real, measured-in-comments latency problem (§1),
  and both backends' underlying libraries already support a substantially
  better number with a small, mechanical change.
- **A bare per-node size flag with one shared `Reassembler`, no mode tag.**
  The first version of this document proposed exactly this, framed as
  requiring a synchronized flag day. Rejected on closer inspection of
  `wayfinder_link_utils::Reassembler::accept`: since fragment placement is
  `index * FRAG_PAYLOAD` with `FRAG_PAYLOAD` fixed at compile time and never
  carried on the wire, a receiver built for one `FRAG_PAYLOAD` cannot
  correctly reassemble a peer's fragments cut at a different one — this
  isn't just a rollout-friendliness question, it's a correctness bug
  waiting to happen the moment two differently-configured nodes are on the
  same mesh even briefly. §3.5's two-`Reassembler`s-plus-tag design is the
  fix, not a nicety.
- **A pure flag day** (§5's phase 2 without phase 1 — commit every node to
  extended-only in one coordinated cutover). Rejected as strictly worse
  than the two-phase rollout once the tag makes the latter possible: a flag
  day requires confirming every node's hardware capability *in advance and
  all at once*, with no fallback if one turns out incapable; the phased
  approach confirms capability node-by-node with the legacy path as a live
  safety net throughout.
- **Distinguishing formats by a second `company_id` value instead of an
  explicit mode byte** (e.g. `0xFFFE` for extended, `0xFFFF` for legacy).
  Considered and not adopted: `0xFFFF` is meaningful because it's the
  Bluetooth SIG's specific reserved-for-testing value (`ad.rs`'s own doc
  comment); a second private value doesn't carry the same justification and
  would need its own explanation for why *that* number is safe to use
  unregistered. An explicit mode byte inside the payload is one byte more
  per fragment but self-documenting and trivially extensible to a third
  mode later without relitigating "which id is safe to squat on."

## 9. Open decisions for the implementing session

1. **Measure, don't guess, the real cross-hardware ceiling** before fixing
   `MAX_EXTENDED_ADV_DATA_LEN`'s value (§7.3) — query `bluer`'s
   `max_advertisement_length` on the actual deployment-target host
   controller(s), and confirm real nRF52840 hardware negotiates extended
   advertising successfully at the chosen size, before writing the constant
   change in §3.1.
2. **Whether `secondary_phy`/`SecondaryChannel` should move to `M2`** for
   extra throughput once basic extended advertising is validated at `M1`,
   or stay at `M1` for broader compatibility. Not decided here (§3.2).
3. **How Phase 1's mode-tag rollout (§5) is itself sequenced** across a
   real deployed mesh — whether it needs its own coordinated cutover or can
   tolerate a transitional mix of tagged and untagged nodes (which would, in
   turn, need *its own* backward-compat handling, since an untagged legacy
   sender is indistinguishable from a malformed tagged one without a further
   convention). Simplest option: Phase 1 ships as a single required firmware
   update with no wire-compat straddle, since it doesn't depend on any
   hardware validation the way Phase 2 does. Confirm this is acceptable
   given actual deployment size before implementing.
4. **Whether `frame::MAX_REASSEMBLED_LEN` (280) should also grow**, now that
   far fewer fragments are needed to reach it. Left as a separate, later
   decision (§2) rather than bundled into this change.
5. **Re-tuning `advertise_dwell`/`ADV_EVENTS_PER_FRAGMENT`/`ADVERTISING_INTERVAL`
   for extended PDU timing** (§7.2) — needs its own `btmon` capture campaign
   against real hardware, mirroring how the legacy values were tuned; not
   assumed to carry over unchanged.
6. **Default `BleSendMode`** for a freshly-updated (Phase 1 only) node before
   any operator opts it into Phase 2 — should default to `Legacy` (safest,
   no behavior change until explicitly opted in) rather than `Both`.
   Recommended but not locked in here.

## 10. Key file map

- `libs/blue/src/ad.rs` — add `MAX_EXTENDED_ADV_DATA_LEN`/
  `MAX_EXTENDED_FRAGMENT_LEN`/`MODE_TAG_LEN` (§3.1) and the
  mode-tag-splitting helper (§3.5); `build_ad_structure`/`find_mesh_fragment`
  keep their existing length-prefixed AD-structure scanning unchanged.
- `libs/blue/src/frame.rs` — `FRAG_PAYLOAD_LEGACY`/`FRAG_PAYLOAD_EXTENDED`/
  `MAX_FRAGMENT_BYTES` (§3.1); existing tests
  (`build_fragment_and_build_fragment_ad_agree_on_the_wire`, the
  `fragment_count_*` family) need duplicating per-mode rather than a single
  parametrized run, per this repo's TDD convention — write the failing
  per-mode tests first, including one pinning the mode-tag byte's position
  and value for each format.
- `libs/blue/src/generic_link.rs` — `BleLink` gains a second `Reassembler`
  field and the mode-tag demux in `recv` (§3.5); `send` gains the
  `BleSendMode`-driven per-mode fragmentation loop. This is now the file
  with the most new logic in this design, not an unchanged one — update its
  existing `FakeAdvertiser`-based tests to cover both modes and their
  interaction (a `Both`-mode `send` producing both a legacy and an extended
  fragment stream per frame; `recv` correctly demuxing a mixed stream of
  both).
- `libs/blue/src/nrf_link.rs` — `LinkT::send`'s per-mode advertisement
  construction (`NonscannableUndirected` / `ExtendedNonscannableUndirected`,
  §3.2); `ble_scan_task`/`ScanConfig` unchanged (already extended-capable by
  default).
- `libs/blue/src/std_link.rs` — `build_advertisement`'s per-mode
  `secondary_channel` field (§3.3); `scan_once`/`read_mesh_report`/
  `mesh_monitor` unchanged.
- `libs/blue/CLAUDE.md` — needs a follow-up pass regardless of whether this
  is implemented: its "On-air format" section currently states extended
  advertising has "no path... without deeper, harder-to-verify-without-
  hardware changes," which this document's §1/§3 supersede.

## 11. Deviations taken during implementation

Recorded per `docs/design/README.md`: a design doc is not a spec to follow to
the letter, but where the implementation departed from it, the departure and
its reason belong here rather than only in a diff.

1. **`MAX_REASSEMBLED_LEN` had to drop from 280 to 270 — §2's non-goal was
   wrong.** §2 lists "not required to change `MAX_REASSEMBLED_LEN` (280)" and
   §3.1 works through `FRAG_PAYLOAD_LEGACY` 19 → 18 without noticing the
   consequence: `wayfinder_link_utils::Reassembler::new()` asserts
   `MAX_REASSEMBLED_LEN <= MAX_FRAGMENTS * FRAG_PAYLOAD` at compile time, and
   `15 * 18 = 270`. Keeping 280 does not degrade, it fails to build. The
   ceiling is now 270, shared by both formats rather than per-format, which is
   also what keeps `BleSendMode::Both` coherent: every frame the link accepts
   is sendable in *both* formats, so a `Both` sender can never emit an extended
   copy whose legacy counterpart silently failed to fragment. 270 still clears
   a full-cert OGM (~250 B) with headroom. `frame.rs` restates the assertion
   beside the constants so a future edit fails there, next to the arithmetic
   that caused it, rather than inside a link's constructor.
2. **The mode tag lives in `frame.rs`, not `ad.rs`.** §3.1/§3.5 proposed an
   `ad::split_mode_tag`-style helper called before `parse_fragment_with_origin`.
   `ad.rs`'s subject is AD-*structure* framing (length/type/company-id), while
   the tag is part of this crate's own payload — the same thing
   `[frag_header][origin][body]` is, and that lives in `frame.rs`. Folding it
   into `parse_fragment_with_origin`'s return (`(BleAdvFormat, FragHeader, Mac,
   &[u8])`) also gives both backends one call site to change instead of two,
   and makes it impossible to parse a fragment without learning its format.
3. **`BleAdvFormat` and `BleSendMode` are two types, in a new `src/mode.rs`.**
   §3.5 named only `BleSendMode`. A wire tag (`Legacy`/`Extended`) and a send
   policy (`Legacy`/`Extended`/`Both`) are different things — `Both` is not a
   value any fragment can carry — so collapsing them would make an
   unrepresentable state representable. `mode.rs` is ungated because
   `BleSendMode` is read by both backends and `BleAdvFormat` appears in
   `BleAdvertiser::advertise`'s signature, so `params.rs` (`std`-only) was the
   wrong home for it.
4. **`build_fragment`/`build_fragment_ad` take a `FragmentSpec` instead of
   positional arguments.** Adding `format` pushed both to 8 parameters, which
   `clippy::too_many_arguments` rejects — correctly, since `msg_id`, `index`
   and `count` are adjacent small integers that transpose silently. `frame` and
   `frame_len` also collapsed into one already-truncated slice, removing a
   second class of mismatch.
5. **`build_fragment_ad` enforces the per-format budget at runtime.** Its
   output buffer is now sized for `MAX_EXTENDED_ADV_DATA_LEN` so one buffer
   serves both formats, which means the *type* no longer bounds a legacy
   advertisement to 31 bytes the way `[u8; MAX_LEGACY_ADV_DATA_LEN]` did.
   Nothing below this crate enforces it either — the SoftDevice firmware
   rejects an oversized legacy advertisement, BlueZ its own way — so the check
   moved into the one function both backends build advertising data through,
   with a test per format.
6. **§7.1/§9.1's capability probe shipped as part of this change, not before
   it.** `log_extended_advertising_capability` queries BlueZ's `MaxAdvLen` and
   supported secondary channels at `StdBleLink::new` and `warn!`s when
   `send_mode` asks for extended on a controller that cannot serve it. It is
   logged, never enforced: a pre-flight check that disagreed with the
   controller would be worse than the controller's own refusal, and a `Both`
   node still has a working legacy half. This does **not** close §9.1 — the
   constant is still a guess; it makes the guess observable on a real host.

7. **A `Both` send succeeds if *any* format reached the air, not if every one
   did.** §3.5 does not say what `Both` should do when one format's
   registrations fail, and the obvious implementation — `?` on each
   `advertise` — gets it wrong. Found immediately on real hardware: against a
   Bluetooth 4.2 controller (extended advertising is a 5.0 feature), the
   legacy copy went out fine and BlueZ then rejected the extended one, and
   the driver logged **every frame as dropped** while the mesh worked. That
   would make `Both` strictly worse than `Legacy` on exactly the hardware it
   exists to tolerate, contradicting §3.5's "safe net-positive ... loses
   nothing". Now a format that fails abandons its own remaining fragments (a
   half-advertised frame is bytes no peer can reassemble) but not the other
   format's pass, and only a frame where *no* format reached the air is a
   `TransmitFailed`. Both backends implement the same rule — they must, or a
   `Both` node's behaviour would depend on which one it runs.
8. **`recv` gained a per-frame `"rx frame"` trace carrying the format.** Not
   in the design at all, and needed before any of it can be validated: with
   `send_mode` governing only transmission, "are this peer's *extended*
   advertisements being heard and reassembled" is otherwise unanswerable from
   a node's logs — and every failure this link has had presented as a link
   that looked alive and moved no traffic. Logged per completed frame rather
   than per fragment. A proper per-format counter belongs in `CentralRouter`
   via the `add-metric` skill; this is the cheap version that makes bring-up
   possible.

**Open decisions (§9) as resolved:** §9.1 — `MAX_EXTENDED_ADV_DATA_LEN`
set to **244**, not the 200 §3.1 proposed: 244 is the largest value that
certainly fits a single `AUX_ADV_IND` PDU once its ~11-byte extended header is
subtracted from that PDU's 255-octet payload, so this crate never depends on
`AUX_CHAIN_IND` chaining — which the nRF scanner cannot reassemble anyway. 200
had no derivation behind it, and below ~244 nothing is gained: a controller
reports either a few hundred bytes of `MaxAdvLen` or 31, with no middle ground
to hedge against. Still unmeasured against a BlueZ controller, now reported at
startup (deviation 6). §9.2 — stayed
at `M1` on both backends, pinned by a test so the two cannot drift apart.
§9.3 — Phase 1 ships as a single required update with no tagged/untagged
straddle, the doc's own "simplest option". §9.4 — `MAX_REASSEMBLED_LEN` moved,
but *down* and under compulsion (deviation 1), not up as §9.4 contemplated;
raising it remains a separate decision. §9.5 — timing constants untouched and
still legacy-tuned; this is the largest live risk. §9.6 — default is `Legacy`,
as recommended.
