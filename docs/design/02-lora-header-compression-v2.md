# Design: LoRa link-layer header compression, v2 (rylr998)

**Status:** Proposed — *enhancement, not a threshold requirement.* Supersedes
design 00, which was written against the hex-encoded, unfragmented link;
this revision reworks the cost model and the layering for the base64 +
fragmentation link that has since shipped. The current `LinkT for RylrClient`
impl (full 14-byte header, base64, transparent fragmentation) is correct and
ships as-is.

**Scope:** the `rylr998` `LinkT` link only (`libs/rylr998`). No changes to
BATMAN, to the `LinkT`/`Received` trait surface, or to `CentralRouter`. The
compression lives entirely below the link boundary, *above* the fragmentation
layer (`frag.rs`).

---

## 1. What changed since v1

Design 00 was motivated by two numbers that are no longer true:

1. **Hex is gone.** The wire encoding is now URL-safe base64 (4:3 expansion,
   not 2:1). A saved frame byte is now worth ~1.33 on-air characters, not 2 —
   the maximum unicast saving drops from ~26 chars to ~17. (v1's own
   "alternatives" section listed removing the hex tax as a compounding future
   step; that step landed first, and it halved the headline win of this one.)
2. **Fragmentation exists.** Frames larger than `MAX_FRAME_LEN` (180 bytes)
   are split into up to 15 fragments, each a separate `AT+SEND` transmission
   carrying a 2-byte frag header. This cuts both ways:
   - *Against:* broadcast/OGM compression saves only 7 frame bytes (~9
     chars), which almost never changes the fragment count of a ~260-byte
     authenticated OGM — the frames that dominate airtime here.
   - *For:* each fragment is a whole LoRa transmission (preamble + PHY
     header, tens of ms at high SF) plus an `AT+SEND`/`+OK` round trip, and
     losing any one fragment loses the frame. Shaving 13 bytes off a unicast
     frame drops every frame in the 13-byte window above a fragment boundary
     from *n+1* fragments to *n* — a payload of 165–177 bytes goes from 2
     transmissions to 1. Fragment elimination, not character count, is now
     the headline benefit.

One prerequisite also got cheaper: v1's biggest open question was assigning
each node a unique 16-bit `AT+ADDRESS`. Fragmentation already imposed exactly
that — `frag::FragKey` keys reassembly on `(sender RYLR address, msg_id)` and
`libs/rylr998/CLAUDE.md` documents distinct per-node addresses as a
deployment requirement. The address↔MAC binding this design learns is the
same trust assumption the reassembler already makes.

## 2. Motivation (updated numbers)

Every logical frame carries a fixed Ethernet-shaped header, assembled in
`LinkT::send`:

```
[dst: Mac(6)] [src: Mac(6)] [protocol: u16 BE(2)] [payload …]   = 14 bytes
```

(Note the order: `dst` first, matching `LinkFrame` — v1 had this reversed.)

Most of it is redundant on this link:

1. **The source is already on the wire.** `+RCV=<Address>,…` reports the
   transmitter's 16-bit RYLR address, which is unique per node (see §1) and
   already parsed. A learned `addr ↔ MAC` table recovers the 6-byte src.
2. **The destination is the radio address.** A unicast next hop is a direct
   neighbor; addressing the RYLR transmission to that neighbor's 16-bit
   address makes the 6-byte dst MAC redundant. Broadcasts go to RYLR
   address `0`.

### Savings

Per-frame content bytes (default protocol), and their on-air cost after the
2-byte frag header and base64:

| Frame kind | Content today | Compressed | Frame bytes saved | On-air chars saved |
|------------|---------------|------------|-------------------|--------------------|
| Unicast, known neighbor | `14 + N` | `1 + N` | 13 | ~17 |
| Broadcast / OGM | `14 + N` | `7 + N` | 7 | ~9 |

Worked example, 30-byte unicast payload: today `14+30+2 = 46` bytes → 64
base64 chars; compressed `1+30+2 = 33` bytes → 44 chars. **~31% airtime
saving** — the relative saving on small frames is unchanged from v1 (encoding
is a constant multiplier); the absolute saving is a third smaller.

Fragment-count effects (the new, larger win):

- The single-fragment payload ceiling rises from **164 to 177 bytes** for
  unicast (171 for broadcast).
- Any unicast whose full-header frame length lands ≤13 bytes above a
  `FRAG_PAYLOAD` (178) boundary loses an entire fragment: one fewer LoRa
  preamble, one fewer `AT+SEND`/`+OK` round trip, and one fewer
  loss-amplification opportunity.
- A ~260-byte authenticated OGM stays at 2 fragments either way; broadcast
  compression only trims ~9 chars off its tail fragment. **Do not expect OGM
  airtime to move much.**

## 3. Goals / Non-goals

**Goals**
- Drop the dst MAC (always) and the src MAC (steady-state unicast) from the
  wire.
- Keep reconstruction purely link-local: `recv` rebuilds a byte-identical
  `LinkFrame`, so everything above the link is unchanged.
- Compose cleanly with fragmentation: compression applies to the *logical
  frame* once, not per fragment.
- Degrade gracefully: an unlearned binding falls back to the full header,
  never to a misdelivery.
- No BATMAN packet parsing in the link.

**Non-goals**
- Cross-segment / multi-radio addressing.
- Changing the `LinkT` trait, the `LinkFrame` format seen by the router, or
  the fragmentation wire format.
- A distributed address-allocation protocol beyond what fragmentation
  already requires (unique static `AT+ADDRESS` per node).
- Mixed legacy/compressed operation on one segment (all-or-nothing; the
  VERSION field guards future evolution).

## 4. Design

### 4.1 Layering: compress → fragment → base64

Compression is a transform on the logical frame's content bytes, applied in
`send` *before* the frame is split, and reversed in `recv` *after*
reassembly completes:

```
send:  [dst][src][proto][payload]
         → [ctrl][optional fields][payload]        (compress, once per frame)
         → split into ≤15 fragments, 2-byte frag header each
         → base64 per fragment → AT+SEND

recv:  +RCV lines → base64-decode → frag::Reassembler
         → completed compressed frame
         → expand to [dst][src][proto][payload]    (decompress, once per frame)
         → LinkFrame::ref_from_bytes → Received
```

The ctrl byte is paid once per frame, not per fragment. The fragmentation
layer is oblivious: it sees slightly shorter content blobs. `parse_fragment`
still owns the first 2 bytes of every on-air packet; the ctrl byte is byte 0
of the *reassembled* content, so the two formats cannot collide.

### 4.2 Node identity and self-MAC

Node identity is the existing per-node unique 16-bit `AT+ADDRESS` (§1) —
this design adds no new assignment mechanism. Collisions are detectable at
the table: learning two distinct MACs for one address is a conflict (`warn!`,
refuse to compress toward that address, carry full src from it).

The link caches its own node MAC from the `origin` argument of the first
`send` — it needs it to reconstruct `dst = self` on compressed unicasts. A
compressed unicast received before the first `send` is dropped (cannot
reconstruct dst); in practice the node OGMs at startup, so the window is one
Trickle interval at most.

### 4.3 Neighbor table

A small bounded (`heapless`) bidirectional cache of *direct* neighbors:

```
addr (u16)  <->  neighbor MAC (6)
```

- **Learned on receive**, after reassembly: any completed frame whose ctrl
  has `SRC_PRESENT` binds `FragKey.addr → src`. Broadcasts always carry a
  full src (§4.5), and OGMs are periodic broadcasts from every node, so the
  table self-populates from ordinary traffic — no discovery sub-protocol, no
  BATMAN parsing.
- **Queried on send**: `dst MAC → addr` to pick the RYLR transmit address.
- Fixed capacity, LRU eviction. Direct-neighbor count on a LoRa segment is
  small; size it like `MAX_REASSEMBLIES` was sized — modest, with graceful
  degradation (an evicted binding costs compression, not correctness).

### 4.4 Wire format: the control byte

Byte 0 of the compressed frame content. This finalizes the bitfield v1 left
open (its "reserve bit 7 as DST_PRESENT" note):

```
byte 0: ctrl
  bit 0   SRC_PRESENT    1 = full 6-byte src MAC follows
  bit 1   DST_BROADCAST  1 = link dst is Mac::BROADCAST
  bits 2-3 PROTO         00 = default 0x4305, omitted
                         01 = 1 trailing proto byte
                         10 = 2 trailing proto bytes (u16 BE, as on the wire today)
                         11 = invalid
  bits 4-6 VERSION       000 for this design; drop on mismatch
  bit 7   DST_PRESENT    1 = full 6-byte dst MAC follows

then, in order, only the present fields:
  [src MAC(6)]   if SRC_PRESENT
  [dst MAC(6)]   if DST_PRESENT
  [proto(0/1/2)] per PROTO
  [payload …]
```

Exactly three variants are ever sent; anything else is dropped as malformed:

| Variant | SRC | DST_PRESENT | DST_BROADCAST | RYLR tx addr | Content |
|---------|-----|-------------|---------------|--------------|---------|
| Compressed unicast (known neighbor) | 0 | 0 | 0 | neighbor's addr | `ctrl [proto] payload` |
| Broadcast / OGM | 1 | 0 | 1 | 0 | `ctrl src [proto] payload` |
| Full fallback (unknown neighbor) | 1 | 1 | 0 | 0 | `ctrl src dst [proto] payload` |

Invalid combinations (`DST_PRESENT` with `DST_BROADCAST`; `SRC_PRESENT=0`
with anything but the compressed-unicast variant) and unknown VERSION are
dropped with a `trace!("drop: …")`, per the logging rules — all reachable
from arbitrary remote input.

### 4.5 Send path

```
fn send(origin, data):
    cache self_mac = origin
    if data.dst.is_broadcast():
        variant = Broadcast(src=origin); rylr_addr = 0
    else if let Some(addr) = table.addr_for(data.dst)
            and !table.conflicted(addr):
        variant = CompressedUnicast; rylr_addr = addr
    else:
        variant = FullFallback(src=origin, dst=data.dst); rylr_addr = 0
    content = encode(ctrl, fields, data.protocol, data.payload)
    fragment content as today (msg_id, FRAG_PAYLOAD slices), base64,
    send_data(rylr_addr, …) per fragment
```

The policy keys only on `data.dst.is_broadcast()` and a table lookup — no
BATMAN inspection. Note the fallback is *addressed to broadcast* but is not a
link-level broadcast: the carried dst MAC is authoritative, exactly as every
frame is today.

**This reverses a documented decision.** `link.rs` currently transmits
everything to `RYLR_BROADCAST_ADDR`, with a doc comment calling the module
address "only a firmware-side UART pre-filter". Compressed unicasts must be
addressed to the neighbor's RYLR address — that is *how* dst is elided. This
is safe: BATMAN needs no promiscuous overhearing of others' unicasts (link
quality comes from OGM broadcasts, which remain addressed to 0), and
module-side filtering reduces bystanders' UART traffic and reassembler
pressure. The module doc comment must be rewritten as part of
implementation.

### 4.6 Receive path

```
fn recv():
    loop:
        packet → base64-decode → parse_fragment → reassembler.accept(...)
        if some message completed (compressed content, len):
            ctrl = content[0]
            reject unknown VERSION / invalid variant        (drop, continue)
            src = carried field, learning addr→src
                  | table.mac_for(key.addr)                 (drop if unknown)
            dst = BROADCAST | carried field | self_mac      (drop if self_mac unset)
            proto = carried field | 0x4305
            expand into rx_frame as [dst][src][proto][payload]
            return Received { frame, metrics }
```

A compressed unicast from a not-yet-learned neighbor is dropped; the
neighbor's periodic OGM broadcasts (which always carry full src) populate
the binding, and BATMAN retransmits. Same bootstrap argument as v1, and the
drop window is bounded by the OGM/Trickle interval.

**Buffer detail.** Today the reassembler writes the finished frame directly
into `rx_frame` and `LinkFrame::ref_from_bytes` borrows it in place.
Decompression *expands* the content (by up to 13 bytes), and the expansion
amount isn't known until fragment 0 (carrying ctrl) has arrived — which may
be last. So: reassemble into `rx_frame` as today, then expand **in place**
with a right-shift of the payload (`copy_within`, overlap-safe in that
direction) and write the 14-byte header into the vacated front. `rx_frame`
grows by 13 bytes of headroom (`MAX_REASSEMBLED_LEN + 13`). No second
512-byte buffer.

## 5. Correctness / edge cases

- **No misdelivery, ever.** dst is either carried explicitly, `BROADCAST`,
  or `self_mac` on a module-address-filtered unicast. A stale *dst→addr*
  binding on send misdirects the RYLR transmission, but the receiver
  reconstructs `dst = self_mac` and hands it to the mesh layer, which… would
  accept it. This is the one genuinely new failure mode vs. today —
  mitigations: conflict detection refuses compression on ambiguous
  addresses, LRU keeps the table fresh relative to OGM cadence, and the
  window requires an address to be *reassigned* between two live neighbors,
  which the static-address deployment model (§1) already forbids. Same trust
  class as fragment-reassembly keying.
- **Address collision** (two MACs claim one addr): detected on learn; mark
  conflicted, `warn!`, stop compressing toward it and stop trusting
  table-recovered src from it (drop instead). Recovers if the conflict ages
  out via LRU.
- **Unknown dst on send**: full-fallback variant — correct, just
  uncompressed.
- **Compressed unicast before binding / before self-MAC known**: dropped;
  bounded by OGM cadence (§4.6).
- **Protocol ≠ 0x4305**: carried via PROTO bits (1 or 2 bytes).
- **VERSION mismatch / invalid variant**: `trace!` drop. A segment is
  all-or-nothing; mixed operation is out of scope.
- **Malformed ctrl + truncated fields** (content shorter than the fields the
  ctrl byte promises): drop, exactly like today's short-frame handling.

## 6. Security considerations

Nothing here is authenticated — same as the existing link. The new surface
is the addr↔MAC table:

- A neighbor can lie in `SRC_PRESENT` frames and poison `addr → MAC`. It can
  already forge the in-frame src MAC today; OGM authenticity is `OgmAuth`'s
  job, above this layer. Net change: none for authenticated traffic;
  spoofed-src *unicasts* become attributable to a spoofed +RCV address
  instead of a spoofed in-frame field — equivalent.
- Table-eviction DoS (spraying bindings to evict real ones) degrades to
  full-header fallback and receive-side drops, not misdelivery — bounded,
  and no worse than the reassembler-eviction pressure the same attacker can
  already apply.

## 7. Observability

Per the "metrics are first-class" rule, but note this state is *link*-local
(`no_std`, below `CentralRouter`), and `LinkT` has no query surface — the
root invariant (state must not live only in the driver) is satisfied
vacuously, not violated: there is nowhere higher to put it without a trait
change, which is a non-goal.

Minimum bar (tracing): `debug!` on learn/evict/conflict with addr + MAC;
`trace!("drop: …")` for unknown-binding, bad-version, invalid-variant drops;
counters can wait. Candidate future metrics if a link-stats surface ever
exists: table occupancy (`TableOccupancy`-style gauge), compressed-vs-full
send ratio, drops-awaiting-binding rate. Left as an open decision (§10).

## 8. Testing strategy (TDD)

- **Unit — ctrl codec:** encode/decode round-trip for each of the three
  variants × PROTO widths; rejection of invalid combinations, bad VERSION,
  truncated fields.
- **Unit — neighbor table:** learn, bidirectional lookup, LRU eviction at
  capacity, conflict detection and its refuse-to-compress effect.
- **Unit — link paths:** compressed frame → fragment → reassemble → expand
  round-trips byte-identically to today's `LinkFrame`, including the
  in-place right-shift with fragment 0 arriving last; unknown-binding drop;
  unknown-neighbor send fallback; self-MAC-unset drop.
- **Integration** (`libs/rylr998/tests/integration.rs`, existing simulator):
  two clients — OGM broadcast populates the binding, a subsequent unicast
  goes out compressed, addressed to the neighbor's RYLR address, and
  reconstructs to the identical `LinkFrame` the uncompressed path produces
  (golden-compare). A third client verifies module-address filtering doesn't
  break its view of broadcasts.

## 9. Alternatives considered

- **Don't do it** — the strongest alternative now. Base64 already took the
  cheap 33% (v1's "binary framing" idea, realized); what's left is ~17 chars
  per unicast, ~9 per broadcast, and occasional fragment elimination, priced
  at a neighbor table, a ctrl-byte format, and a trust-model extension. This
  doc's position: still worth having *as an opt-in enhancement* for
  unicast-heavy workloads at high SF, but it is lower priority than v1
  claimed, and OGM-dominated deployments should expect little.
- **Merge the ctrl byte into the fragment header** (e.g. steal frag-header
  bits). Rejected: the ctrl byte is per-*frame*, the frag header per-
  *fragment*; merging couples two independent wire formats and versions, to
  save at most 1 byte per frame.
- **Snoop BATMAN OGM internals to learn bindings.** Rejected in v1, still
  rejected: binds the originator (possibly multi-hop) rather than the
  immediate neighbor, and couples the driver to BATMAN wire formats.
- **Keep always-broadcast addressing and compress only src.** Halves the
  benefit (dst must then always be carried) to preserve a doc comment;
  the pre-filter rationale doesn't survive contact with §4.5's analysis.

## 10. Open decisions for the implementing session

1. **Neighbor-table capacity** (suggest starting at 8, same spirit as
   `MAX_REASSEMBLIES`) and whether entries deserve a coarse staleness signal
   given `no_std` has no wall clock (v1's open question; capacity-LRU alone
   is probably fine, matching the reassembler's precedent).
2. **Where the table lives** in `RylrClient` vs. a separate module
   (suggest a `compress.rs` sibling to `frag.rs`, owning ctrl codec + table).
3. **Whether conflict state ages out** via LRU only, or needs an explicit
   clear on a consistent re-learn.
4. **Link-stats surface**: leave metrics at tracing-only (§7) or propose the
   `LinkT` query extension separately. Do not let this design grow that
   trait change.

## 11. Key file map for the implementer

- `libs/rylr998/src/link.rs` — `LinkT::send`/`recv`, `HEADER_LEN`,
  `MAX_FRAME_LEN`, base64 codec; the always-broadcast doc comment to rewrite
  (module header, bullets 1–3); `rx_frame` expansion in `recv`.
- `libs/rylr998/src/frag.rs` — unchanged wire format; `FRAG_PAYLOAD`,
  `MAX_REASSEMBLED_LEN` (rx buffer headroom note in §4.6), `FragKey.addr`
  as the learning key.
- `libs/rylr998/src/lib.rs` — `RylrClient` state: `rx_frame` (size),
  neighbor table + cached self-MAC live next to `msg_id_ctr`/`reassembler`.
- New `libs/rylr998/src/compress.rs` (suggested) — ctrl codec + neighbor
  table + their unit tests.
- `libs/rylr998/tests/integration.rs` — simulator-based integration tests.
- `libs/rylr998/CLAUDE.md` — document the compression layer alongside the
  fragmentation section; update the addressing story.
- `docs/design/00-lora-header-compression.md` — already marked Superseded by
  this doc.
