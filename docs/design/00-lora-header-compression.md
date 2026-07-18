# Design: LoRa link-layer header compression (rylr998)

**Status:** Superseded by design 02 (`02-lora-header-compression-v2.md`), see
there. This doc was written against the hex-encoded, unfragmented link; the
base64 wire encoding and the fragmentation layer that have since shipped
invalidate its savings analysis and its layering, and v2 reworks both. Kept
for the record; do not implement from this version.

**Scope:** the `rylr998` `LinkT` link only. No changes to BATMAN, to the
`LinkT`/`Received` trait surface, or to `CentralRouter`. The compression lives
entirely below the link boundary.

---

## 1. Motivation

LoRa airtime is the dominant cost on this medium (at SF12 each on-air byte is
tens of milliseconds), and the RYLR AT protocol is text, so every frame is
**hex-encoded — each frame byte costs two on-air characters.**

Today each frame carries a fixed `LinkFrame` header:

```
[src: Mac(6)] [dst: Mac(6)] [protocol: u16(2)] [payload …]   = 14 bytes header
```

That is **28 on-air characters of header on every single frame**, before any
payload. Two observations make most of it redundant on this link:

1. **The source is already on the wire.** `+RCV=<Address>,<Length>,<Data>,…`
   reports the *transmitter's* 16-bit `AT+ADDRESS`. If each node owns a unique,
   stable RYLR address, the 6-byte src MAC is recoverable from that address via
   a learned table — `recv` already parses the field and discards it.
2. **The destination is the radio address.** A unicast next hop is a *direct
   neighbor*; addressing the RYLR transmission to that neighbor's 16-bit address
   makes the 6-byte dst MAC redundant. A broadcast goes to RYLR address `0`.

This is the same idea as ARP + 6LoWPAN header compression: full addresses during
discovery, compact handles in steady state.

### Savings

| Frame kind | Header today | Header compressed | On-air saving (hex) |
|------------|--------------|-------------------|---------------------|
| Unicast / MCAST | `src 6 + dst 6 + proto 2` = 14 | `ctrl 1` (+ optional proto) = 1–3 | **22–26 chars** |
| Broadcast / OGM | 14 | `ctrl 1 + src 6` = 7 | **14 chars** |

Unicast steady-state frames lose essentially the entire header. Because the
240-byte module limit is on the hex string, the recovered budget also raises the
max payload per frame.

## 2. Goals / Non-goals

**Goals**
- Drop the dst MAC (always) and the src MAC (steady-state unicast) from the wire.
- Keep reconstruction *purely link-local*: `recv` rebuilds a normal `LinkFrame`
  in its scratch buffer, so everything above the link is byte-for-byte unchanged.
- Degrade gracefully: an unlearned binding falls back to the full header, never
  to a misdelivery.
- No BATMAN packet parsing in the link (avoid the layering violation).

**Non-goals**
- Cross-segment / multi-radio addressing.
- Changing the `LinkT` trait or the `LinkFrame` format seen by the router.
- A complete distributed address-allocation protocol (see Open Questions).

## 3. Background: what the link already has

- `RylrClient::send_data(addr, &str)` / `listen_for_packet() -> ReceivedPacket`
  (`address`, `length`, `data`, `rssi`, `snr`). The sender's 16-bit address is
  already surfaced on receive.
- `LinkT::send(&mut self, origin: Mac, data: &LinkFrameData)` — the link is
  handed **its own node MAC** (`origin`) on every send, and the next-hop MAC
  (`data.dst`, which is `Mac::BROADCAST` for floods/OGMs).
- `LinkFrame.src` on a received frame is the *immediate transmitter* (one RF
  hop) — always a direct neighbor. This is the MAC that pairs with the `+RCV`
  address, **not** the OGM originator (which may be multi-hop away).

## 4. Design

### 4.1 Node identity: a unique 16-bit RYLR address

Each node sets `AT+ADDRESS` to a 16-bit ID derived from its 6-byte node MAC
(e.g. a hash folded to 16 bits), reserving `0` for broadcast. The link caches
its own node MAC from the `origin` argument of the first `send` (or via an
explicit `set_node_mac`) — it needs it to reconstruct `dst = self`.

Uniqueness only has to hold **among direct neighbors** (the only nodes whose
address↔MAC binding a given node learns), so the effective namespace is small
and local. Collisions are *detectable*: learning two distinct MACs for one
address is a conflict (log + refuse to compress for that address). Full
duplicate-address detection is an Open Question.

### 4.2 Neighbor table

A small bounded (heapless), bidirectional cache of direct neighbors:

```
addr (u16)  <->  neighbor MAC (6)
```

- **Learned on receive**: every frame whose src MAC is present binds
  `+RCV.address -> src`. Broadcasts/OGMs always carry a full src (§4.4), so the
  table self-populates from ordinary traffic — no BATMAN parsing required.
- **Queried on send**: `dst MAC -> addr` to choose the RYLR transmit address.
- Fixed capacity with LRU eviction; direct-neighbor count on a LoRa segment is
  small. Entries may carry a last-seen timestamp for staleness (Open Question).

### 4.3 Wire format

A single **control byte** prefixes the frame and selects the variant, so
compressed and full frames coexist and the format can evolve:

```
byte 0: ctrl
  bit 0  SRC_PRESENT   1 = full src MAC follows
  bit 1  DST_BROADCAST 1 = link dst is BROADCAST; 0 = unicast (dst = receiver)
  bits 2-3 PROTO       00 = default 0x4305 (omitted)
                       01 = 1 trailing byte
                       10 = 2 trailing bytes (u16, native-endian)
  bits 4-6 VERSION     format version (000 for this design)
  bit 7   reserved (0)

then, in order, only the present fields:
  [src MAC(6)]      if SRC_PRESENT
  [proto(0/1/2)]    per PROTO
  [payload …]
```

dst is **never** carried: it is the RYLR transmit address (unicast) or
`BROADCAST` (`DST_BROADCAST`). Note the receiver cannot tell unicast-to-me from
broadcast from `+RCV` alone (it reports no destination), which is exactly why
`DST_BROADCAST` lives in the control byte.

Example sizes (payload `N`):
- Unicast, known neighbor, default proto: `1 + N` bytes (vs `14 + N`).
- Broadcast/OGM, default proto: `1 + 6 + N` bytes (vs `14 + N`).

### 4.4 Send path

```
fn send(origin, data):
    cache self_mac = origin
    if data.dst.is_broadcast():
        ctrl.DST_BROADCAST = 1
        ctrl.SRC_PRESENT   = 1          # broadcasts always teach the binding
        rylr_addr = 0
        body = [src=origin]
    else:
        rylr_addr = table.addr_for(data.dst)
        if rylr_addr is None:           # unknown neighbor -> safe fallback
            ctrl.DST_BROADCAST = 1       # flood-addressed, but carry full dst…
            ctrl.SRC_PRESENT   = 1
            rylr_addr = 0
            body = [src=origin, dst=data.dst]   # full header fallback (see note)
        else:
            ctrl.DST_BROADCAST = 0       # addressed to the neighbor's RYLR addr
            ctrl.SRC_PRESENT   = 0       # src recoverable from +RCV at receiver
            body = []
    encode proto into ctrl/body
    hex = encode(ctrl ++ body ++ payload)
    send_data(rylr_addr, hex)
```

> **Fallback note.** The unknown-neighbor case needs the *full* `[src][dst]`. The
> cleanest encoding is a distinct control combination (e.g. `SRC_PRESENT=1` plus a
> `DST_PRESENT` bit) rather than overloading `DST_BROADCAST`; the sketch above
> elides that fourth bit for readability. Concretely: reserve bit 7 as
> `DST_PRESENT` and drop the "reserved" note.

The send policy keys only on `data.dst.is_broadcast()` — **no BATMAN inspection.**

### 4.5 Receive path

```
fn recv():
    pkt = listen_for_packet()
    bytes = decode_hex(pkt.data)
    ctrl = bytes[0]; off = 1
    # source
    if ctrl.SRC_PRESENT:
        src = bytes[off..off+6]; off += 6
        table.learn(pkt.address -> src)
    else:
        src = table.mac_for(pkt.address)
        if src is None:                 # binding not yet known
            return Err(InvalidPacket)   # drop; OGMs will populate it shortly
    # destination
    dst = BROADCAST if ctrl.DST_BROADCAST else self_mac
    # protocol + payload
    proto, payload = decode_proto(ctrl, bytes[off..])
    # rebuild a normal LinkFrame in rx_frame and hand it up unchanged
    rx_frame = [src][dst][proto][payload]
    return Received { frame: &rx_frame, metrics: from(pkt.rssi, pkt.snr) }
```

The reconstructed `rx_frame` is a vanilla `LinkFrame`, so `handle_frame` and the
BATMAN engine are oblivious to the compression.

### 4.6 Bootstrapping

The src binding is required before a node can decompress that neighbor's
unicasts. BATMAN OGMs are periodic, every node emits them, and they are
broadcasts — so they always carry a full src (§4.4) and continuously refresh the
table. A unicast that arrives before the first OGM from that neighbor is simply
dropped (§4.5); BATMAN will retransmit, and by then the binding exists. No
explicit discovery sub-protocol is needed.

## 5. Edge cases

- **Address collision** (two MACs, one `+RCV` address): detected on `learn`;
  refuse to compress for that address (carry full src), log a warning.
- **Stale binding** (neighbor left, address reused): LRU eviction + optional
  last-seen TTL; worst case a dropped frame and a re-learn from the next OGM.
- **Unknown dst on send**: full-header fallback via broadcast (§4.4) — correct,
  just not compressed.
- **Self-MAC not yet known** (node hasn't sent before receiving): hold or drop
  until the first `send` caches `origin`; in practice the node OGMs on startup.
- **Protocol ≠ 0x4305**: encoded explicitly via the `PROTO` bits.
- **Homogeneous segment assumption**: all nodes on the LoRa segment must speak
  this format. The `VERSION` field guards future changes; mixed legacy/compressed
  operation is out of scope (a segment is all-or-nothing).

## 6. Savings analysis

For a typical small BATMAN unicast (e.g. an ARP-in-`BATADV_UNICAST`, payload
~30 bytes), header overhead drops from 14 → 1 frame bytes, i.e. **28 → 2 on-air
characters** — roughly a 30% airtime reduction on a 60-char frame, and larger
for smaller payloads. OGMs (broadcast) drop 14 → 7, ~halving their header.

## 7. Risks & open questions

1. **Address assignment / DAD.** Hash-from-MAC + collision detection is the
   minimum; a proper duplicate-address-detection handshake (claim + listen) is
   unspecified here. Biggest open question.
2. **Drop-before-bind window.** Relies on OGM cadence being fast relative to
   unicast onset. Quantify against the configured OGM interval.
3. **Table sizing / eviction policy** under churn.
4. **Self-MAC acquisition** ergonomics (cache-from-`send` vs explicit setter).
5. **Control-bit budget**: the clean encoding needs `SRC_PRESENT`, `DST_PRESENT`,
   `DST_BROADCAST`, `PROTO(2)`, `VERSION` — finalize the bitfield before coding.

## 8. Testing strategy (TDD)

- **Unit (link)**: encode/decode round-trip for each control variant; table
  learn + bidirectional lookup; reconstruction of src (from table) and dst
  (self vs BROADCAST); unknown-binding drop; unknown-neighbor send fallback;
  collision detection; proto compression paths.
- **Integration**: two `RylrClient`s over a simulated serial pair — OGM
  broadcast populates the binding, a subsequent unicast is sent compressed and
  reconstructs to the identical `LinkFrame` the full path would have produced
  (golden-compare against the current impl).

## 9. Alternatives considered

- **Snoop BATMAN OGM internals to learn bindings.** Rejected: binds the
  *originator* (possibly multi-hop) rather than the immediate neighbor, and
  couples the LoRa driver to BATMAN wire formats. Learning from `LinkFrame.src`
  on broadcasts is both correct and layering-clean.
- **Always broadcast, never compress dst.** The current shipped behavior; simple
  but pays the full 14-byte header forever.
- **Binary (non-hex) framing with length-prefixed `+RCV` parsing.** Orthogonal:
  removes the 2× hex tax but not the header redundancy; could compose with this
  later for a further ~2× on whatever header remains.
