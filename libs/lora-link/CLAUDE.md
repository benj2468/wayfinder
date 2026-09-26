# libs/lora-link

Framing and fragmentation for a **raw LoRa PHY** — a radio that hands over a
payload and nothing else. `no_std`, no opinion about the radio chip, and **no
`LinkT` impl**: that lives in the adapter, exactly as `libs/ieee802154`'s does
in `at86rf233`/`nrf-ieee802154`. See
`docs/design/25-stm32wl55-subghz-node.md`.

The send path is `assemble_frame` → `fragment_count` → `build_fragment` per
fragment; the receive path is `accept_fragment` per packet → `decode_frame`
once one completes. Fragmentation reuses `wayfinder-link-utils`, as `rylr998`,
`blue` and `ieee802154` do.

## Why this is not `rylr998`, which is also LoRa

`rylr998` drives a REYAX *module* over AT commands, and that module supplies
three things this crate has to supply itself:

| | RYLR998 | raw SX126x |
|---|---|---|
| sender address on receive | `+RCV=<addr>,…` | nothing |
| network filtering | `AT+NETWORKID` | nothing |
| addressed send | `AT+SEND=<addr>` | nothing — every send is a broadcast |

Hence the 3-byte header. **The two formats are deliberately not
interoperable** and must not be unified: the RYLR module imposes base64 and a
180-byte AT-line budget that a raw PHY has no reason to inherit, and adopting
it would roughly halve usable payload.

## The wire format

One on-air LoRa payload:

```text
[net_id: 1][src_id: 2, big-endian][frag_hdr: 2][frame content …]
```

`FRAG_PAYLOAD` is 250 (`255 - 3 - 2`). The frame content is the same
Ethernet-shaped `[dst][src][protocol][payload]` blob every other link carries,
so **nothing above `LinkT` can tell this link apart from any other** — which is
the property that makes the link substitutable, and the one worth protecting.

`net_id` is a **filter, not a security boundary.** It is one forgeable byte,
and its only job is keeping a co-located mesh out of this one's reassembly
table — a table with four slots, where a stranger's message evicts a real one.
Mesh membership is `wayfinder-auth`'s `MembershipCert`, verified above `LinkT`.
Never describe `net_id` as segregation.

## The reassembly key is the `src_id` in the header

It has to be *in the header*, not read out of the reassembled content — even
though that content's Ethernet header already carries the full 6-byte source
`Mac` at bytes 6..12. That copy is only available once reassembly *finishes*,
and the key is what decides which reassembly a fragment belongs to.

`src_id` is the low 16 bits of the sender's `Mac`, which is
`ieee802154::short_address_of`'s derivation — deliberately the same, so a
node's two radios agree on its short identity. This crate does **not** call
that function or depend on that crate: the adapter passes `src_id` in, the way
the STM32F411 board already computes its RYLR998 address inline
(`bins/wayfinder-stm32f411/src/main.rs`). Keep it that way; a LoRa crate depending on
an 802.15.4 crate for two lines of arithmetic is worse than the duplication it
avoids.

Worth contrasting with `libs/blue`, whose key *is* an embedded 6-byte `Mac`:
BLE draws a fresh random advertiser address per advertising-set registration,
so no multi-fragment message's fragments share one. **Don't copy blue's scheme
here** — it would spend 6 bytes of every fragment solving a problem this medium
does not have.

**Two nodes whose `Mac`s share their low 16 bits corrupt each other's
reassembly.** The same deployment constraint `rylr998` and `ieee802154`
document. It costs dropped frames, never misattributed ones — the authenticated
`Mac` travels *inside* the reassembled content, so a spoiled reassembly fails
the `LinkFrame` parse or the signature check rather than arriving under the
wrong sender. `colliding_source_addresses_corrupt_rather_than_misattribute`
pins that, under the same name as `ieee802154`'s.

## `MAX_REASSEMBLED_LEN` is pinned to the board's capacity profile

512, matching `rylr998` and `ieee802154`. **If a board's profile
`max_frame_len` changes, change it here too** — or rather, let the board's
`const` assertion catch it, the way `wayfinder-nrf` asserts
`ieee802154::MAX_REASSEMBLED_LEN == nrf52840::MAX_FRAME_LEN`. Below the
profile's value the router silently refuses frames this link considers legal,
and since a full authenticated OGM is ~260 bytes, the node looks healthy and
routes nothing.

Do not shrink it to save RAM on a small part. It is sized for an authenticated
OGM plus revocation TVLVs; the RAM comes from somewhere else (on the WL55, the
log ring — design 25 §4.7).

## Implementing a `LinkT` adapter over a real radio

1. Implement `LinkT` (`libs/wayfinder/src/link.rs`) for your device.
2. `send`: `assemble_frame` into a scratch buffer, then `build_fragment` and
   transmit each of `fragment_count`'s fragments. **Abandon the frame if one
   fragment fails** — the receiver cannot complete a reassembly missing a
   fragment, so the rest of the airtime is spent for nothing.
3. `recv`: **loop.** Feed each received buffer to `accept_fragment` and return
   only when one completes a frame. The driver's `recv` arm expects a whole
   frame or nothing; a lone fragment must buffer and the loop continue, never
   return early or fabricate a short frame.
4. Own your own `LoraReassembler` and `msg_id` counter. `msg_id` is per
   *frame*, and it wraps.
5. Fill `LinkMetrics` with the radio's RSSI/SNR and leave `quality` **`None`**,
   so the engine derives the score. Setting `quality` commits to an
   IEEE-802.15.4-style 0..=255 LQI scale, and a value on some other scale
   silently suppresses routing through the radio rather than looking wrong
   anywhere — see `LinkMetrics::quality`'s own docs. There is no
   datasheet-pinned mapping for a LoRa RSSI/SNR pair, so do not invent one.
6. Do **not** override `fan_out`. No radio driver here does, and a broadcast
   LoRa send arguably fits its `Some(1)` case — but that method is a design-17
   seam nothing currently reads, so diverging alone would change egress
   behaviour for no benefit. If it is ever settled, settle it for `rylr998`,
   `blue`, `ieee802154` and this crate together.

### `recv` must be cancel-safe, and awaiting the radio directly is not

`wayfinder_embedded_driver` races **every link's `recv` against the OGM
timer** and drops every loser, so a `recv` holding a half-received frame in a
local is torn down routinely — on every timer tick, and on every frame from any
other link.

The shape that survives it: **a never-cancelled task owning the radio, with
`recv` awaiting only a channel.** `nrf-ieee802154`'s `radio_task`,
`wayfinder_nrf::usb_link` and `blue`'s `ReportQueue` are all this, for this
reason.

The trap is that awaiting the hardware directly *looks* fine. It is typically
memory-safe — `lora-phy`'s futures and `embassy_nrf`'s `Radio::receive` both
clean up on drop — it just **loses the frame and leaves the receiver off** until
the next `recv`. A radio duty-cycled by an unrelated timer reads as *poor RF,
not as a bug*, which is the worst available failure shape on a mesh whose job
is judging link quality. `at86rf233` still awaits its IRQ line inside `recv`
and has exactly this latent problem; it has never been exercised only because
it is unwired.

`send` is under no such constraint — it is awaited to completion by
`plan_dispatch`'s caller and is not raced — **but it still must not take the
radio through a mutex**. On a half-duplex radio the receive side sits parked
inside `rx()` holding the radio, so a mutexed `send` waits until a frame happens
to arrive. Hand transmit to the owning task through a queue instead, and have
that task race `rx()` against the queue (`bins/wayfinder-wl55jc/src/radio.rs`
is the shape to copy).

## Fuzzing

The air-facing boundary is `accept_fragment`: header validation, fragment-header
parsing, and reassembly, all reachable by anyone in radio range. A `fuzz/`
target should mirror `libs/ieee802154/fuzz`, including the part that is easy to
get wrong — **the reassembler must persist across inputs**, since reassembly is
stateful (capacity eviction, duplicate indices, a mid-message count change) and
a fresh table per call never reaches any of it. No seed corpus needed; it is
structural parsing with no crypto barrier.
