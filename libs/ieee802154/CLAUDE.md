# libs/ieee802154

Hardware-agnostic IEEE 802.15.4 framing and fragmentation. `no_std`.

Wraps a `LinkFrame` in a minimal 802.15.4 MAC header (broadcast PAN/address,
no security/ack) and cuts it into fragments; reassembles them on receive. No
opinion about the radio chip; the mesh filters on the `Mac` embedded in the
reassembled frame. `MAX_FRAME_LEN` = 125. Used by the `at86rf233` and
`nrf-ieee802154` `LinkT` adapters. See
`docs/design/19-ieee802154-nrf-link.md`.

The send path is `assemble_frame` → `fragment_count` → `build_fragment` per
fragment; the receive path is `accept_fragment` per fragment → `decode_frame`
once one completes. Fragmentation reuses `wayfinder-link-utils` (see its
`CLAUDE.md`), as `rylr998` and `blue` do.

## Why fragmentation exists here at all

One PHY frame carries `FRAG_PAYLOAD` = 114 bytes of mesh frame
(`125 - 9` MAC header `- 2` fragment header). A full-cert OGM is ~250 bytes
and the `nrf52840` capacity profile's `max_frame_len` is 512, so a
single-frame link could not carry this mesh's own traffic. `MAX_REASSEMBLED_LEN`
is pinned to that 512 — **if the profile's `max_frame_len` changes, change it
here too**, or the link silently refuses frames the router considers legal.

## The reassembly key is the MAC header's short source address

Not an address embedded in the fragment body. This is the one place worth
contrasting with `libs/blue`, whose reassembly key *is* an embedded 6-byte
`Mac`: BLE draws a fresh random advertiser address on every advertising-set
registration, so no multi-fragment message's fragments share an address.
802.15.4 has a stable source address field this crate controls, so the key
costs 2 bytes instead of 6. **Don't "unify" the two by copying blue's
embedded-origin scheme here** — it would spend 6 bytes of every fragment
solving a problem this medium does not have.

The address is `short_address_of(mac)` — the low 16 bits of the sender's mesh
`Mac`, the same derivation the board's LoRa link uses for its `AT+ADDRESS`,
so a node's two radios agree on its short identity.

**Two nodes whose MACs share their low 16 bits corrupt each other's
reassembly.** Same deployment constraint `rylr998` documents. It costs dropped
frames, never misattributed ones — the authenticated `Mac` travels *inside*
the reassembled frame, so a corrupted reassembly fails the `LinkFrame` parse
or the signature check rather than arriving under the wrong sender.
`colliding_source_addresses_corrupt_rather_than_misattribute` pins that.

## Implementing a physical radio driver

1. Implement the `LinkT` trait (`libs/wayfinder/src/link.rs`) for your device.
2. `send`: `assemble_frame` into a scratch buffer, then `build_fragment` and
   transmit each of `fragment_count`'s fragments. Abandon the frame if one
   fragment fails — the receiver cannot complete a reassembly missing a
   fragment, so the rest of the airtime is spent for nothing.
3. `recv`: **loop**. Feed each received buffer to `accept_fragment` and return
   only when one completes a frame; the driver's `recv` arm expects a whole
   frame or nothing.
4. Own your own `Ieee802154Reassembler` and `msg_id` counter. `msg_id` is per
   *frame*; the MAC `seq` is per *fragment*.

The link trait is deliberately minimal and fire-and-forget: no TX-side
ACK/retry/CCA feedback in the shared trait.

### `recv` must be cancel-safe

`wayfinder_embedded_driver` races every link's `recv` against the OGM timer
and drops every loser, so a `recv` holding a half-received frame in a local is
torn down routinely — on every timer tick and every frame from any other link.

The shape that survives it: a never-cancelled task owning the hardware, with
`recv` awaiting only a channel. `nrf-ieee802154`'s `radio_task`,
`wayfinder_nrf::usb_link` and `blue`'s `ReportQueue` are all this, for the
same reason.

The trap is that awaiting the hardware directly *looks* fine.
`embassy_nrf`'s `Radio::receive` is memory-safe under cancellation (an
`OnDrop` guard stops the radio and fences DMA) — it just loses the frame and
leaves the receiver **off** until the next `recv`. A radio duty-cycled by
unrelated links reads as poor RF, not as a bug. `at86rf233` still awaits its
IRQ line directly inside `recv` and has the same latent problem; it is
unwired, so it has never been exercised.

## Fuzzing

`fuzz/` is an independent `cargo-fuzz` workspace (see `libs/wayfinder/CLAUDE.md`
for the general setup/conventions). `accept_fragment` fuzzes the whole
outermost boundary for any 802.15.4-radio carrier: MAC header validation,
fragment-header parsing, and reassembly. Its reassembler is **deliberately
persistent across inputs** — reassembly is stateful (capacity eviction,
duplicate indices, a mid-message count change), and a fresh table per call
would never reach any of it. No seed corpus needed; it's pure structural
parsing with no crypto barrier.
