# libs/nrf-ieee802154

`LinkT` adapter for the nRF52840's built-in 802.15.4 radio (`embassy-nrf`).
`no_std`.

Adapts `libs/ieee802154`'s framing and fragmentation to the radio's `Packet`
buffer. `Ieee802154Link::new` takes a `Spawner` and the `Radio` built from the
real peripheral, configures channel/CCA/TX-power, and hands the radio to a
task it spawns.

**The `Radio` never leaves that task, and that is the point.** The driver
races every link's `recv` against the OGM timer and drops every loser, so
awaiting `Radio::receive` directly would turn the radio off between ticks —
memory-safe, but silently lossy. `recv` awaits only a channel. See the crate
docs and `docs/design/19-ieee802154-nrf-link.md` §3.3.

## Implementing a physical radio driver

1. Implement the `LinkT` trait (`libs/wayfinder/src/link.rs`) for your device.
2. Serialize the `LinkFrame` and send via hardware; parse received bytes back
   into a `LinkFrame` plus `LinkMetrics`.
3. For an 802.15.4 radio, reuse `libs/ieee802154`'s framing rather than rolling
   your own (see `at86rf233` / `nrf-ieee802154`): `assemble_frame` +
   `fragment_count` + `build_fragment` on send, `accept_fragment` +
   `decode_frame` on receive. One PHY frame carries 114 bytes of mesh content
   (a whole mesh frame reaches 512), so `recv` must **loop** until a fragment
   completes a frame. Handle broadcast addressing appropriately for your
   medium.

The link trait is deliberately minimal and fire-and-forget: no TX-side
ACK/retry/CCA feedback in the shared trait.
