# libs/ieee802154

Hardware-agnostic IEEE 802.15.4 framing. `no_std`.

`encode`/`decode` wrap/unwrap a `LinkFrame` in a minimal 802.15.4 MAC header
(broadcast PAN/address, no security/ack). No opinion about the radio chip; the
mesh filters on the embedded `Mac`. `MAX_FRAME_LEN` = 125. Used by the
`at86rf233` and `nrf-ieee802154` `LinkT` adapters.

## Implementing a physical radio driver

1. Implement the `LinkT` trait (`libs/wayfinder/src/link.rs`) for your device.
2. Serialize the `LinkFrame` and send via hardware; parse received bytes back
   into a `LinkFrame` plus `LinkMetrics`.
3. Reuse `ieee802154::encode`/`decode` for 802.15.4 radios (see `at86rf233` /
   `nrf-ieee802154`); handle broadcast addressing appropriately for your medium.

The link trait is deliberately minimal and fire-and-forget: no TX-side
ACK/retry/CCA feedback in the shared trait.

## Fuzzing

`fuzz/` is an independent `cargo-fuzz` workspace (see `libs/wayfinder/CLAUDE.md`
for the general setup/conventions). `decode` fuzzes `decode` — the outermost
boundary for any 802.15.4-radio carrier. No seed corpus needed; it's pure
structural parsing with no crypto barrier.
