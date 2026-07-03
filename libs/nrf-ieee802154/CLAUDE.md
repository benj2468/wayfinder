# libs/nrf-ieee802154

`LinkT` adapter for the nRF52840's built-in 802.15.4 radio (`embassy-nrf`).
`no_std`.

Adapts `ieee802154::encode`/`decode` to the radio's `Packet` buffer; the caller
constructs the `Radio` from the real peripheral.

## Implementing a physical radio driver

1. Implement the `LinkT` trait (`libs/wayfinder/src/link.rs`) for your device.
2. Serialize the `LinkFrame` and send via hardware; parse received bytes back
   into a `LinkFrame` plus `LinkMetrics`.
3. Reuse `ieee802154::encode`/`decode` for 802.15.4 radios (see `at86rf233` /
   `nrf-ieee802154`); handle broadcast addressing appropriately for your medium.

The link trait is deliberately minimal and fire-and-forget: no TX-side
ACK/retry/CCA feedback in the shared trait.
