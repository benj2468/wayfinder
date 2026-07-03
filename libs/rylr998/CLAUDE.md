# libs/rylr998

REYAX RYLR998/RYLR498 LoRa module driver. `no_std`.

`RylrClient<S>` is an async AT-command interface (`set_mode`,
`set_rf_frequency`, `set_parameters`, `send_data`, `listen_for_packet` with
RSSI/SNR), plus a `LinkT` mesh-interface adapter. Treats LoRa as a shared
broadcast medium (the mesh filters on the embedded `Mac`).

## Implementing a physical radio driver

1. Implement the `LinkT` trait (`libs/wayfinder/src/link.rs`) for your device.
2. Serialize the `LinkFrame` and send via hardware; parse received bytes back
   into a `LinkFrame` plus `LinkMetrics`.
3. Reuse `ieee802154::encode`/`decode` for 802.15.4 radios (see `at86rf233` /
   `nrf-ieee802154`); handle broadcast addressing appropriately for your medium.

The link trait is deliberately minimal and fire-and-forget: no TX-side
ACK/retry/CCA feedback in the shared trait.
