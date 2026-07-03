# libs/at86rf233

SPI driver for the Atmel/Microchip AT86RF233 802.15.4 transceiver, exposed as a
`LinkT`. `no_std`.

Generic over `embedded-hal-async` `SpiDevice`/`Wait` + `embedded-hal`
`OutputPin` (interrupt + reset GPIOs). Runs the chip in basic mode (no hardware
auto-ACK/CSMA-CA); on-air framing is delegated to `ieee802154`.

## Implementing a physical radio driver

1. Implement the `LinkT` trait (`libs/wayfinder/src/link.rs`) for your device.
2. Serialize the `LinkFrame` and send via hardware; parse received bytes back
   into a `LinkFrame` plus `LinkMetrics`.
3. Reuse `ieee802154::encode`/`decode` for 802.15.4 radios (see `at86rf233` /
   `nrf-ieee802154`); handle broadcast addressing appropriately for your medium.

The link trait is deliberately minimal and fire-and-forget: no TX-side
ACK/retry/CCA feedback in the shared trait.
