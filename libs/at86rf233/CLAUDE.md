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
3. For an 802.15.4 radio, reuse `libs/ieee802154`'s framing rather than rolling
   your own (see `at86rf233` / `nrf-ieee802154`): `assemble_frame` +
   `fragment_count` + `build_fragment` on send, `accept_fragment` +
   `decode_frame` on receive. One PHY frame carries 114 bytes of mesh content
   (a whole mesh frame reaches 512), so `recv` must **loop** until a fragment
   completes a frame. Handle broadcast addressing appropriately for your
   medium.

The link trait is deliberately minimal and fire-and-forget: no TX-side
ACK/retry/CCA feedback in the shared trait.
