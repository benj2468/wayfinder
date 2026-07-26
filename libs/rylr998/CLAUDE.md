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

## Fragmentation (`frag.rs`)

The module's AT interface caps an on-air frame at `MAX_FRAME_LEN` (180 bytes:
240 base64 chars, since payload is base64-encoded — a URL-safe alphabet,
`=`-padded, chosen so no comma/CR/LF can appear in the AT data field, same
constraint hex satisfied before it, but at a 4:3 rather than 2:1 expansion).
Real mesh frames — especially authenticated OGMs — routinely exceed that,
so `link.rs`'s `send`/`recv` split and reassemble transparently; nothing
above `LinkT` (the router, the engine) ever observes that a frame was
fragmented. `frag.rs` here is a thin adapter instantiating the shared wire
format/reassembly machinery in `libs/wayfinder-link-utils` (see that crate's
`CLAUDE.md` for the wire format, the reassembly-key genericity, and the
eviction policy) with this driver's own constants (`FRAG_PAYLOAD` = 178,
keyed by the RYLR module's 16-bit `AT+ADDRESS` — **meaning distinct
physical nodes must be configured with distinct `AT+ADDRESS` values**, since
unlike BLE this medium doesn't assign addresses itself).

One RYLR998-specific wrinkle `wayfinder-link-utils` doesn't need to know
about: base64 encoding. The frag header and frame-content slice are
concatenated *before* encoding, in one `push_base64` call — base64 packs
bits in 3-byte groups, so encoding them separately would each pad to its own
group boundary and produce bytes a single `decode_base64` call couldn't
reverse.

Two related, unrelated-looking fixes shipped alongside this:

- The AT-command line buffer (`LINE_BUF_LEN` in `lib.rs`) had to grow from 256
  to 300 bytes, since a maximal fragment's `+RCV=<addr>,<len>,<240-char
  base64>,<rssi>,<snr>` line can reach ~264 characters — a pre-existing latent
  limit that a maximal fragment now actually reaches.
- `expect()` (in `lib.rs`) was silently discarding an unsolicited `+RCV` line
  that arrived while it was waiting on a command's response — a pre-existing
  bug, not introduced by fragmentation, but fragmentation multiplies
  `AT+SEND`/`+OK` round trips per logical frame (once per fragment), which
  widened the window for it to actually bite. Fixed with a small
  `rx_queue`/`next_line` classifier: unsolicited `+RCV` lines seen mid-command
  are parsed and buffered (bounded, oldest-evicted) rather than dropped, so
  `listen_for_packet` still observes them afterward.
