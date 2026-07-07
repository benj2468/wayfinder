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

The module's AT interface caps an on-air frame at `MAX_FRAME_LEN` (120 bytes:
240 hex chars, since payload is hex-encoded). Real mesh frames — especially
authenticated OGMs — routinely exceed that, so `link.rs`'s `send`/`recv` split
and reassemble transparently; nothing above `LinkT` (the router, the engine)
ever observes that a frame was fragmented.

**Wire format.** Each fragment is a 2-byte header prefixed to a slice of the
`[dst][src][protocol][payload]` bytes, before hex-encoding:
`[msg_id: u8][index<<4 | count: u8]`. `count` is 1..=15 (a 4-bit field);
non-final fragments always carry exactly `FRAG_PAYLOAD` (118) frame-content
bytes, so a fragment's offset is always `index * FRAG_PAYLOAD` — reassembly
needs no per-fragment length bookkeeping, only the last fragment is short.
`send` always fragments, even a 1-fragment message, so there is exactly one
receive code path.

**Reassembly key and its deployment requirement.** `frag::Reassembler` keys
in-flight messages by `(sender's RYLR 16-bit address, msg_id)` rather than the
mesh `Mac`, since the module already reports the sender's address on every
`+RCV` line — this avoids duplicating the 6-byte `Mac` into every fragment.
**This means distinct physical nodes must be configured with distinct
`AT+ADDRESS` values** (e.g. derived from the low 16 bits of the node's mesh
`Mac`); nodes sharing an address would have their fragments cross-contaminate
in each others' reassembly slots. This is the same class of trust assumption
the mesh already makes for MAC-based filtering.

**Eviction, not timeout.** The reassembly table (`MAX_REASSEMBLIES` = 4
concurrent in-flight messages) has no wall clock to expire stale partial
state — `no_std` has none available. Instead it evicts the oldest in-flight
message when a new key arrives and the table is full, mirroring the
capacity-bound eviction `OgmAuth.neighbors` uses in `wayfinder::auth`. A
message that never completes (a lost fragment) simply occupies a slot until
capacity pressure reclaims it; acceptable on a lossy, fire-and-forget medium.

**`recv`'s control flow.** `LinkT::recv` loops consuming physical `+RCV`
packets, feeding each into the reassembler, until *some* message completes —
not necessarily the fragment just read. This adds no new starvation risk
versus before: every iteration still awaits real serial I/O, exactly as
`listen_for_packet` already did.

Two related, unrelated-looking fixes shipped alongside this:

- The AT-command line buffer (`LINE_BUF_LEN` in `lib.rs`) had to grow from 256
  to 300 bytes, since a maximal fragment's `+RCV=<addr>,<len>,<240-char
  hex>,<rssi>,<snr>` line can reach ~264 characters — a pre-existing latent
  limit that a maximal fragment now actually reaches.
- `expect()` (in `lib.rs`) was silently discarding an unsolicited `+RCV` line
  that arrived while it was waiting on a command's response — a pre-existing
  bug, not introduced by fragmentation, but fragmentation multiplies
  `AT+SEND`/`+OK` round trips per logical frame (once per fragment), which
  widened the window for it to actually bite. Fixed with a small
  `rx_queue`/`next_line` classifier: unsolicited `+RCV` lines seen mid-command
  are parsed and buffered (bounded, oldest-evicted) rather than dropped, so
  `listen_for_packet` still observes them afterward.
