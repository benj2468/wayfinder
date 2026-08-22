# libs/wayfinder-link-utils

Shared small-MTU fragmentation/reassembly for `LinkT` drivers whose medium
caps on-air payload well below `wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN`.
`no_std`. Extracted from `libs/rylr998/src/frag.rs` once a second consumer
(`libs/blue`) needed the same scheme — the same relationship
`libs/ieee802154` has to `at86rf233`/`nrf-ieee802154` (shared framing logic,
multiple consumers).

**Wire format.** Each fragment is a 2-byte header prefixed to a slice of the
frame's `[dst][src][protocol][payload]` bytes: `[msg_id: u8][index<<4 |
count: u8]`. `count` is 1..=15 (a 4-bit field); non-final fragments always
carry exactly `FRAG_PAYLOAD` (a per-medium const generic) frame-content
bytes, so a fragment's offset is always `index * FRAG_PAYLOAD` — reassembly
needs no per-fragment length bookkeeping, only the last fragment is short. A
driver should always fragment, even a 1-fragment message, so there is
exactly one receive code path.

**Reassembly key is per-medium.** `Reassembler<A, MAX_REASSEMBLIES,
FRAG_PAYLOAD, MAX_REASSEMBLED_LEN>` is generic over `A`, the reassembly key's
address type — `FragKey<A> { addr: A, msg_id: u8 }`. A consumer picks
whatever address the medium already reports on receive when that address is
trustworthy, avoiding duplicating the 6-byte mesh `Mac` into every fragment —
but that trust has to be earned, not assumed:

- `rylr998` uses `u16` (the RYLR module's `AT+ADDRESS`) — this means
  **distinct physical nodes must be configured with distinct `AT+ADDRESS`
  values**, since the medium doesn't assign these itself.
- `blue` uses the sender's own mesh `Mac`, embedded in every fragment
  (`blue::frame::ORIGIN_LEN`), *not* the BLE advertiser address the medium
  reports. It used to be the address, on the same "no configuration burden,
  already globally distinct" reasoning as RYLR998 — until a `btmon` capture
  against a real BlueZ controller showed the address rotating on *every*
  advertising-set registration, so no multi-fragment message's fragments
  ever shared one. Embedding the origin costs 6 bytes of payload per
  fragment but doesn't depend on the medium's address behavior at all. See
  `libs/blue/CLAUDE.md` for the full story.

**Eviction, not timeout.** The reassembly table (`MAX_REASSEMBLIES`, a
per-consumer const generic) has no wall clock to expire stale partial state
— `no_std` has none available. Instead it evicts the oldest in-flight
message when a new key arrives and the table is full — the same category of
capacity-bound eviction `OgmAuth.neighbors` uses in `wayfinder::auth`, though
that one settles for always overwriting slot 0 rather than tracking true
arrival order. A message that never completes (a lost fragment) simply
occupies a slot until
capacity pressure reclaims it; acceptable on a lossy, fire-and-forget medium.

**`recv`'s control flow.** A consumer's `LinkT::recv` should loop consuming
physical packets, feeding each into `Reassembler::accept`, until *some*
message completes — not necessarily the fragment just read. See
`rylr998::link::recv` or `blue`'s `link::recv` for the shape.
