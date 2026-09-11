# libs/interfaces

Core abstractions shared by every layer. `no_std`.

- `MeshRoutingEngine` trait — routing protocol behaviour (`handle_rx`,
  `produce_periodic_broadcast`).
- `Mac` — the node-address type: a `#[repr(transparent)]` newtype over `[u8; 6]`
  with `is_multicast`/`is_broadcast` (I/G bit), `from_ipv4_multicast`,
  `BROADCAST`, and `From<[u8;6]>`. The protocol/engine/router layers are concrete
  over `Mac`.
- `MeshIdentifier` trait — retained only as the type constraint for the still-
  generic *container* types (`IdentTable`, `LinkQualityTable`, `Switch`);
  implemented for `u8` (used by their unit tests) and `Mac`.
- `LinkFrame` / `LinkFrameData` / `LinkFrameDataMut` — zero-copy link-layer frame.
- `RoutingAction` enum — returned by routing engines: `Consumed`, `ForwardTo`,
  `DeliverLocal`, `DeliverLocalAndForward`.
- `LinkMetrics` (per-frame RSSI/SNR) and `LinkError`. Its `quality` field is
  the one thing here a driver can satisfy *incorrectly*: it is a normalized
  IEEE 802.15.4 LQI on `0..=255`, consumed verbatim, and it clamps the TQ the
  node advertises for every path over that link. A driver whose hardware
  reports something else — a correlator indicator, an ED level — must map it,
  and pin that mapping to its datasheet with a unit test, because nothing
  about the value distinguishes a correct LQI from an unscaled one.
  `nrf-ieee802154`'s `ieee_lqi` is the worked example.

## Link-layer frame format

All frames use the `LinkFrame` structure (`src/frame.rs`):

- `src: Mac` — source identifier (added by link layer)
- `dst: Mac` — destination identifier (or `Mac::BROADCAST`)
- `protocol: u16` — EtherType-style protocol identifier
- `payload: [u8]` — variable-length payload

## Zero-copy parsing

Wire-format structs derive `zerocopy`'s `FromBytes`, `IntoBytes`, `Immutable`,
`KnownLayout` so packets are parsed without allocations.
