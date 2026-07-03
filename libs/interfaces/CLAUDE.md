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
- `LinkMetrics` (per-frame RSSI/SNR) and `LinkError`.

## Link-layer frame format

All frames use the `LinkFrame` structure (`src/frame.rs`):

- `src: Mac` — source identifier (added by link layer)
- `dst: Mac` — destination identifier (or `Mac::BROADCAST`)
- `protocol: u16` — EtherType-style protocol identifier
- `payload: [u8]` — variable-length payload

## Zero-copy parsing

Wire-format structs derive `zerocopy`'s `FromBytes`, `IntoBytes`, `Immutable`,
`KnownLayout` so packets are parsed without allocations.
