# libs/batman

BATMAN-adv routing protocol implementation. `no_std`, heapless. Implements
`MeshRoutingEngine`.

## Types

- `BatmanEngine<MAX_ORIGINATORS>` — core engine: originator table, broadcast
  dedup table, and multicast membership tables (`local_mcast` / `mcast_members`).
- `BatmanOgmPacket` — Originator Messages (OGM) for topology discovery. Matches
  batman-adv's `batadv_ogm_packet` layout (`flags`, `reserved`, big-endian
  `tvlv_len`); can carry a variable-length TVLV tail after the fixed header.
- `BatmanTvlvHdr` + `find_tvlv` — Type-Version-Length-Value records in the OGM
  tail. `BATADV_TVLV_MCAST` announces the originator's joined multicast groups.
  The router adds `Cert` / `OgmSig` TVLVs for authentication; the engine
  preserves unknown TVLVs verbatim when re-flooding.
- `BatmanUnicastPacket` — unicast data packets with TTL and destination.
- `BatmanMcastPacket` — selectively-forwarded multicast copy (one per interested
  listener), routed toward `dest` like a unicast.
- `BatmanBroadcastPacket` — TTL-limited, seqno-deduplicated flooded broadcasts
  (e.g. ARP).
- `Trickle` (`trickle.rs`) — adaptive OGM emission timer (after RFC 6206). The
  interval doubles from `i_min` toward `i_max` while the topology is stable and
  snaps back to `i_min` on any inconsistency (new originator, changed next hop,
  lost route, membership change) — near-silence in steady state, fast
  reconvergence on change.
- `set_local_mcast_groups` / `mcast_listeners` — manage local memberships
  (announced in OGMs) and query learned `(group → originators)` memberships.

Protocol constants: `ETH_P_BATMAN` (0x4305), `BATADV_IV_OGM` (0x01),
`BATADV_BCAST` (0x02), `BATADV_UNICAST` (0x03), `BATADV_MCAST` (0x04),
`BATADV_TVLV_MCAST` (0x06).

## Routing logic

The engine maintains an originator table tracking `neighbor_ident` (destination
node), `best_next_hop` (immediate neighbor to forward to), `max_tq` (Transmission
Quality, 0–255), and `paths` (up to 4 alternate paths via different neighbors).

**OGM processing** (`handle_rx`, `BATADV_IV_OGM` arm in `src/engine.rs`):

1. Drops own OGMs (loop prevention).
2. Creates or updates the originator record.
3. Computes path quality (TQ −= 10 per hop).
4. Selects the best path (highest TQ).
5. Folds the OGM's multicast TVLV into `mcast_members` (authoritative per
   originator, so dropped groups are pruned).
6. Forwards the OGM with decremented TTL and updated prev_sender, preserving the
   TVLV tail verbatim.

When authentication is enabled, the router's `OgmAuth::verify_ogm` runs *before*
the engine sees an incoming OGM (rejecting unsigned/forged/foreign OGMs) and
`augment_ogm` appends the cert + signature TVLVs *after* the engine builds one;
the engine itself is unchanged. See `libs/wayfinder` for `OgmAuth`.

**Multicast forwarding** (`handle_rx`, `BATADV_MCAST` arm + `CentralRouter`):

1. Each node announces its locally-joined groups in its OGM's
   `BATADV_TVLV_MCAST` tail; receivers record `(group → originator)` in
   `mcast_members`.
2. To send, `CentralRouter::mcast_plan` chooses `Unicast` (1..=`MCAST_FANOUT`
   known listeners) or `Flood`. For unicast, the executor sends one
   `BATADV_MCAST` copy per listener via `handle_local_mcast`.
3. A `BATADV_MCAST` packet routes like a unicast: delivered locally when `dest`
   is self, else forwarded toward the next hop with TTL decremented.

**Broadcast flooding** (`handle_rx`, `BATADV_BCAST` arm):

1. Drops own broadcasts (loop prevention).
2. Deduplicates on `(orig, seqno)` via the engine's `broadcast_seqno` table —
   duplicates/stale are dropped.
3. If TTL expired, returns `DeliverLocal` (deliver, no re-flood).
4. Otherwise writes a re-flood (TTL−1, inner frame preserved) into the reply
   buffer and returns `DeliverLocalAndForward(BROADCAST)`. The caller delivers
   the inner frame locally *and* forwards the re-flood.

**Unicast forwarding** (`handle_rx`, `BATADV_UNICAST` arm):

1. Checks if the packet is for the local node (`DeliverLocal`).
2. Validates TTL > 1.
3. Looks up the next hop in the originator table.
4. Returns `ForwardTo` with the immediate neighbor address.

## Fuzzing

`fuzz/` is an independent `cargo-fuzz` workspace (see `libs/wayfinder/CLAUDE.md`
for the general setup/conventions). `find_tvlv` fuzzes `find_tvlv`/`iter_tvlv`
over all four `TvlvType`s — the scanner every OGM tail (multicast, cert,
signature, revocation records) is parsed through. No seed corpus: it's pure
structural scanning with no crypto barrier, so libFuzzer explores it fully on
its own (millions of exec/s locally).
