# libs/batman

BATMAN-adv routing protocol implementation. `no_std`, heapless. Implements
`MeshRoutingEngine`.

## Types

- `BatmanEngine<MAX_ORIGINATORS, MAX_INTERFACES, MAX_MCAST_MEMBERS,
  MAX_LOCAL_MCAST>` — core engine: originator table, broadcast dedup table,
  per-interface OGM/keep-alive timer banks, and multicast membership tables
  (`local_mcast` / `mcast_members`). All but the first parameter default to the
  crate constants of the same name, so `BatmanEngine<N>` keeps host sizing.
  A constrained node picks a smaller profile instead: `BatmanEngine<16, 2, 8, 4>`
  is roughly an eighth of the host profile's footprint (`capacity_tests.rs`
  pins the ratio rather than the byte counts, which drift with every field
  added).

  **Runtime bounds must read the generic parameters, not the crate constants.**
  `configure_interface_ogm` / `configure_interface_keepalive` reject
  `idx >= MAX_INTERFACES` (the parameter); using `crate::MAX_INTERFACES` there
  would let a 2-interface profile accept index 7 and overflow its timer bank.
  `capacity_tests.rs` pins this, along with the defaults matching today's sizing.
- `BatmanOgmPacket` — Originator Messages (OGM) for topology discovery. Matches
  batman-adv's `batadv_ogm_packet` layout (`flags`, `reserved`, big-endian
  `tvlv_len`); can carry a variable-length TVLV tail after the fixed header.
- `BatmanTvlvHdr` + `find_tvlv` — Type-Version-Length-Value records in the OGM
  tail. `TvlvType::Mcast` announces the originator's joined multicast groups.
  The router adds `Cert` / `OgmSig` TVLVs for authentication; the engine
  preserves unknown TVLVs verbatim when re-flooding.
- `BatmanUnicastPacket` — unicast data packets with TTL and destination.
- `BatmanMcastPacket` — selectively-forwarded multicast copy (one per interested
  listener), routed toward `dest` like a unicast.
- `BatmanBroadcastPacket` — TTL-limited, seqno-deduplicated flooded broadcasts
  (e.g. ARP).
- `BatmanEchoPacket` — the reachability-probe pair (`EchoRequest`/`EchoReply`),
  the mesh's `ping`: no IP addresses here, so no ICMP. One header serves both
  halves, since a reply is the request with the addresses swapped and the hop
  counters carried forward. Routed toward `dest` like a unicast, with the one
  thing no other packet type does — **each relay increments `hops`**, so a probe
  carries its own path length home. `req_hops` is the forward count, frozen by
  the responder into the reply, and `hops` counts the leg in hand; both are
  reported because mesh paths are routinely asymmetric. No transmit timestamp on
  the wire: the originating node owns the ping session and already knows when it
  sent sequence *n*, so timing comes from local state rather than from bytes a
  peer handed back.
- `Trickle` (`trickle.rs`) — adaptive OGM emission timer (after RFC 6206). The
  interval doubles from `i_min` toward `i_max` while the topology is stable and
  snaps back to `i_min` on an inconsistency — near-silence in steady state,
  fast reconvergence on change. "Inconsistency" is narrower than it looks, and
  the boundary is deliberate: an OGM advertises **only this node's own state**,
  so a reset is warranted exactly when *that* changed. A new originator (we are
  likely newly reachable too), a route lost by `purge_stale`, and a change to
  our **own** multicast groups (`set_local_mcast_groups`) all reset it. A
  changed next hop toward some *other* originator does **not** — in a dense
  mesh, per-seqno TQ jitter would flip it every round and pin everyone at
  `i_min`. Neither does a *remote* originator's membership change: every
  neighbour that cares got the same OGM we did.
- `set_local_mcast_groups` / `mcast_listeners` — manage local memberships
  (announced in OGMs) and query learned `(group → originators)` memberships.

Protocol constants: `ETH_P_BATMAN` (0x4305) and the `BatmanPacketType`
`#[repr(u8)]` enum — `Ogm` (0x01), `Bcast` (0x02), `Unicast` (0x03), `Mcast`
(0x04), `CertReq` (0x05), `CertReply` (0x06), `Keepalive` (0x07),
`NextHopChallenge` (0x08), `NextHopResponse` (0x09), `EchoRequest` (0x0a),
`EchoReply` (0x0b), `RenewReq` (0x0c), `RenewReply` (0x0d). Modelled as an
enum (not free consts) so the compiler guarantees the type bytes are unique;
`as_u8()` is the wire byte, `from_u8()` decodes a received one (`None` = a type
this build doesn't know, routed by destination). Header structs keep
`packet_type: u8` for exactly that reason. `TvlvType` gets the same treatment
for OGM-tail records (`BATADV_TVLV_MCAST` is `TvlvType::Mcast`, 0x06).

## Routing logic

The engine maintains an originator table tracking `neighbor_ident` (destination
node), `best_next_hop` (immediate neighbor to forward to), `max_tq` (Transmission
Quality, 0–255), and `paths` (up to 4 alternate paths via different neighbors).

**OGM processing** (`handle_rx`, `BatmanPacketType::Ogm` arm in `src/engine.rs`):

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

**Multicast forwarding** (`handle_rx`, `BatmanPacketType::Mcast` arm +
`CentralRouter`):

1. Each node announces its locally-joined groups in its OGM's
   `TvlvType::Mcast` tail; receivers record `(group → originator)` in
   `mcast_members`.
2. To send, `CentralRouter::mcast_plan` chooses `Unicast` (1..=`MCAST_FANOUT`
   known listeners) or `Flood`. For unicast, the executor sends one
   `BatmanPacketType::Mcast` copy per listener via `handle_local_mcast`.
3. A `BatmanPacketType::Mcast` packet routes like a unicast: delivered locally
   when `dest` is self, else forwarded toward the next hop with TTL decremented.

**Broadcast flooding** (`handle_rx`, `BatmanPacketType::Bcast` arm):

1. Drops own broadcasts (loop prevention).
2. Deduplicates on `(orig, seqno)` via the engine's `broadcast_seqno` table —
   duplicates/stale are dropped.

   **Both halves of that key come from inside the payload, and no ingress
   check authenticates a `Bcast`** (only OGMs and keep-alives are gated; a
   held revocation and a link's `rx_data` flag do drop frames at ingress, but
   neither authenticates anything and neither looks at `orig`). So this is the
   one routing table an outsider writes to directly, choosing both which entry
   to touch and what goes in it.

   What makes that survivable is *not* a check on the frame — a keyless
   attacker passes every check available. It is that
   `BroadcastSeqnoEntry::admit` makes any wrong high-water self-correcting,
   whatever put it there. `admit` sorts an incoming seqno into three bands
   (`SeqnoVerdict`), and the third is the whole defence:

   - **Advance** — within `BROADCAST_SEQNO_WINDOW` ahead. Moves the high-water,
     clears any watch.
   - **Duplicate** — at or within `BROADCAST_SEQNO_REORDER_TOLERANCE` behind.
     The same flood by a second path; dropped, touching nothing.
   - **Implausible** — anything else. Opens a `SeqnoResyncWatch`, and once that
     run has persisted for `BROADCAST_SEQNO_RESET_PROTECTION` the high-water
     resynchronises **to the seqno that opened the run**, not to whichever
     frame trips the deadline.

   Three properties there are load-bearing, and issue #31's history is the
   argument for each — the first cut of the fix had only the first of them and
   was still exploitable:

   - **The behind-band is narrow.** A forgery needs no implausible leap: one
     *inside* the window is accepted as an advance, and every genuine broadcast
     the victim then sends sits behind it. If that band were merely "duplicate,
     drop", the victim would stay silent until its own counter climbed past the
     forged value — thousands of frames, hours at ARP rates, from one frame.
   - **The resync restores the seqno that opened the run.** Restoring whichever
     frame arrives at the deadline lets a third party wait out a run an honest,
     rebooting originator earned and substitute its own number — failure mode B
     again, from two frames thirty seconds apart.
   - **A full table evicts its least-recently-updated entry** rather than
     refusing the packet, which used to deny broadcast to every originator not
     already present for the life of the process. The re-seeded entry takes its
     first seqno on trust; that is deliberate (an attacker can force a first
     sighting at will, so a check would buy nothing) and safe only because of
     the band above.

   Note the asymmetry in what each failure mode costs an attacker: pinning one
   named member took a *single* frame, saturating the table takes about
   `MAX_ORIGINATORS` of them.

   The residual, which only authentication closes (design 09 §8 item 6): an
   attacker injecting *continuously*, faster than the victim broadcasts, keeps
   advancing the high-water and so keeps clearing the watch. That is a
   sustained flood, which an outsider can mount here anyway; what it can no
   longer be is a one-shot with permanent effect.

   Five `sim/scenarios/red_team.py` attacks pin this surface, and each was
   checked to report `GAP` when the property it guards is removed rather than
   merely passing: `attack_broadcast_seqno_blackhole` and
   `attack_broadcast_dedup_table_exhaustion` for the two original failure
   modes, and `attack_broadcast_seqno_in_window_jump`,
   `attack_broadcast_resync_hijack` and `attack_broadcast_evict_then_reseed`
   for the three ways the first cut of the fix was still exploitable.

   The `frame.src`-based gate that keeps suggesting itself here is *not* the
   answer and has been rejected twice (issue #31, and
   `docs/design/implemented/09-mesh-auth-gaps.md` §3's "What does *not* fix
   it"): an outsider copies a member MAC off the air, and the damage is keyed
   on `orig` anyway.

3. If TTL expired, returns `DeliverLocal` (deliver, no re-flood).
4. Otherwise writes a re-flood (TTL−1, inner frame preserved) into the reply
   buffer and returns `DeliverLocalAndForward(BROADCAST)`. The caller delivers
   the inner frame locally *and* forwards the re-flood.

**Next-hop proof** (`handle_rx`, `NextHopChallenge`/`NextHopResponse` arms):
both are `Consumed` — the engine never routes or re-floods one. They are
link-local by construction (`BatmanNextHopChallengePacket` /
`BatmanNextHopResponsePacket` carry no `dest` and no `ttl`), and the router owns
the pairwise key material the nonce and tag are checked against, keeping the
engine free of any crypto dependency. See `libs/wayfinder`'s `OgmAuth` and
`docs/design/implemented/09-mesh-auth-gaps.md` §4.

**Reachability probes** (`handle_rx`, `EchoRequest`/`EchoReply` arms →
`handle_echo`): the `handle_credential_control` twin — delivered locally at `dest` (a
request so the router can answer it, a reply so the router can credit it),
relayed toward the next live hop otherwise, dropped at `ttl <= 1`. The relay
also increments `hops`, saturating rather than wrapping: a rolled-over count
would report a two-hop path as a 258-hop one, and `ttl` is what actually bounds
the relay. Measurement-free at this layer, in the same spirit as
`handle_credential_control` being crypto-free — what a probe *means* (a session, an interval, a round-trip
time) lives in `libs/wayfinder`'s `ping.rs`.

**Unicast forwarding** (`handle_rx`, `BatmanPacketType::Unicast` arm):

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
