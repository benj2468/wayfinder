# Design: Revocation durability — local persistence + peer catch-up + CA-pull reconciliation

**Status:** Proposed. Grew out of issue #3's still-open "revocation
re-propagation" question, generalized beyond CA restart to any node restart.

**Scope:** `libs/wayfinder-auth` (`RevocationRecord`; the durable-cache trait
lives in a to-be-designed generic store crate, see Prerequisites),
`libs/wayfinder/src/auth.rs` (`OgmAuth`: load/save hooks, the reconciliation
trigger, the peer-catch-up burst + strip-on-re-flood + overhear-and-answer
path, per-requester rate limiter), `libs/batman/src/wire.rs` (two new routed
control packets mirroring `CertReq`/`CertReply`, and a new OGM-tail TVLV
marker) + `libs/wayfinder/src/lib.rs` (demux/originate/handle for all three),
`libs/wayfinder-server` (the CA-side responder via `MeshAuthority`, a `std`
file-backed store impl). No new node config field — the CA is addressed via
on-demand discovery, not static config (§3.2). No change to `RevocationRecord`
itself, to `LinkT`/`FrameIo`, or to the existing OGM-tail flood mechanism,
which is retained unchanged as the steady-state propagation path.

**Prerequisites — raised in MR review, not resolved in this document:**

1. **A generic persistent-record-store abstraction, designed separately
   (proposed as design 04) before §3.1 is implemented.** `RevocationStore`
   below is written as its own bespoke trait, but this is the *second*
   near-identical persistence pattern in this codebase (`CaLog` in
   `wayfinder-server/src/persistence.rs` is the first) — a sign a shared
   no_std/std abstraction is warranted now rather than letting ad-hoc copies
   accumulate. §3.1 should be rewritten to build on that shared abstraction
   once it exists, including retrofitting `CaLog` onto it. This also folds in
   the embedded flash story more coherently than treating it as a one-off
   non-goal (§2) — see the updated non-goal bullet.
2. **`BATADV_*` packet-type constants need to become a proper enum** (mirroring
   how `TvlvType` already does this with `as_u8()`) **in a small, separate MR,
   landed before** `BATADV_REVOKE_SYNC_REQ`/`_REPLY` are added — so the
   compiler enforces byte-value uniqueness across packet types instead of
   relying on comments across scattered `pub const` declarations (§3.3.1).
3. **The `ca_mac` addressing approach (§3.2) needs explicit sign-off, not just
   review-in-passing** — it's a security-posture trade-off (how discoverable
   the CA's identity is), not a technical correctness question this document
   can settle unilaterally. See §3.2 and §10.9.

---

## 1. Motivation

`OgmAuth.revocations` (`libs/wayfinder/src/auth.rs`) is bounded (`MAX_REVOKED`
= 32), in-RAM, and **never persisted** — by design, since router state is a
documented host-persistence non-goal (issue #3 scopes persistence to
`wayfinder-server`'s `CertAuthority` only; the `no_std` core stays ephemeral).
Meanwhile, propagation of a new revocation is a deliberately *one-shot* burst:
each node that ingests a new record re-advertises it on its own OGMs for
`REVOKE_FLOOD_BUDGET` (6) emissions, then goes quiet — the record stays in the
local set (still dropping the node) once the budget is spent; only its
re-advertisement stops (`auth.rs`, `ingest_revocation` / `augment_ogm`).

Put together: **any node that restarts, or was down through an entire flood
window, has no way to learn a still-active revocation** short of the
underlying certificate's own passive expiry. This is not hypothetical — it is
the current, shipped behavior of every node in the mesh, not just the CA. A
node that reboots (brownout, driver restart, firmware update) forgets every
revocation it once enforced and will silently re-trust a revoked-but-not-yet-
cert-expired peer until either (a) a neighbor happens to still be inside that
record's flood window, or (b) the cert itself expires.

This design closes that gap **three ways**, cheapest-first:

1. **Local persistence** — a node keeps what it already knew across its own
   restart (cheap, local, zero network cost). Fixes the common case: the same
   node rebooting.
2. **Peer catch-up** — on a fresh/stale start a node emits a bounded OGM-tail
   marker asking neighbors to hand over their current revocation set; any
   neighbor holding one answers directly over the link (nearly free,
   partition-tolerant, needs no CA and no route). Fixes the fast, local case: a
   fresh node next to informed neighbors.
3. **CA-pull reconciliation** — when its local view might be stale relative to
   what it missed while down, a node pulls an authoritative, date-filtered set
   from the CA (rare, authoritative, paid only when actually needed, and the
   only mechanism that can *prove* the node's whole view is current).

The three are layered and complementary, not redundant: persistence eliminates
the majority of restarts before any packet is sent; peer catch-up covers the
rest quickly and even across a CA partition; CA-pull is the authoritative
backstop that alone clears a node's "stale" flag (§3.4, §3.7).

## 2. Goals / Non-goals

**Goals**
- A node's own restart no longer erases its revocation enforcement state.
- A fresh or stale node can be caught up **immediately by a 1-hop neighbor**
  that already holds revocations, over the link it is already on — no route, no
  CA reachability required (partition-tolerant catch-up).
- A node that was down through a flood window (or is brand new) can recover
  an authoritative, **date-filtered** set of currently-live revocations from
  the CA — never one that's already expired by the time it's sent.
- The CA recovery pull is a **request/reply**, not a broadcast: the CA's full
  revoked set is never flooded to the mesh, only delivered point-to-point to
  the node that asked.
- Reuse `RevocationRecord` verbatim as the flood unit, the peer-reply unit, and
  the CA-pull-reply unit, so `ingest_revocation` handles a record identically
  regardless of how it arrived.

**Non-goals**
- **CA-routing-intercept peer answering** — trying to give the CA-pull
  request/reply the "any on-path node answers early" property that
  `CertReq`/`CertReply` has. Rejected: that property is *unsound* for
  revocations (§9), and it is a different thing from the neighbor-broadcast
  peer catch-up this design **does** adopt (§3.7). The distinction is
  load-bearing — see §9 so the two are never conflated again.
- **Fine-grained delta/epoch cursors** (a `CaLog` schema migration adding a
  revocation sequence number, letting the CA send only records newer than a
  client-presented watermark). Rejected as unnecessary complexity — see §9.
- Embedded (flash-backed) `RevocationStore` implementation, **and the
  bespoke `RevocationStore` trait itself, pending the generic-store design
  (prerequisite #1, above).** No `embedded-storage` usage exists anywhere in
  this repo today, and neither embedded bin wires up `OgmAuth` yet. Once the
  generic store design lands, an embedded revocation-cache backend becomes
  "just another backend of that store," not a bespoke flash driver written
  for this feature alone — a materially different (and better) scope than
  writing a one-off embedded impl here.
- Any change to the in-mesh flood mechanism (`REVOKE_FLOOD_BUDGET`,
  `MAX_REVOKE_PER_OGM`, `prune_expired`) — it remains the steady-state
  propagation path, unchanged.

## 3. Design

### 3.1 Local persistence: `RevocationStore`

**This section is provisional, pending prerequisite #1 (Scope).** The trait
below sketches the shape this design needs; the actual implementation should
sit on top of a generic persistent-record-store abstraction shared with
`CaLog` (a separate design, proposed as 04), not stand alone as a second
bespoke persistence trait. Treat what follows as "what `RevocationStore`
needs to be able to do," not a final API to build against.

A small `no_std` trait in `libs/wayfinder-auth`, next to `RevocationRecord`
(which already derives `FromBytes`/`IntoBytes`/`Immutable`/`KnownLayout`/
`Unaligned` — a fixed 92-byte POD struct, so persisting it is raw bytes, no
serde, no alloc):

```rust
/// Local durable cache of this node's own revocation enforcement state, so a
/// restart doesn't erase what it already knew. Not an authoritative source —
/// see `RevocationRecord`'s docs for the CA-pull reconciliation path that
/// covers what a restart-persisted cache cannot: revocations issued entirely
/// during a downtime window.
pub trait RevocationStore {
    type Error;
    /// Load persisted records into `out`, returning how many were read, plus
    /// the last successful CA-reconciliation instant (0 if never reconciled).
    fn load(&mut self, out: &mut [RevocationRecord]) -> Result<(usize, u64), Self::Error>;
    /// Overwrite the persisted set and last-reconciled instant.
    fn save(&mut self, records: &[RevocationRecord], last_reconciled_unix: u64)
        -> Result<(), Self::Error>;
}
```

`OgmAuth` takes an `Option<impl RevocationStore>` at construction, loads at
startup, and calls `save()` after every mutation to `revocations` (new ingest,
prune-on-expiry) — the same persist-inside-a-mutation shape `CaLog` already uses
via `mutate_issued`/`mutate_held` in `wayfinder-server/src/persistence.rs`, for
consistency. `last_reconciled_unix` is written only after a *successful CA-pull*
completes (§3.4), never on ordinary flood ingestion **nor on a peer answer**
(§3.7) — those prove one record is known, not that the node's whole view is
current.

**What's persisted, deliberately not `floods_left`.** Only the raw
`RevocationRecord`s and `last_reconciled_unix`. On restore, records are
re-armed with a small nonzero flood budget (open decision, §10) rather than 0
— a node that crash-looped through its original flood window would otherwise
sit on a permanently-silent copy, unable to help a neighbor who also missed
it, even though the record's signature is still independently valid forever.

**`std` implementation:** now superseded by prerequisite #1 — this should be
the same `DurableStore` file backend design 04 defines for `CaLog`, reused
rather than reimplemented (`persistence.rs`'s `save_atomic`: write a `.tmp`
sibling, `sync_all` the file, `rename` over the target — note it's a free
function today, not a `CaLog` method, and it deliberately does *not* `fsync`
the parent directory, an accepted lower-severity gap per its own doc comment,
not an oversight to silently "fix" while reusing it).

**Embedded implementation:** out of scope for this design (§2's non-goals);
the trait is shaped to support an `embedded-storage`-backed flash-sector impl
later without changing `OgmAuth`'s side of the contract.

### 3.2 Addressing the CA

There is currently **no way for an ordinary node to name the CA as a routing
target.** `TrustAnchor` (`libs/wayfinder-auth/src/cert.rs`) holds `mesh_id` +
`root_pubkey` only — the CA is identified by its *signing key*, never by a
network address, and no config field carries its MAC today. This is a
genuine prerequisite gap, not a detail to wave past.

**Revised proposal (superseding an earlier draft's static `ca_mac` config
field — see §9 for why that was rejected in review):** an on-demand,
**root-key-signed discovery announcement**, not baked-in config.

- A node that needs to reach the CA and doesn't have a cached address emits a
  small discovery query (analogous in spirit to the peer-catch-up marker,
  §3.3.2 — a bounded, cheap signal, not a standing broadcast).
- Only the CA can answer authentically: the response is signed by the mesh
  **root private key** directly (`TrustAnchor.root_pubkey` is already trusted
  by every node for exactly this kind of check, so verifying this
  announcement needs **no new trust assumption** — it's the same key that
  backs every `MembershipCert` and `RevocationRecord`). An ordinary member,
  however compromised, cannot forge this response, because it never holds the
  root private key.
- The discovered MAC is cached locally (not persisted as durable config) and
  can be re-queried if it goes stale (e.g., the CA moves to a different
  physical node — a config-based `ca_mac` would require re-flashing every
  node in that scenario; this doesn't).

**Why this is better than static config, per review:**
- **No embedded-management-API dependency.** A static `ca_mac` field is only
  as good as the ability to change it post-deployment, and no embedded node
  in this repo has a management interface to do that yet (§1's own framing —
  auth doesn't even run on embedded targets currently). On-demand discovery
  needs no reconfiguration channel at all.
- **Doesn't assume the CA is a fixed, permanent physical node.** A config
  field permanently binds every node's flash image to "wherever the CA
  happens to be running today."

**What this does *not* solve, stated plainly rather than glossed over:** it
narrows the CA's discoverability, it does not eliminate it. Any mechanism
that lets a legitimate node find the CA is available on the same terms to a
compromised member node — the protocol has no cheap way to distinguish a
genuine reconciliation need from a hostile node profiling the mesh for its
highest-value target. Querying-on-demand (rather than every node's static
config trivially revealing it, including nodes that were never compromised
leaking it if their flash is dumped) is a real improvement, not a full fix.
Whether the deeper problem — a single, nameable node is the mesh's entire
root of trust — needs a structural answer (redundancy, threshold signing,
some other approach) is a larger architectural question this document
doesn't attempt to resolve. **This whole section needs explicit sign-off,
not silent adoption** (§10.9) — it's a security-posture trade-off, not a
technical correctness call.

Note the asymmetry either way: **peer catch-up (§3.7) needs no CA address at
all and works regardless**, so a CA-less or CA-partitioned mesh still gets
neighbor-driven catch-up; only the authoritative pull needs to find the CA.

### 3.3 Wire format

**Note on `ca_mac` in what follows:** per §3.2's revision, this is now a
locally cached, discovered value (root-signed at discovery time), not a
config field — the name is kept as shorthand for "this node's current
best-known CA address" throughout the rest of this document.

#### 3.3.1 CA-pull routed control packets

**Blocked on prerequisite #2 (Scope): `BATADV_*` packet types must become a
proper enum first.** `libs/batman/src/wire.rs` today spells these out as
individual `pub const XXX: u8` declarations (`BATADV_IV_OGM`, `BATADV_BCAST`,
`BATADV_UNICAST`, `BATADV_MCAST`, `BATADV_CERT_REQ`, `BATADV_CERT_REPLY`),
unlike `TvlvType`, which already gets proper-enum treatment with an `as_u8()`
method. Land that refactor as its own small MR first, so the compiler (not a
comment thread) enforces that no two packet types collide — then add these two
as new variants of that enum, not as two more raw consts:

Two new routed control packets, structurally identical in spirit to
`BATADV_CERT_REQ` (`0x05`) / `BATADV_CERT_REPLY` (`0x06`) in
`libs/batman/src/wire.rs`, taking the **next free** packet-type values after
that pair (illustrated here as consts for readability; implement as enum
variants per the above):

```rust
pub const BATADV_REVOKE_SYNC_REQ: u8 = 0x07;   // next free after CERT_REPLY = 0x06
pub const BATADV_REVOKE_SYNC_REPLY: u8 = 0x08;
```

**Request** — self-authenticating, same shape as `CertReq`: carries the
requester's own `MembershipCert` plus a signature over
`domain ‖ requester_mac` (a distinct domain-separation prefix, e.g.
`b"wf-revsync-req-v1"`), so the CA can verify the requester is a legitimate,
non-revoked mesh member without a separate lookup — and so an outsider can't
use this to probe the mesh or waste the CA's cycles. No cursor/epoch field —
see §2's non-goals; the CA always replies with its complete current live set.
Unlike a `CertReq`, this packet has **no early-answer path**: only the CA holds
the authoritative issued log, so the request routes all the way to `ca_mac` and
is answered only there (§3.6, §9).

**Reply** (`BATADV_REVOKE_SYNC_REPLY`) — paginated, because a full reply can
exceed on-link limits (§3.5): a small header (`version`, `mesh_id`,
`page_index: u8`, `page_count: u8`) followed by up to a capped number of raw
`RevocationRecord`s (propose 4, matching `MAX_REVOKE_PER_OGM`'s existing
per-unit cap for consistency). For a CA reply, each record is freshly signed at
query time from the CA's persisted `(node_mac, cert_not_after)` — see §3.6 —
not replayed from the original `revoke()` call, so no new persisted signature
bytes are needed.

#### 3.3.2 Peer-catch-up OGM marker + reply reuse

One new OGM-tail TVLV, taking the **next free** `TvlvType` value after the
existing set (`Mcast = 0x06`, `Cert = 0x80`, `OgmSig = 0x81`, `Revoke = 0x82`,
`CertFp = 0x83`):

```rust
RevSyncReq = 0x84   // "I am catching up — send me your revocation set"
```

The marker's *presence* is the request; its value is a single version byte for
forward-compat, no payload. It is attached to the requester's **own OGM
emissions** for a bounded burst (§3.7), following exactly the
`REVOKE_FLOOD_BUDGET`-style "bounded burst then stop" philosophy — and
explicitly **not** the always-on philosophy of `CertFp` (`CertFp` is
load-bearing for OGM auth on every emission; this marker is a one-time bootstrap
catch-up signal only).

**The marker must be stripped on every re-flood — this is load-bearing, not
an optimization** (raised in MR review: as originally drafted, this document
claimed "responder and requester are 1-hop neighbors by construction" without
actually enforcing it). `batman::engine`'s re-flood path preserves an OGM's
TVLV tail **verbatim** by design (`engine.rs`, ~line 569-570) — so without an
explicit exception, this marker would ride every re-flood out to the mesh's
full diameter, and *every* node at *every* hop holding revocation state would
reply, not just true 1-hop neighbors. That is exactly the "entire mesh
answering at once" airtime waste flagged in review.

Fix: **every relay removes `RevSyncReq` from the tail before its own
re-flood.** This can't happen inside `batman::engine` itself, which is
deliberately crypto/auth-agnostic and forwards TVLV bytes without
interpreting them (wayfinder's own `CLAUDE.md`: "the engine stays free of any
crypto dependency") — the strip has to happen at the router/auth layer
(`OgmAuth`/`lib.rs`), the same layer that already knows what this TVLV means.
It is safe to mutate: `OgmSig` never covers `RevSyncReq` (it's appended after
signing, exactly like the opportunistic `Revoke` records `augment_ogm`
already attaches to *originated* OGMs — neither is part of what the signature
protects), so removing it on a *re-flooded* OGM doesn't touch anything the
signature covers and doesn't require re-signing. The practical effect: a node
at hop 2 receives the OGM from a relay that has already stripped the marker,
so it never sees it at all — visibility is mechanically bounded to true
1-hop neighbors, by construction, not by trusting the claim.

Crucially, the marker needs **no signature of its own**: it rides an OGM that
the overhearing neighbor already authenticates via the existing `OgmSig`
verification before processing. On an auth mesh a non-member's OGM is dropped
outright, so a non-member's marker is never honored — self-authentication comes
for free, without the standalone signature a routed `CertReq`/`RevokeSyncReq`
needs.

The **peer reply reuses `BATADV_REVOKE_SYNC_REPLY`** verbatim — same header,
same 4-records-per-page cap, same pagination (§3.5) — rather than inventing a
second reply scheme. The only difference from a CA reply is provenance: a peer
forwards the root-signed `RevocationRecord`s it already holds, unchanged (they
are self-authenticating; the requester verifies each against the trust anchor
identically regardless of who relayed it). The requester distinguishes an
authoritative reply from a peer reply purely by **source**: a completed reply
whose origin is `ca_mac` clears staleness; anything else is additive-only
(§3.7). (This also transparently handles the corner where the CA node itself
overhears a marker and answers as a neighbor — it *is* `ca_mac`, so its answer
is authoritative, exactly as desired.)

All routed packets hop-by-hop exactly like `CertReq`/`CertReply` — no new
routing logic, just new packet types recognized in `CentralRouter`'s demux
(`lib.rs`) the same way `BATADV_CERT_REQ`/`_REPLY` are today. The peer reply,
by contrast, is **not multi-hop routed at all** (§3.7): responder and requester
are 1-hop neighbors by construction.

### 3.4 CA-pull trigger policy — deciding *when* to pull

This is the crux of the CA-pull path, so it gets its own section rather than
being implied.

**State:** one persisted `u64`, `last_reconciled_unix` (0 = never), living
alongside the revocation cache in `RevocationStore` (§3.1).

**Staleness predicate.** Once the driver sets a real wall-clock time (mirroring
`OgmAuth::set_time`'s existing "first real time" semantics — `now_unix == 0`
means no clock yet, do nothing):

```
stale = last_reconciled_unix == 0
     || (now_unix - last_reconciled_unix) > RECONCILE_MAX_AGE_SECS
```

**Concretely, when a pull is issued.** If `stale`, `OgmAuth` sets a
`needs_reconciliation` flag — the same take-and-clear pattern already used for
`trickle_reset_hint`. On each router `poll`, while that flag is set and no
request is already in flight, the router checks whether a route to `ca_mac`
resolves (ordinary BATMAN convergence). As soon as one does, it originates
exactly one `RevokeSyncReq` and moves to in-flight tracking (mirroring
`InFlightCertRequest` / `CERT_REQUEST_RETRY_SECS` / `MAX_CERT_REQUEST_ATTEMPTS`).
There is **no first-hop-seeding trick** here the way `CertReq` has one: `CertReq`
can borrow a next-hop from the very OGM that triggered it, but a staleness pull
has no such triggering OGM, and in any case only `ca_mac` can answer, so the
node simply waits for a normal route to that fixed destination — the same as any
other unicast to a configured target.

**On a fully-received CA reply** (all pages, or a reply that explicitly says
zero revocations — that's still a successful reconciliation, not "nothing
happened"), *and only when the reply's origin is `ca_mac`*: ingest every record
via the existing `ingest_revocation()`, then set and persist
`last_reconciled_unix = now_unix`.

**On failure** (no route ever resolves, or retries exhaust — same bounded-retry
shape as `CertReq`): `last_reconciled_unix` is left unchanged, so the node stays
"stale" and will try again — at minimum on its next boot; whether it also
retries periodically *without* rebooting is an open decision (§10), since it
changes the traffic model from "boot-triggered only" to "a new periodic timer
alongside the driver's OGM loop."

**Picking `RECONCILE_MAX_AGE_SECS`:** it should track the mesh's flood horizon
— roughly how long a freshly-ingested revocation keeps actively re-propagating
before every hop's budget is spent — which scales with the slowest configured
link's Trickle `i_max`. Rather than auto-deriving this across layers (`OgmAuth`
doesn't otherwise know per-link Trickle config), this design keeps it a plain
configured value with a documented default (propose 1 hour) and that reasoning
written down as guidance for operators tuning it — see §10 and §9 for the
auto-derivation alternative considered and deferred.

The **peer-catch-up** burst (§3.7) is triggered separately and much more
cheaply; its relationship to this staleness check is spelled out in §3.7 under
"Composition with the CA-pull trigger."

### 3.5 A concrete sizing constraint

`frag::MAX_REASSEMBLED_LEN` on the rylr998 link is 512 bytes. A worst-case
32-record reply is ~2944 bytes (`92 bytes × MAX_REVOKED`) — this **exceeds**
that ceiling outright, independent of the `AT+SEND` on-air cap. This isn't a
tunable judgment call the way the flood-budget-on-restore question is (§3.1) —
pagination at the application layer (§3.3) is mandatory for correctness on this
link, not an optimization. Because the peer reply reuses the same reply framing
(§3.3.2) and a peer likewise holds up to `MAX_REVOKED` records, the identical
pagination cap applies to it — reuse it, don't re-derive a second cap.

### 3.6 CA-side responder

The authoritative answer requires the CA's **issued-certificate log**, which
lives in `wayfinder-server`'s `CertAuthority` (`authority.rs`) — *not* in the
router's `OgmAuth`. This is the one structural asymmetry from `CertReply`: a
`CertReply` is answered entirely inside `OgmAuth` from its own cert cache,
whereas a `RevokeSyncReq` cannot be, because `OgmAuth` has no issued log.

**Not through `RouterAdapter`** (corrected in review — the original draft of
this section routed the reply through it, which is the wrong seam).
`RouterAdapter` (`adapter.rs:43-50`) is specifically the **management-API-facing**
projection: it exists to serve `WayfinderService` (an *operator* querying this
node), and wraps `Option<&mut dyn MeshAuthority>` for exactly that purpose. A
`RevokeSyncReq` is not a management-API call — it's a **mesh-peer wire
protocol request** arriving from another node over the radio/link, structurally
identical in origin to a `CertReq`. Routing it through the operator-facing
adapter would conflate two different roles that are deliberately kept
separate everywhere else in this codebase.

The correct seam: the driver already holds `provider: Option<Box<dyn
MeshAuthority>>` directly (`provider.rs`) — the same trait `RouterAdapter`
delegates to, but reachable independent of it. On the CA node, the flow is:
the router receives and locally-delivers the `RevokeSyncReq` (exactly as it
does a `CertReq`), and the **driver's mesh-frame dispatch** (not the mgmt-API
path) calls a new method added directly to `MeshAuthority` — e.g.
`fn build_revocation_sync_reply(&self, now_unix: u64) -> Vec<u8>` — to obtain
the encoded records, which the router then paginates (§3.3.1) and routes back
as `RevokeSyncReply`. This exactly mirrors the existing asymmetry: `revoke_node`
is invoked *from* the mgmt API *via* `RouterAdapter`; this is invoked *from
the mesh* *via* the driver holding `MeshAuthority` directly — same trait,
opposite direction, and neither conflated with the other.

An **ordinary (non-CA) node has no issued log and therefore never answers** a
`RevokeSyncReq` — it only forwards it onward toward the CA. That is consistent
and desirable: it is precisely why the CA-pull path has no early-answer
(§3.3.1, §9), and it is the reason the neighbor-broadcast peer path (§3.7)
exists as a *separate* mechanism rather than as an early-answer bolt-on to
this one.

Building the reply in `CertAuthority`: filter `issued` to
`revoked && not_after > now_unix` — the "certs in the base set must be active by
date" requirement, enforced authoritatively at the source rather than trusted
client-side — and for each surviving entry, mint a fresh `RevocationRecord` via
`Authority::revoke`-equivalent signing, using the **persisted cert's own
`not_after`** (`IssuedRecord.not_after`, which already exists) as the
revocation's `not_after`. Note this is deliberately *more* conservative than the
live `CertAuthority::revoke` path, which stamps `now_unix + cert_ttl_secs`
(`authority.rs`): reusing the cert's own expiry means nothing is ever handed out
with more enforcement lifetime than the cert it cancels actually has left,
matching the invariant `RevocationRecord.not_after`'s own doc comment already
states. No new persisted fields are needed.

### 3.7 Peer-seeded catch-up (broadcast trigger + neighbor response)

This is the cheap, partition-tolerant middle layer between local persistence and
CA-pull. It has three parts.

**Trigger — the requester's burst.** On a fresh/stale start (§3.4's clock-ready
point), `OgmAuth` arms a small per-node budget (mirror `floods_left`; propose a
`REVOKE_SYNC_REQ_BUDGET` of a handful of emissions, open decision §10). While
that budget is nonzero, `augment_ogm` attaches a `RevSyncReq` TVLV (§3.3.2) to
this node's own OGM and decrements the budget; at zero it stops. This is a
one-shot burst on OGMs the node was going to send anyway — a few extra TVLV
bytes on a handful of emissions, no new packets, no route needed.

**Response — a neighbor answers directly, after a jittered listen.** Any node
that (a) already authenticated the requester's OGM (so it holds a fresh 1-hop
route to the requester and has confirmed the requester is a member) and (b)
currently holds a **nonzero** revocation set is a *candidate* responder. Given
the strip-on-forward fix (§3.3.2), candidates are now correctly bounded to
true 1-hop neighbors of the requester — but on a shared/broadcast medium
(LoRa) there can still be several such neighbors at once, and **each one
independently replying is a real airtime cost, not a free no-op** (raised in
review, correcting an earlier draft of this section that only evaluated
redundancy against storage/dedup cost, never against airtime — the actual
scarce resource this whole design exists to protect). Fix: each candidate
waits a short random jittered delay before replying, and **cancels its own
reply if it overhears another node's `BATADV_REVOKE_SYNC_REPLY` addressed to
the same requester first** — the same listen-before-transmit suppression
idiom this codebase already relies on for Trickle's OGM backoff, applied here
to a one-shot reply instead of a periodic schedule. This only does useful work
on a medium where siblings can overhear each other's traffic (true of LoRa,
where reception is inherently broadcast at the physical layer regardless of
addressing — see `libs/rylr998/src/link.rs`'s own framing of this); on a
genuinely point-to-point link (a single peer per link, e.g. a wired
UDP/TAP-bridge carrier) there is at most one candidate anyway, so suppression
is simply moot there, not broken.

Once bounded this way, the reply itself stays simple: responder and requester
are neighbors *by construction* the moment the (correctly 1-hop-scoped) marker
is overheard, so the reply is a direct link-addressed unicast (or,
equivalently, a route via the route the OGM just installed) — **it needs none
of the first-hop-seeding trick `CertReq` requires (lazy-cert §3.2) and none of
the pending-query machinery `CertReply` needs for an absent return route
(lazy-cert §3.3/§3.5)**. This path is strictly *simpler* than `CertReq`'s hard
part, not a variant of it — a future reader must not mistake it for one. A
node whose revocation set is empty simply stays silent (nothing to offer). Any
reply that does go out still sends its full (bounded, ≤32-record, usually far
smaller) set rather than a diff — `ingest_revocation`'s dedup makes a
duplicate record a free *storage* no-op, which is still the right reason to
skip building a digest/diff protocol (§9); it was never, on its own, a reason
to skip bounding *how many replies get sent in the first place*, which is
what the suppression window above actually does.

**Ingestion — additive only, never authoritative.** The requester feeds every
record from a peer reply through the existing `ingest_revocation()` immediately,
for real enforcement value right away, **but must not set
`last_reconciled_unix`** (§3.1). A peer's view is convergent gossip, not a
completeness guarantee: the responding peer might itself be on a stale local view
(its own flash restore, or a record it lost to `MAX_REVOKED`-capacity eviction).
Only a completed *CA* reply, whose responder authoritatively filtered `issued`
by `revoked && not_after > now` (§3.6), proves the whole view current and
therefore sets `last_reconciled_unix`. This is exactly why CA-pull stays in the
design as the authoritative backstop: peer response does not obsolete it, it
reduces how urgently and how often CA-pull is actually needed and gives
catch-up coverage in situations CA-pull structurally cannot — a CA-less mesh, or
a node partitioned from the CA but not from its neighbors.

**Composition with the CA-pull trigger (§3.4).** Recommended policy (recorded as
an explicit open decision, §10, not silently assumed):

- The peer-catch-up burst fires **at every fresh/stale start**, unconditionally
  — it is nearly free (a few TVLV bytes on this node's own OGMs) and worth doing
  whenever the node is fresh or stale.
- The heavier CA-pull round trip stays gated behind the `RECONCILE_MAX_AGE_SECS`
  staleness check (§3.4), because it costs a routed request/reply to a possibly
  distant CA.
- The two run **concurrently**, not sequenced. A "give the peer burst a head
  start, then pull the CA" variant was considered and is *not* recommended:
  because a peer answer never sets `last_reconciled_unix` (above), the CA-pull
  must run regardless to clear staleness, so delaying it would only prolong the
  stale window with no correctness or airtime benefit — the two mechanisms are
  independent and idempotent (peer records dedup for free against whatever the
  CA later sends), so there is nothing to gain by ordering them and one fewer
  timer to maintain by not doing so.

**Rate-limiting the responder.** A malicious or malfunctioning neighbor could
spam the `RevSyncReq` marker to bait others into wasteful replies. Mitigate with
the same per-requester spacing already used for `CertReq`
(`accept_cert_request_rate` / `cert_req_rate` / `CERT_REQ_RATE_LIMIT_SECS` in
`auth.rs`): a `revsync_req_rate` table (bounded, first-slot eviction, identical
shape) that refuses to answer the same requester more than once per window. See
§5.

## 4. Correctness / edge cases

- **No route to the CA, ever** (discovery never resolves an address, or the
  discovered `ca_mac` is genuinely unreachable):
  CA-pull never fires; the node stays on local persistence + peer catch-up +
  ordinary flood. `last_reconciled_unix` stays 0 (the node reads as "never
  authoritatively reconciled", which is *true* and not a bug — without a
  reachable CA there is no authoritative source to reconcile against). Peer
  catch-up still runs every boot, so a CA-less or CA-partitioned mesh is not
  left without any recovery path. Not a regression, not a crash.
- **Reply arrives after the record has since expired** (slow multi-hop CA path,
  or a slow peer): `ingest_revocation` already drops anything with
  `not_after <= now_unix` (`auth.rs`) — no new check needed, reused as-is for
  both reply kinds.
- **A reconciliation (CA or peer) races an ordinary flood ingesting the same
  record**, or two peers answer the same marker: `ingest_revocation`'s existing
  MAC-dedup makes the later arrival — whichever order — a harmless no-op.
- **Peer answers but its own view is stale/incomplete**: the requester gains
  whatever the peer had (still useful) but does **not** mark itself reconciled,
  so a CA-pull still fires per §3.4. Convergent, never falsely "complete".
- **Marker overheard by a node with an empty revocation set**: it stays silent.
  No wasted reply, no error.
- **CA itself is down or unreachable long-term**: node stays stale
  indefinitely but keeps enforcing what it has and keeps getting peer top-ups;
  this is the same degradation class issue #3 already accepted for CA
  persistence (fail toward "keep working with what you have," not toward
  blocking).
- **Partial CA reply (some pages lost)**: `last_reconciled_unix` is set only on
  a *complete* reply — a partial one is retried like any other failure, never
  treated as partial success. A partial *peer* reply is simply whatever records
  arrived (it never sets `last_reconciled_unix` anyway), so lost pages just mean
  fewer free top-ups — corrected by the next boot's burst or by CA-pull.

## 5. Security considerations

- **CA-pull request is self-authenticating** (§3.3.1), same posture as
  `CertReq` — an outsider cannot use it to enumerate the mesh's revocation list
  or grief the CA into wasted signing work.
- **Peer-catch-up marker is authenticated by the carrying OGM.** The marker
  carries no signature of its own, but a responder only acts on it after the
  OGM's own `OgmSig` verifies (an unauthenticated OGM is dropped before the tail
  is processed), so only a real member can elicit a peer reply. No new outsider
  surface.
- **Marker-spam / reply amplification.** A *compromised member* could still spam
  the marker to bait neighbors into repeated replies (airtime amplification, the
  expensive resource on LoRa). Mitigated by per-requester rate-limiting
  (`revsync_req_rate`, §3.7), reusing `cert_req_rate`'s existing spacing rather
  than inventing a new mechanism. Bound the table like `cert_req_rate`.
- **Information disclosure via peer reply.** A peer reply hands its revocation
  set to a 1-hop neighbor — but that neighbor is an authenticated member (its
  OGM verified), and revocations are already designed to reach every member by
  flood, so this discloses nothing a member wasn't entitled to learn anyway.
- **No new trust assumption.** The CA is already the mesh's trust root; CA-pull
  just gives ordinary nodes a second way to reach it (pull vs. its existing
  push-via-OGM-flood). Every record — flooded, peer-relayed, or CA-minted — is
  root-signed and verified against the trust anchor at the receiver by the same
  `verify_revocation` path. A peer relaying a record it holds cannot forge or
  alter one; a tampered record fails the signature check and is dropped.
- **Logging:** obey the repo rules — never log record bytes; MACs, counts, and
  lengths only. Parse failures of remotely-supplied req/reply/marker frames are
  `trace!`, not `warn!`.

## 6. Observability

Per the "metrics are first-class" rule, state lives in `CentralRouter`/`OgmAuth`
(so it exists on embedded too), and prefer bounded here-and-now signals:

- **Time since last successful CA reconciliation** — a gauge (bounded,
  here-and-now, not an unbounded counter), so an operator or an app on top of
  the mesh can see a node that's been unable to reach the CA for an alarming
  length of time. This gauge is the *observable proof* of the epistemic
  distinction in §3.7: a peer answer, by design, does **not** move it — only a
  CA reply does. A node being caught up by neighbors while still showing a
  large "time since CA reconciliation" is the intended, meaningful signal, not a
  contradiction.
- **Peer-catch-up activity** — a `RateEstimator` for `RevSyncReq` markers
  emitted/answered and peer-reply records ingested. Cheap, and it lets an
  operator distinguish "this node is being kept alive by gossip" from "this node
  is authoritatively current," which the CA-reconciliation gauge alone can't
  show.

Wire each end-to-end with the `add-metric` skill (proto → service →
`RouterAdapter` → client → TUI → smoke test). Tracing: `debug!` on
reconciliation start/success and on peer-catch-up start, `warn!` on exhausted
CA-pull retries (an operator-relevant, handled-and-retried condition), never
payload logging of reply contents beyond metadata.

## 7. Testing strategy (TDD)

- **Unit — `RevocationStore`**: round-trip save/load including
  `last_reconciled_unix`; the `std` file impl's atomic-write behavior
  (crash-mid-write leaves the old file intact), mirroring `CaLog`'s existing
  tests.
- **Unit — CA-pull trigger logic**: `stale` computed correctly for
  `last_reconciled == 0`, just-under-threshold, just-over-threshold; the hint
  fires exactly once per staleness detection (take-and-clear, like
  `trickle_reset_hint`).
- **Unit — CA responder**: filters out `not_after <= now`; mints a record whose
  `not_after` equals the persisted cert's `not_after`, not a fresh
  `now + cert_ttl_secs`; pagination splits correctly at the configured per-page
  cap.
- **Unit — peer-catch-up burst**: `RevSyncReq` is attached to the node's own
  OGMs for exactly the configured budget of emissions and then stops (the same
  shape as the existing `REVOKE_FLOOD_BUDGET` exhaustion test).
- **Unit — peer answer is additive only**: a record ingested from a peer reply
  is enforced (`is_revoked` true) but does **not** set `last_reconciled_unix`
  (the node stays `stale`). This is the load-bearing epistemic invariant of
  §3.7 and must have its own test.
- **Unit — responder rate limit**: a second `RevSyncReq` from the same requester
  within `CERT_REQ_RATE_LIMIT_SECS`-equivalent window is not answered
  (mirroring the `cert_req_rate` tests).
- **Unit — marker stripped on re-flood**: an OGM carrying `RevSyncReq`, once
  re-flooded by a relay, no longer carries it — asserted directly on the
  re-flood output bytes. This is the load-bearing test for §3.3.2's
  1-hop-scoping claim; without it, a regression here silently reintroduces
  mesh-wide reply amplification.
- **Unit — suppressed duplicate reply**: given two candidate responders that
  both overhear the same marker, the second cancels its reply after
  overhearing the first's `BATADV_REVOKE_SYNC_REPLY` to the same requester
  within its jitter window.
- **Integration (`wayfinder-test`)**:
  - *CA-pull golden-compare*: a node with a stale/empty local store boots,
    resolves a route to a CA node, pulls, and ends up with an enforcement set
    identical to a node that received every revocation via ordinary flood —
    same shape as the lazy-cert-distribution doc's integration test.
  - *Peer-only golden-compare*: a stale node adjacent to an informed neighbor is
    caught up **entirely from the neighbor's cache**, with **no CA round-trip
    involved** (no `ca_mac` reachable, or asserted no `RevokeSyncReq` sent), and
    reaches the same enforcement set.
  - *Peer does not satisfy reconciliation*: after a successful peer catch-up, if
    the node is still `stale`, a CA-pull still eventually fires once a route to
    `ca_mac` resolves (peer answers accelerate but do not substitute for
    authoritative reconciliation).
  - *CA unreachable*: node stays stale, keeps running and keeps taking peer
    top-ups, no crash, no wedge.
  - *Amplification bound, multi-hop*: in a 3+ hop line topology, a marker
    emitted at one end never reaches a node 2+ hops away — direct evidence the
    strip-on-forward fix actually bounds visibility, not just a claim about it.
  - *Amplification bound, single-hop fan-out*: a requester with several
    informed 1-hop neighbors receives exactly one `BATADV_REVOKE_SYNC_REPLY`
    in the common case, not one per neighbor.

## 8. Migration / versioning

`RevocationStore`'s on-disk schema (the `std` impl) needs its own version byte,
independent of `CaLog`'s `CURRENT_STATE_VERSION` — different data, different
lifecycle, don't couple them. The wire packets and the `RevSyncReq` marker carry
the same `version` field convention already used elsewhere (e.g.
`REVOKE_VERSION`); a version mismatch is dropped, not crashed on, per this mesh's
existing all-or-nothing-per-segment convention (see design 02 §4.4 for the same
posture on a different wire format). The new `RevSyncReq` TVLV is additive: an
un-upgraded node that doesn't recognize `0x84` simply skips it as an unknown
TVLV (the `find_tvlv`/`iter_tvlv` scanners already ignore unknown types), so a
mixed mesh degrades to "the marker is silently unanswered by old nodes" — no
breakage, just no peer catch-up from those nodes.

## 9. Alternatives considered

- **CA-routing-intercept peer answering** — giving the CA-pull
  `RevokeSyncReq`/`Reply` the "any node along the path answers early" property
  that `CertReq`/`CertReply` has, by routing the request toward `ca_mac` and
  letting an intermediate node intercept and answer. **Rejected — and this is a
  different thing from the peer catch-up that §3.7 adopts.** `CertReq`'s
  early-intercept is sound *only because* route-to-originator and cert-possession
  are provably the same set for auth nodes (route ⟺ cert — verifying an
  originator's OGM caches its cert as a side effect, lazy-cert §3.1). Revocation
  knowledge has **no such correlation** with position on any routing path: a
  node's revocation set comes from an independent, *budgeted* flood unrelated to
  routing topology, so a node sitting on the route to `ca_mac` has no special
  likelihood of holding the record the requester needs. Trying to make
  "intercept the CA-pull en route" reliable would therefore be building a
  fundamentally different (and unfounded) correlation. So the CA-pull path is
  answered **only** at `ca_mac` (§3.6), and the "a nearby node answers" property
  is instead provided by an *independent* mechanism — the neighbor-broadcast
  marker of §3.7 — which does not route toward any target at all and makes no
  claim that path position implies knowledge; it just asks *every* neighbor and
  takes whatever any of them happens to hold. Keep these two firmly distinct in
  any future revisit.
- **Fine-grained delta/epoch cursors** (`CaLog` schema bump adding a revocation
  sequence number, client presents a watermark, CA sends only what's newer).
  Rejected: `MAX_REVOKED` bounds the whole live set at 32 records (~3 KB worst
  case, usually far less), and `ingest_revocation`'s existing dedup already makes
  a redundant record a free no-op — building a precise diff protocol to shave an
  already-small, already-idempotent transfer doesn't earn its complexity at this
  scale, matching the same reasoning the CA-persistence design used to reject a
  transactional store. The same argument is why the peer reply (§3.7) sends its
  full set rather than a digest.
- **A static `ca_mac` config field** (this document's own original proposal for
  §3.2, before review). Rejected in favor of on-demand root-signed discovery:
  a config field is only as useful as the ability to change it, and no
  embedded node in this repo has a management interface to do that yet; it
  also permanently binds every node's flash image to naming the CA's current
  physical identity, which is both an operational liability (CA migrates →
  re-flash the mesh) and a security one (every node's config becomes a map
  revealing the mesh's highest-value target). §3.7's peer catch-up softens
  the *operational* failure mode of a stale/wrong CA address either way (a
  node still gets neighbor top-ups), but that doesn't address the
  discoverability concern, which is the more serious of the two. See §3.2 for
  the adopted alternative and the honest limits of what it actually fixes.
- **Auto-deriving `RECONCILE_MAX_AGE_SECS` from live Trickle config** instead of
  a plain configured value. Cleaner in principle (no magic number to drift from
  reality) but couples `OgmAuth` to per-link Trickle state it doesn't otherwise
  need; deferred as a possible follow-up once there's a concrete reason the
  static default proves wrong in practice.

## 10. Open decisions for the implementing session

1. **Confirm the new wire values are free** at implementation time:
   `TvlvType::RevSyncReq = 0x84` (next after `CertFp = 0x83`) and
   `BATADV_REVOKE_SYNC_REQ`/`_REPLY = 0x07`/`0x08` (next after
   `BATADV_CERT_REPLY = 0x06`).
2. **Peer-broadcast vs. CA-pull composition** (§3.7): the recommendation is
   *peer burst every fresh/stale boot, CA-pull gated on `RECONCILE_MAX_AGE_SECS`,
   both run concurrently (no head-start sequencing)*. Confirm this rather than
   letting it default silently — it's the load-bearing timing decision and was
   deliberately left explicit.
3. **Whether the peer reply reuses `BATADV_REVOKE_SYNC_REPLY`** (recommended,
   §3.3.2, discriminating authoritative-vs-peer by `source == ca_mac`) or gets
   its own distinct packet type. Reuse is simpler and keeps one pagination path;
   confirm the source-based discriminator is acceptable vs. an explicit
   provenance flag in the header.
4. **`REVOKE_SYNC_REQ_BUDGET`** — the marker burst length (propose a small value
   like 3–6, mirroring `REVOKE_FLOOD_BUDGET`'s scale). Confirm against real
   OGM cadence once on hardware.
5. **`RECONCILE_MAX_AGE_SECS` default** (propose 1 hour) and whether staleness is
   re-checked periodically during steady-state or only at boot — the latter is
   simpler; the former is stronger defense against a long-lived partition on a
   node that never restarts.
6. **Flood budget on restore** (§3.1): restore persisted records with
   `floods_left` at some small nonzero value (propose 1–2) rather than 0 or the
   full `REVOKE_FLOOD_BUDGET`.
7. **Per-page record cap** (proposed 4, matching `MAX_REVOKE_PER_OGM`) — shared
   by the CA reply and the peer reply; confirm against real on-air budgets once
   this runs on hardware.
8. **Where the `std` `RevocationStore` impl lives** — superseded by
   prerequisite #1 (Scope): this is now a question for the generic-store
   design (04), not this document.
9. **Sign off on §3.2's on-demand discovery approach** for addressing the CA,
   replacing this document's original static-`ca_mac`-config proposal —
   raised in review as a security-posture trade-off requiring explicit
   agreement, not something this document should decide unilaterally. If
   discovery is rejected in favor of some other approach, §3.2, §3.3.1's
   `ca_mac` shorthand, §3.4, and §3.6 all need a follow-up pass.
10. **Suppression-window tuning** (§3.7): the jittered reply-delay range for
    peer-catch-up responses, so it's long enough to usually let one responder
    win before others transmit, but short enough not to noticeably delay
    catch-up. No principled default proposed yet — needs real airtime/RTT
    numbers from hardware.

## 11. Key file map

**Blocked on, in order: design 04 (generic store) landing far enough to know
`RevocationStore`'s real shape; the `BATADV_*` enum refactor MR (prerequisite
#2); sign-off on §3.2 (open decision #9).** The file map below assumes both
land first.

- `libs/wayfinder-auth/src/revoke.rs` — `RevocationRecord` unchanged (92-byte
  POD, `Unaligned`); the durable-cache trait now lives wherever design 04
  lands it, not here.
- `libs/wayfinder/src/auth.rs` — `OgmAuth`: load-at-construction,
  save-on-mutation, `last_reconciled_unix`/staleness check, `needs_reconciliation`
  hint (mirror `trickle_reset_hint`), in-flight CA-pull tracking (mirror
  `InFlightCertRequest`/`PendingReply`/`CERT_REQUEST_RETRY_SECS`); the
  `RevSyncReq` emission budget (mirror `floods_left`/`REVOKE_FLOOD_BUDGET` in
  `augment_ogm`), the **strip-on-re-flood** step for `RevSyncReq` (§3.3.2 — a
  new touch-point on the re-flood path, not inside `batman::engine`), the
  overhear-and-answer path with its jittered/suppressible reply (§3.7), and a
  `revsync_req_rate` limiter (mirror `accept_cert_request_rate`/
  `cert_req_rate`). The additive-only peer ingestion (ingest without touching
  `last_reconciled_unix`) is the invariant to guard here.
- `libs/batman/src/wire.rs` — new `BATADV_REVOKE_SYNC_REQ`/`_REPLY` variants
  added to the (now-enum, per prerequisite #2) packet-type type, header structs
  mirroring `BatmanCertReq/ReplyPacket`; and `TvlvType::RevSyncReq = 0x84`.
- `libs/wayfinder/src/lib.rs` — demux the two new packet types (mirror the
  `BATADV_CERT_REQ`/`_REPLY` arms), originate/handle the CA-pull; attach and
  overhear the `RevSyncReq` marker and emit the direct peer reply over the
  ingress link. The OGM verify/originate gate is the anchor for both.
- `libs/wayfinder/src/config.rs` — **no new field** (superseding the original
  `ca_mac` config proposal, §3.2/§9); the discovered CA address is runtime
  state, not config.
- `libs/wayfinder-server/src/provider.rs` — new `MeshAuthority` method (e.g.
  `build_revocation_sync_reply`) for the CA-side responder — **not**
  `adapter.rs`/`RouterAdapter` (§3.6 correction).
- `libs/wayfinder-server/src/authority.rs` — `CertAuthority` implements the new
  `MeshAuthority` method: filters `issued` by date, mints from
  `IssuedRecord.not_after`.
- The driver's mesh-frame dispatch (wherever it holds `provider: Option<Box<dyn
  MeshAuthority>>` today) — new call site invoking that method when a
  `RevokeSyncReq` is locally-delivered, instead of routing through
  `RouterAdapter`.
- `libs/wayfinder-test` — integration tests per §7 (CA-pull golden-compare,
  peer-only golden-compare, peer-does-not-satisfy-reconciliation, CA
  unreachable, **hop-2+ never sees the marker**, **only one of several informed
  1-hop neighbors actually transmits a reply**).
- `libs/wayfinder-shark` — extend the dissector + pytest for the two new packet
  types and the `RevSyncReq` TVLV.
