# Design: cloud-scale state — a host capacity profile, and the CA on SQLite

**Status:** Phase 1 implemented (see §3.1); phase 2 not started. Numbered 26 because 25 is taken by the WL55 design on `bjc/wl55jc-relay`.

**Scope:**
- `libs/interfaces` (`define_profile!`) and `libs/wayfinder` (`router_for!`, a
  new `host` profile, the identity table's slot index).
- `libs/wayfinder-driver`, `libs/wayfinder-server` (`RouterAdapter`) and
  `bins/wayfinder-tap`: letting a host node choose a profile.
- `libs/wayfinder-server` (`persistence.rs`, `authority.rs`): the CA's durable
  state.
- The deployments: `nix/machines/wayfinder-ca`, the containers.

Boards are out of scope and must not change: their profiles, `heapless` tables
and `no_std` build stay exactly as they are.

## 1. Problem

A cloud node (the certificate authority, a VPN hub, any `wayfinder-tap` on a
server) has effectively unlimited memory and disk, but it is held to the same
kind of fixed limits as a board. It runs out in two places.

**The router's tables.** `wayfinder-tap` and the CA always run the `default`
profile, because `wayfinder-driver` and `RouterAdapter` name `CentralRouter`
with its defaults and no host node can choose another:

| Table | `default` capacity | When full |
|---|---|---|
| originators (also sizes broadcast dedup, keepalive, proofs) | 128 | evicts the least recently heard |
| identity table | 128 (100 live) | evicts; slot index is a `u8`, so no profile can exceed a 128-slot table |
| neighbour keys (also sizes the cert-request and renewal rate limiters) | 64 | overwrites the first slot, which can be a live member (deliberate trade-off, #50) |
| multicast members | 64 | silently drops the rest |
| revocations | 32 | evicts the live entry with the lowest flood budget |
| in-flight cert requests / pending replies | 16 / 16 | refuses / overwrites |

On a VPN hub every peer is a direct neighbour, so the neighbour-key table fills
at 64 peers, and each new peer after that displaces an existing member's keys.

**The CA's durable state.** `CaLog` keeps the issued-certificate log, held
CSRs, enrollment policy, users and invites in one JSON document,
`/var/lib/wayfinder/ca-state.json`:
- every mutation, logins included, re-serialises and rewrites the whole file;
- the issued log (one entry per node ever enrolled) and the user list are
  never pruned;
- **loading reads at most `MAX_STATE_BYTES` (1 MiB) and fails closed**, so the
  file's growth ends with a CA that refuses to start;
- revocations are not persisted at all. The flag on an issued entry survives,
  but the signed `RevocationRecord`s the mesh floods are gone after a restart
  (the gap design 03 describes).

## 2. Goals and non-goals

**Goals**
- A host node chooses its capacity profile, and a `host` profile exists with
  limits no realistic mesh reaches.
- The CA's state lives in a store with transactions, per-record writes, schema
  migrations and no size cliff, starting as one SQLite file on the CA's disk.
- The store's interface does not assume SQLite, so moving to PostgreSQL later
  (for several CA instances, or outside tools reading it) is a backend change,
  not a redesign.
- Signed revocation records are persisted and re-flooded after a CA restart,
  and checked against a complete in-memory index rather than a bounded table.
- Where access is skewed, a fast in-memory tier in front of a persistent store
  (§5): certificates on cloud nodes. Where it isn't (live routing state),
  tables sized to the whole population instead.

**Non-goals**
- Any change to boards, their profiles, or the `no_std` routing core's
  behaviour at a given capacity.
- Persisting routing tables. They are soft state that rebuilds from OGMs within
  seconds of a restart, so writing them to disk costs I/O on the per-packet
  path for nothing a restart needs.
- PostgreSQL in this design.
- Unbounded routing tables in phases 1 and 2. §6 sketches them as phase 3.

## 3. Phase 1: a host capacity profile

1. **Host nodes choose a profile, in the binary.** Make `wayfinder-driver::Driver`
   generic over its router, `R: RouterOps = CentralRouter`, exactly as the
   embedded driver already is, and do the same for `RouterHandle` and the
   management adapter. `RouterOps` covers 9 of the 19 router methods the host
   driver calls today; the other 10 join the trait (it is capacity-erased, so
   every profile implements it for free). `wayfinder-tap` then chooses by naming
   `router_for!(host)`.

   **Not a Cargo feature on `wayfinder-driver`.** That was the obvious route
   and is the wrong one: features unify across a workspace build, so a
   `cargo test --workspace` that also builds `wayfinder-tap` would silently run
   every driver test at host sizes, and tests pinned to the `default` capacities
   would pass or fail depending on what else was built. The profile belongs to
   the binary, the same rule `CLAUDE.md` gives for the log sinks.
2. **Widen the identity table's slot index** from `u8` to `u16`, so a profile
   can exceed a 128-slot table. Boards keep their memory use: the index width is
   the only change, and it moves with the profile through a const-generic
   helper or a per-profile type.
3. **Add the profile**, sized so no mesh we run gets near it (capacities that
   back an `FnvIndexMap` must be powers of two):

   | Parameter | `default` | `host` |
   |---|---|---|
   | originators | 128 | 4096 |
   | identity table (live) | 128 (100) | 4096 (3500) |
   | link quality | 64 | 1024 |
   | neighbour keys | 64 | 1024 |
   | multicast members / local | 64 / 16 | 1024 / 64 |
   | revocations | 32 | 1024 |
   | in-flight requests / pending replies | 16 / 16 | 256 / 256 |

   Estimated from the measured per-entry sizes (`OriginatorRecord` 240 B,
   `NeighborKeys` 272 B), the router grows from about 74 KB to a few MB. That
   rules out the stack: **the router must be heap-allocated on host nodes**,
   and phase 1 has to check every place a `CentralRouter` is built by value.
4. **Linear scans.** Several of these tables are `heapless::Vec`s searched
   linearly per frame (neighbour keys on every tagged frame, for example). At
   1024 entries that is a measurable per-frame cost. Phase 1 measures it with
   `wayfinder-bench` at the new sizes; any table that shows up converts to an
   indexed map within phase 1, keeping the same eviction policy.
5. The `host` build becomes the CA's and the containers' default. The
   saturation alarm and `TableOccupancy` gauges keep working unchanged.

### 3.1 Phase 1 as built

- **Naming.** The profile was proposed as `cloud` and shipped as `host`:
  `wayfinder-tap` runs on Linux gateways and laptops as well as in the cloud,
  and all of them get it (the measurements below are why that costs nothing
  worth a second build). The previous `host` profile, `CentralRouter`'s
  default capacities, is now `default`; it stays small because tests, the
  simulator and the tick driver build routers on ordinary thread stacks.
- **Profile choice.** `Driver` is generic over `R: RouterOps`; its management
  path and `RouterHandle` are const-generic over `CentralRouter`'s eleven
  capacities, as `RouterAdapter` already was; `wayfinder-tap` names `router_for!(wayfinder::host)`
  once (`TapRouter`). The TLS transport, which only ever serves reads, holds an
  `Arc<dyn ServeRouterRead>` so its types do not depend on the profile.
- **Heap placement.** A host router is 1.77 MB and its `OgmAuth` 548 KB. A
  `no_std` value cannot be built in place, and a debug build needs 6-8x the
  router's size in stack to construct one (measured), so `Driver::new` builds
  and configures it on a short-lived thread sized from the type and gets back
  only the `Arc`. Installing a credential needs ~2.1 MB of stack in a debug
  build; the tap's loop runs on the main thread (8 MiB), which has it. Release
  builds need a fraction of either.
- **Measurements** (`wayfinder-bench`'s `host` suite, aarch64, release):

  | Path | `default` | `host`, 1 entry | `host`, full |
  |---|---|---|---|
  | OGM ingest | 78 ns | 77 ns | 87 ns (4095) |
  | unicast forward, 512 B | — | 105 ns | 113 ns (4095) |
  | directed verify, 512 B | — | 1.04 µs | 1.63 µs (1024 keys) |
  | idle periodic tick, hub | — | 86 ns (64) | 4.9 µs (4096) |

  The first run had ingest and forward at ~2.5 µs at *every* occupancy: a cost
  tracking capacity, not occupancy. `IdentTable::clear` assigned
  `Self::new()`, a >100 KB temporary that inlined into
  `apply_self_revocation` — called on every frame — so that function
  stack-probed a frame that size per call. It now clears in place.
- **Boards do grow, slightly.** Step 2 promised the slot index would move with
  the profile; it does not. It is `u16` for every profile, which costs a board
  about 5 bytes per identity-table slot — ~164 B at the nRF52840 and ESP32
  profiles' 32 slots, ~84 B at the STM32's 16. Choosing the width per profile
  needs either a twelfth parameter on `CentralRouter` or a `where` bound on
  every generic impl of it, the viral shape rejected for capacity profiles
  once already. `embedded_router_size_is_pinned` now pins a board-sized
  router so any further growth is a deliberate edit.
- **Deferred: the neighbour-key scan.** `OgmAuth`'s `neighbors` and
  `recv_counters` are searched linearly, adding ~0.6 µs per directed frame at
  1024 keys. Not converted: an index map would add RAM on every board (this
  design's one hard constraint), and the cost only appears on a hub with
  hundreds of *authenticated* neighbours, on a path where each OGM already
  pays tens of µs for Ed25519. Revisit with phase 3's per-profile tables.
- The idle tick is linear in the neighbourhood (~1.2 ns per neighbour), paid per
  timer wake-up rather than per frame.

## 4. Phase 2: the CA on SQLite

**Store interface.** A `CaStore` trait in `wayfinder-server` with record-level
operations the authority already performs:
- issued certificates: upsert by MAC, mark revoked, list, look up;
- held CSRs, the enrollment policy, users and invites: the same kinds of
  operations;
- revocation records: append, list the live ones;
- one `transaction` entry point for the few operations that touch two
  collections at once (approving a CSR both removes it and issues).

`CaLog`'s sealed-mutation rule (`Persisted`: mutate, persist, roll back on
failure) carries over: a mutation is a transaction that commits or leaves
nothing behind, so there are still no ad-hoc `persist()` calls.

**Backend.** SQLite through `sqlx`, which covers SQLite and PostgreSQL behind
one query API, with checked-in migrations. The authority task already runs off
the router loop (design 13) on tokio, so an async store fits where the
blocking `FileStore` sat. One file, `/var/lib/wayfinder/ca.sqlite3`, in WAL
mode.

**Migration from `ca-state.json`.** On first start with no database, the CA
imports the JSON document through the existing, versioned loader (so every
older schema version still upgrades), commits it in one transaction, and
renames the JSON to `ca-state.json.imported`. It fails closed if both exist
and disagree. The 1 MiB read cap goes with the JSON path.

**Revocations.** Signed `RevocationRecord`s are stored as they are issued. On
startup, the CA re-queues the unexpired ones into its flood path, and builds
the complete in-memory index of revoked fingerprints (§5) that verification
checks. That closes design 03's CA-restart gap. Its node-restart and peer
catch-up parts stay design 03's own.

**Operations.**
- **Backups:** `sqlite3 .backup` or a copy of the database file taken while
  WAL is checkpointed, documented next to the NixOS module.
- **Tooling:** the "one writer" rule in `CLAUDE.md` still holds. Operators
  change state over RPC, never by opening the database beside the running CA.

## 5. Tiering: which state gets a cache in front of a store

A tiered (multi-level) cache keeps a small fast tier of hot entries in memory
in front of a large slow tier on disk or across the network. It pays off only
when access is **skewed**: a few entries hot, most cold but still valid. So the
question is asked per kind of state, not once for "the tables".

One constraint governs every answer: **the routing engine is synchronous and
`no_std`, so the per-packet path never waits on a slow tier.** A miss becomes
"defer, then fill asynchronously", as design 01's `NeedCert` already does.
That is acceptable for data that can arrive a moment late (a certificate needed
to verify a *later* OGM), and not for the forwarding decision about the frame
in hand.

| State | Access pattern | Tiering | Why |
|---|---|---|---|
| Originators and what they size (broadcast dedup, keepalive, proofs, identity) | Every live entry written each OGM round | **None.** Size to the live mesh (phase 1) | Every originator floods an OGM each Trickle interval (at most 128 s), and processing it updates that originator's seqno window and path statistics. The working set is the whole live population, so a smaller hot tier would thrash. An originator not heard within the purge timeout is dead and removed, so there is no valid cold data to keep. |
| Neighbour keys, link quality, multicast membership | All live entries used continuously | **None.** Size to the live population (phase 1) | Same reasoning: these describe the current neighbourhood and group state, and a miss cannot be deferred for the frame being forwarded. |
| Membership certificates | Skewed: needed when an originator's OGM is verified; most arrive and stay | **Three tiers on cloud nodes:** the router's cert store, then a persistent local store (SQLite), then fetch over the mesh | Design 01 already makes the first and third tiers. A local persistent tier between them makes a restart or an eviction a disk read instead of a mesh round trip. Boards keep two tiers. |
| Revocations | Must be checked completely on every verification; records rarely read | **Index plus records, not a cache.** A compact set of every revoked fingerprint in memory; the signed records in SQLite; only the ones being flooded in the router | A revocation check that can miss is a security hole, so the fast tier must be *complete*, never a cache. An 8-byte fingerprint per revocation is 8 MB at a million, cheap enough to hold them all. |
| CA state (issued log, users, invites, held CSRs) | Mostly cold; hot lookups at enrollment and login | **SQLite's own page cache** | The database already keeps hot pages in memory. A hand-written cache in front of it would add invalidation bugs and nothing else. |

So the answer to "an unbounded store with a cache of the active part" is:
- **yes for certificates**, which gain a persistent middle tier on cloud nodes;
- **yes, in a stricter form, for revocations**, as a complete in-memory index
  over records on disk;
- **no for live routing state**, whose working set *is* the whole population.
  Those tables get big enough in phase 1 and stay entirely in memory.

## 6. Phase 3 (sketch): tables behind an interface, with tiers where access is skewed

Once phase 1 is in, every table still has a fixed capacity, just a large one.
Phase 3 makes the routing core stop naming `heapless` types directly. Each
table becomes a trait with:
- a fixed-capacity implementation (boards, unchanged);
- a growable in-memory one (hosts, `std` collections behind an `alloc`
  feature), for the tables §5 says should hold their whole population;
- for certificates only, a tiered one whose miss path defers and fills
  asynchronously, as `NeedCert` does today.

Growth still needs an **admission budget**, so a flood of forged identities
can't grow memory without limit: a table with no fixed cap still has a ceiling,
set by policy rather than by the type. This is a large change to the
per-packet path, and gets its own design once phase 1's measurements show which
tables actually matter.

The revocation index (§5) does not wait for phase 3: it is a small, separate
structure and lands with phase 2, since that is when the CA's full revocation
set first persists.

## 7. Test plan

- **Phase 1:**
  - A test that a `host`-profile router builds and runs on the heap.
  - The existing capacity-profile pinning tests extended to `host`.
  - Identity-table tests past what a `u8` index can address.
  - `wayfinder-bench` runs at the new sizes, compared against `main` for the
    per-frame paths.
- **Phase 2:**
  - Store tests against an in-memory SQLite: every operation, transaction
    rollback, and migrations from an empty database.
  - An import test from each historical `ca-state.json` version already in the
    test fixtures.
  - A restart test showing revocations are re-flooded.
  - The revocation index: a revoked fingerprint is always found, including
    after a restart and past the router table's capacity.
  - The existing authority tests run against the SQLite store.

## 8. Open questions

1. **One profile per binary, or several?** Phase 1 has `wayfinder-tap` name
   one router type. If one image should serve both a small gateway and the CA,
   a runtime choice between two compiled routers (an enum over them) is
   possible, at the cost of binary size.
2. **When to move to PostgreSQL:** when a second CA instance or an outside
   reader of CA state becomes a requirement, not before.
3. **Retention for the issued log:** entries for nodes whose certificates
   expired long ago could be archived. Out of scope until the log's size
   matters on SQLite, which it won't for a long time.
4. **Where the revocation index lives on non-CA cloud nodes.** The CA builds
   it from its own store. A VPN hub or gateway only learns revocations from the
   mesh, so the index would need design 03's catch-up to be complete after its
   restart. Until then, such a node's index is only as complete as the floods
   it has heard.
5. **The certificate middle tier on a board.** Flash is too small and
   wear-limited for a general cert cache, so boards keep two tiers. Worth
   revisiting only if board re-fetch traffic shows up as a problem.
