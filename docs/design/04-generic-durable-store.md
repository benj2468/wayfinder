# Design: A generic durable-blob-store abstraction

**Status:** Proposed. Prerequisite for design 03
(`03-revocation-durability.md`), raised in that document's MR review: rather
than let `RevocationStore` become the second bespoke small-state persistence
trait in this codebase (after `CaLog`), factor out the part that's actually
shared before building the second one.

**Scope:** a new crate (`libs/wayfinder-store`, name open — see §10), `no_std`
core + `std`-gated file backend, mirroring the shape `wayfinder-auth` already
uses (`no_std` core does the crypto; the `std`-gated `Authority` is the CA in
the *same* crate). Retrofits `wayfinder-server`'s existing `CaLog`
(`persistence.rs`) onto the shared file-backend piece. Feeds design 03's
`RevocationStore`. No change to any wire format, to `CaState`'s JSON schema,
or to `CaLog`'s external behavior (this is a refactor of *how* it persists,
not *what*).

---

## 1. Motivation

This codebase is about to have two independent, hand-rolled "durably persist
some small state across a restart" implementations:

- **`CaLog`** (`wayfinder-server/src/persistence.rs`, shipped): `std`-only,
  JSON, versioned with migrations, atomic write via a private free function
  `save_atomic` — `.tmp` sibling file → `write_all` → `sync_all` → `rename`
  over the target. (Its own doc comment flags one accepted gap: the parent
  directory is *not* `fsync`ed, so a *power loss* — not a process crash —
  immediately after the rename could in principle still lose it on some
  filesystems. Worth carrying forward as a known, accepted limitation, not
  silently "fixing" while retrofitting.)
- **`RevocationStore`** (design 03, not yet implemented): needs to run on
  both `std` (a file) and eventual `no_std` embedded targets (flash) — a
  fixed-size POD blob (bounded revocation records + a timestamp), no JSON,
  no migration machinery, nothing like `CaLog`'s shape.

These look different on the surface (JSON vs. raw bytes, `std`-only vs.
`no_std`-capable, versioned-with-migrations vs. a flat fixed record) but they
share exactly one real mechanical problem: **durably replace one blob with
another, such that a reader never observes a torn mix of old and new, even
across a crash or power loss mid-write.** That problem is medium-specific
(a POSIX file has atomic `rename`; raw NOR/NAND flash has neither atomic
rename nor even atomic byte-level overwrite — a completely different
strategy is needed there) but *not* caller-specific — `CaLog` and
`RevocationStore` need the identical guarantee from whatever medium they're
each running on.

Building `RevocationStore` as a third, independent reimplementation of "how
do I atomically persist a blob" — this time with a `no_std` twist neither
existing implementation has had to solve — is the wrong moment to keep
duplicating rather than extract. This design factors out the medium-specific
part once, `no_std`-clean, so both `CaLog` and `RevocationStore` (and,
plausibly, embedded node-identity persistence someday — see §2) become thin
callers of it rather than each reimplementing atomic-write mechanics.

## 2. Goals / Non-goals

**Goals**
- One trait capturing "durably, atomically replace a single blob" that is
  `no_std`-clean, so it can be implemented by both a `std` file backend and a
  future embedded flash backend without forcing either shape onto the other.
- Retrofit `CaLog` onto the `std` backend with **no behavior change** — same
  JSON schema, same versioning/migration logic, same accepted directory-fsync
  gap. This is a refactor, not a rewrite of `CaLog`'s own concerns.
- Give design 03's `RevocationStore` a real backend to build on instead of a
  third bespoke implementation.
- Sketch (not build) the shape a future embedded flash backend would take, so
  whoever eventually writes one isn't starting from a blank page.

**Non-goals**
- **Any embedded flash implementation.** No `embedded-storage` usage exists
  anywhere in this repo today, and no embedded bin wires up anything that
  would consume this yet (`wayfinder-nrf52840`/`wayfinder-stm32f411` don't run
  `OgmAuth`, per design 03 §2). Sketched in §5 for a future session, not
  delivered here.
- **A general-purpose transactional store, multi-blob atomicity, or a
  database.** Explicitly one blob per `DurableStore` instance, single-writer,
  no cross-blob transactions — `CaLog` already treats `issued` and `held` as
  two independently-persisted concerns (two separate `mutate_*` calls, two
  separate persists, documented as intentional in `persistence.rs`), and
  nothing here should change that. A caller needing several independently
  durable things holds several `DurableStore` instances, same as today.
- **Encoding, versioning, or migration.** These stay entirely the caller's
  concern (Layer 2, §3). `CaLog` keeps its own JSON + `CURRENT_STATE_VERSION`
  + migrations exactly as they are; `RevocationStore` uses its own flat POD
  layout (design 03 §3.1). The shared trait knows nothing about what's
  inside the blob.
- **Node-identity (keypair/cert) persistence on embedded** — a real, related
  gap (embedded nodes don't persist their own identity across reboots
  either, so they'd re-enroll every power cycle once auth runs there), and a
  plausible future consumer of this same abstraction, but its own concerns
  (secret material, not just cache state) make it a separate design's
  problem, not this one's.

## 3. Design

### 3.1 Layer 1 — `DurableStore`: the medium abstraction

```rust
/// Durable, atomic single-blob storage: `no_std`-clean so it can run under a
/// bare-metal flash backend as readily as a `std` file. A `DurableStore`
/// instance owns exactly one blob's worth of state — a caller with several
/// independently-persisted things (as `CaLog` already has: `issued` and
/// `held`) holds one instance per thing, not one instance managing several.
pub trait DurableStore {
    type Error;

    /// Load the most recently durably saved blob into `out`, returning its
    /// length. `Ok(None)` means nothing has ever been saved — a legitimately
    /// fresh store, not an error (mirrors `CaLog::load`'s existing "missing
    /// file is a fresh CA" handling).
    fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, Self::Error>;

    /// Durably replace the saved blob with `data`, atomically: `load` after a
    /// crash or power loss during this call must return either the old blob
    /// or the new one in full, never a mix, and never a torn partial write.
    fn save(&mut self, data: &[u8]) -> Result<(), Self::Error>;
}
```

Deliberately synchronous in this sketch — see §10.1 for why that's an open
decision, not a settled one: `LinkT` is a native `async fn` trait
specifically because embedded I/O is genuinely slow and shares a cooperative
executor with time-sensitive mesh routing (`wayfinder`'s own `CLAUDE.md`:
"Async I/O — `embedded-io-async`"). A flash erase/write cycle is exactly that
kind of slow operation, and a *synchronous* `save()` on an embedded target
would stall OGM forwarding and link I/O for its duration. Whether that's
acceptable (persistence writes are rare — only on a genuine state mutation,
not a hot path) or whether this needs the same native-`async fn` +
`dynosaur` treatment `LinkT` gets is left open (§10.1) rather than assumed
either way.

`out: &mut [u8]` (caller-supplied buffer, no allocation) mirrors the existing
idiom this codebase already uses for exactly this shape of problem —
`frag::Reassembler::accept`'s `out: &mut [u8]` in `libs/rylr998/src/frag.rs`
is the same pattern for a different reason (bounded reassembly, no `alloc`).

### 3.2 `std` file backend

Extract `wayfinder-server/src/persistence.rs`'s existing `save_atomic` logic
(a private free function today, not a `CaLog` method) into a `FileStore`
implementing `DurableStore`, gated behind a `std` feature **in the same
crate** — mirroring exactly how `wayfinder-auth` already splits itself
(`no_std` core does verification/agreement; the `std`-gated `Authority` is
the CA, same crate, per the root `CLAUDE.md`'s architecture map). No new
crate boundary needed for the `std`/`no_std` split.

Behavior preserved verbatim: write to a `.tmp` sibling in the same directory,
`sync_all`, `rename` over the target (atomic on POSIX), best-effort remove
the `.tmp` on failure. The known accepted gap (no directory `fsync`, so a
*power loss* — not a process crash — immediately after rename could in
principle still lose it on some filesystems) carries forward unchanged; this
refactor is not the moment to silently tighten or loosen that guarantee.

### 3.3 Retrofitting `CaLog`

`CaLog` keeps everything caller-specific — its `issued: Vec<IssuedCertData>` /
`held: Vec<HeldCsr>` fields, `CaState`'s JSON shape, `CURRENT_STATE_VERSION`,
and the migration-on-load logic in `load()` — and swaps its internal use of
the free-function `save_atomic`/`load` for calls through a `FileStore:
DurableStore` field. Same external behavior, same tests (they should need no
changes beyond the internal wiring), one fewer independent atomic-write
implementation in the codebase.

### 3.4 Design 03's `RevocationStore` becomes a thin Layer-2 wrapper

Design 03 §3.1 sketched `RevocationStore` as its own bespoke trait; it should
instead become a small encode/decode layer over `DurableStore`. Since
`RevocationRecord` is already `FromBytes`/`IntoBytes`/`Immutable`/
`KnownLayout`/`Unaligned` (a 92-byte POD struct, per design 03 §3.1), the
"encoding" is close to free: a tiny fixed header (version byte, record count,
`last_reconciled_unix: u64`) followed by up to `MAX_REVOKED` raw
`RevocationRecord`s, written and read as one blob via `DurableStore::save`/
`load`. No JSON, no migration machinery — `RevocationRecord`'s own `version`
field (`REVOKE_VERSION`) already covers the one thing that might need to
evolve.

### 3.5 Sketch: a future embedded flash backend (not built here)

Flash has neither atomic rename nor atomic byte-level overwrite, so `save()`
needs a different strategy than the file backend — sketched here so a future
implementer starts from something rather than nothing:

- **Two flash pages/sectors ("ping-pong" / A-B logging).** Each `save()`
  writes the new blob to the currently-inactive page, prefixed with a small
  header: a monotonically incrementing generation counter and a checksum
  over the payload.
- **`load()` reads both pages**, verifies each header's checksum, and takes
  the highest-generation page that verifies — if the last write was torn
  (power loss mid-write), its checksum fails and the *other* (previous,
  intact) page is used instead, which is exactly the atomicity guarantee
  `DurableStore::save` promises.
- This is a standard embedded pattern (A/B flash logging), not a novel
  design — cited so it's available as a starting point, not to pre-commit to
  its exact framing before someone builds it against real hardware
  constraints (page size, erase granularity, wear leveling policy all vary
  by part).

## 4. Correctness / edge cases

- **Nothing ever saved** (`load` returns `Ok(None)`): both `CaLog` (today)
  and `RevocationStore` (design 03) already treat this as "legitimately
  fresh," not an error — preserved by this trait's `Option` return, not
  reinterpreted.
- **A torn write** (crash/power-loss mid-`save`): the file backend's
  rename-based atomicity already prevents this on `std`; the sketched flash
  backend's checksum-and-fall-back-to-previous-generation achieves the same
  guarantee by a different mechanism. Both satisfy the same trait contract.
- **`CaLog`'s directory-fsync gap**: explicitly *not* something this
  refactor should fix incidentally — call it out if a future session wants
  to close it, but don't let a mechanical extraction quietly change
  durability guarantees CaLog's own design already accepted.

## 5. Security considerations

No new trust boundary: this stores data that's already either self-verifying
(`RevocationRecord`s are root-signed independent of how they're stored) or
already trusted local state (`CaLog`'s issued-cert log, already `std`-local
today). A corrupted or missing store degrades to "fresh/empty," per each
caller's own existing fail-closed posture (`RevocationStore`: falls back to
peer catch-up / CA-pull, design 03 §4; `CaLog`: fails closed per issue #3).

## 6. Testing strategy (TDD)

- **Unit — `FileStore`**: round-trip save/load; a `.tmp` sibling left behind
  by a simulated failure doesn't corrupt a subsequent load; migrated
  verbatim from `CaLog`'s existing `save_atomic`/`load` test coverage, not
  rewritten from scratch.
- **Unit — `CaLog` retrofit**: existing test suite should pass unchanged
  (behavior-preserving refactor) — treat any test that needs to change as a
  signal the refactor drifted from "same behavior, different internals."
- **Unit — the sketched flash backend**, once built (out of scope here): a
  torn write on page A falls back to page B's prior generation; monotonic
  generation counter wraps correctly at its bit width.

## 7. Alternatives considered

- **Don't extract anything; let `RevocationStore` duplicate `CaLog`'s
  approach.** Rejected per the MR review that prompted this document —
  two near-identical hand-rolled persistence layers is exactly the signal to
  generalize, and design 03 explicitly named this as likely to recur.
- **A single trait that also standardizes encoding** (e.g., requiring
  `serde` or a fixed schema-versioning scheme at the trait level). Rejected:
  `CaLog`'s JSON-for-auditability choice and `RevocationStore`'s raw-POD
  choice are both deliberate, caller-specific decisions (see design 03 §3.1
  and the CA-persistence issue's own reasoning for JSON) — forcing one
  encoding strategy at the shared layer would fight one of the two callers
  no matter which was picked.
- **Async `DurableStore` from the start**, matching `LinkT`. Deferred to an
  open decision (§10.1) rather than decided either way here — see §3.1.

## 8. Open decisions for the implementing session

1. **Sync vs. async `DurableStore`** (§3.1). Sync is simpler and matches
   `CaLog`'s existing fully-synchronous behavior on `std`; async matches
   `LinkT`'s precedent for genuinely slow embedded I/O sharing a cooperative
   executor. Given persistence writes are mutation-triggered (rare), not
   hot-path, sync may be an acceptable trade-off — but this should be a
   deliberate call, not a default.
2. **Crate name and location** — `libs/wayfinder-store` is a placeholder.
3. **Whether `CaLog`'s retrofit lands in the same MR as `RevocationStore`'s
   implementation, or ships on its own first** (recommend: on its own first,
   as a pure refactor with no behavior change, so it's reviewable
   independent of anything design 03-specific).

## 9. Key file map

- New crate (name per §10.2), `no_std` by default: `DurableStore` trait
  (§3.1); `std`-feature-gated `FileStore` (§3.2), extracted from
  `wayfinder-server/src/persistence.rs`'s `save_atomic`/`load` free
  functions.
- `libs/wayfinder-server/src/persistence.rs` — `CaLog` retrofit (§3.3): swap
  internal atomic-write calls for a `FileStore` field; `CaState`/
  `CURRENT_STATE_VERSION`/migration logic unchanged.
- `libs/wayfinder-auth` (or wherever design 03 ultimately places it) —
  `RevocationStore` becomes the Layer-2 wrapper described in §3.4, once this
  crate exists for it to wrap.
