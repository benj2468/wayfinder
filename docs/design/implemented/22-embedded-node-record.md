# Design: what a bare-metal node keeps across a reset

**Status:** Implemented — landed on `main` in `7e91bb5`. §11 records what the
implementing session decided and where it deviated.

Owns #54, resolves #60, discharges design 20 §4.5's constraint, and
unblocks #55. Two facts in `main` this changes are recorded in §2.

## 1. Scope

**In play:**

- `libs/wayfinder-storage` — `DurableStore` grows two erasure operations
  (`scrub`, `erase`); `FlashStore` and `FileStore` implement them.
- `libs/wayfinder-embedded-driver/src/identity.rs` — replaced. Today it
  persists a `Mac`; it will persist a **node record**: an identity seed, a
  clock checkpoint, and the `NodeSettings` a `RouterAdapter` writes through.
- `libs/wayfinder-embedded-driver/src/lib.rs` — the driver restores that
  record at boot, hands the adapter a `SettingsStore` so `SetAuth` is durable,
  and rewrites the checkpoint on a schedule.
- `libs/wayfinder-nrf/src/identity.rs` — mints a *random* seed on first boot
  and derives the MAC from it; FICR stops being the mesh address and becomes
  the USB serial.
- `libs/wayfinder-nrf/src/{node,usb_mgmt}.rs`, both nRF board `main.rs` — the
  seed and the restored record are threaded through bring-up.
- `libs/wayfinder-hil/{src/mesh.rs,tests/}` — the reset test design 21 §5.3
  says to flip, plus the new one this makes possible.

**Explicitly not touched:**

- **The certificate format, the trust anchor, the revocation record, the OGM
  signature scheme.** Nothing a *node* sends changes. This is a storage design.
  (§7 does add one management-API enum value, `ALARM_KIND_CERTIFIED_ADDRESS_MISMATCH`
  — no new field, and nothing on the mesh.)
- **`NodeSettings`/`NodeIdentity`/`SettingsStore`** in `wayfinder-server`. The
  seam already exists and already carries what a board needs; the board
  supplies an implementation, it does not change the trait.
- **Host behaviour.** `wayfinder-tap`'s `SettingsFile` and `FileStore` are
  untouched apart from `FileStore` gaining the two erasure methods.
- **Enrolment, and what a credential-less board does about `require_auth`.**
  Those are #55. See §3's non-goals for exactly where the line falls.
- **`bins/wayfinder-stm32f411`.** It has a compile-time `Mac` constant and no
  durable store at all; §6.3 records why that is left alone.

## 2. Motivation

Three separate things are owed here, and they are one piece of work because
they are one blob.

### 2.1 A board has nowhere to keep a credential

`SetAuth` over a board's management port works today — design 20 made it work,
by removing the not-yet-valid rejection that used to refuse every real
certificate. What it does not do is survive: `identity.rs` persists a `Mac` and
nothing else, so a reset returns the board to uncredentialed. That is
`libs/wayfinder-hil/tests/clock.rs::a_reset_returns_the_board_to_unknown`, which
passes today and is written to be flipped by this work.

### 2.2 The board's address is not derived from its key

Found on a real DK by the HIL rig (#60), and directly observed:

```
node info: node_id=da182c334bc4  ...  clock_posture=AtLeast
security:  auth_enabled=true mesh_id=0x48494c00 node_mac=663d1a49a076
```

`node_id` is the router's own address, FICR-derived. `node_mac` is the
installed certificate's, which since design 09 §5 *is* the address the
identity key derives. The node routes as one MAC and is certified as another,
and accepts the install without complaint.

The nRF board is **the only identity in the workspace that is not
seed-derived**. `wayfinder-tap` loads a seed and takes `keypair.derived_mac()`;
`adapter.rs`'s own refusal message on the certify-in-place path already names
the remedy — *"Restart it on a build that derives its MAC from its seed, so it
comes up under the certified address."* There is no such build. This makes one.

That is also why #60 cannot be fixed in the rig: a certificate's MAC is a hash
of its public key, so matching a specific FICR address would mean grinding
keypairs.

### 2.3 Design 20 left a checkpoint here

Design 20 §4.5, in bold:

> **#54 must persist the clock checkpoint in the same blob as the credential,
> written, loaded and erased with it.**

with the wear budget ("two 4 KiB pages at roughly 10 000 erase cycles") and the
rewrite interval explicitly handed forward as this design's call.

## 3. Goals and non-goals

**Goals**

1. A board holds an identity **seed**, minted once, and its mesh MAC is that
   seed's `derived_mac()` — so a certificate naming that MAC is a certificate
   for the address the board actually routes under.
2. A credential installed over `SetAuth` survives a reset, and so does the
   clock checkpoint. A self-revocation *round-trips* the record — so a
   `SetAuth` that clears one is durable, and a future writer needs no format
   change — but **nothing on the embedded path writes one yet**: that is the
   host driver's loop. §11.2 records what a board does on finding one.
3. Rotating the seed does not leave the previous one readable in a spare flash
   page.
4. The design states what the store does and does not promise about
   confidentiality at rest, rather than implying a guarantee it cannot keep.

**Non-goals**

- **Enrolment from the board.** A board still cannot ask a CA for a
  certificate; an operator installs one over the management port. #55.
- **Renewal.** A board cannot renew itself, so the renewal provider is
  deliberately *not* persisted (§4.2).

  > **Note (design 24).** No longer true. A board renews over the *mesh* — it
  > was never unable to reach its authority, only unable to speak to it, since
  > every management conversation here is TLS over TCP. The provider's pinned
  > key is now persisted; see design 24 §2.1, which cites §4.2 below by name as
  > the behaviour it overturns.
- **`require_auth` on a board.** What a credential-less board does — route
  unauthenticated or stay inert — is #55's decision. This design persists the
  flag; it does not choose its default.
- **Confidentiality against a debug probe.** §4.7 — that is APPROTECT's job and
  no software on this part can substitute for it.
- **Factory reset over RPC.** The erasure primitive lands here and has a caller
  (§4.4); exposing it as a request kind does not. §9.

## 4. Design

### 4.1 One record, one lifetime

A single blob in the board's existing two-page `FlashStore`:

```
version: u8                 = 2
flags:   u8                 which optional fields follow, and the two tri-state bools
seed:    [u8; 32]           the node's Ed25519 identity seed
checkpoint_unix: u64        the clock high-water mark (0 = none), big-endian
cert:            [u8]       MembershipCert, 156 bytes, if present
trust_anchor:    [u8]       TrustAnchor, 36 bytes, if present
self_revocation: [u8]       RevocationRecord, 92 bytes, if present
```

**No length prefixes.** Every optional field's size is a compile-time constant,
so the flags byte and the total length determine the layout between them — and
decode requires those two independent statements to *agree*, rather than
trusting either alone. The worst case is 2 + 32 + 8 + 156 + 36 + 92 = 326 bytes
against a page capacity of 4080, so the geometry has an order of magnitude of
headroom and the encoding does not need to be clever.

**The seed is a top-level field, not a field of the identity.** `NodeIdentity`
bundles `{seed, cert, trust_anchor, provider}` because on a host those four
arrive together, and a half-updated identity there is non-functional rather
than merely weaker. A board is different in one way that matters: **it has a
seed before it has a credential**, from its very first boot. Hoisting the seed
out makes that structural — there is exactly one seed, the credential is
optional beside it, and the invariant "the board's MAC is the MAC its
credential names" cannot be encoded in a form that violates it. Reconstructing
a `NodeSettings` for the adapter puts the seed back:

```rust
identity: cert.zip(trust_anchor).map(|(cert, trust_anchor)| NodeIdentity {
    seed: seed.to_vec(), cert, trust_anchor, provider: None,
})
```

and persisting one takes it back out, *replacing* the stored seed. That is the
seed-rotation path, and §4.4 is what makes it safe.

### 4.2 What is deliberately not stored

- **The renewal provider.** `run_once_with_mgmt` already drops it, with a
  stated reason: a board cannot renew its own certificate, that path is the
  host driver's tokio loop. Persisting a target nothing reads would be a
  durable lie about what this node will do.

  > **Note (design 24).** This is the decision design 24 overturns, and it
  > cites this paragraph by name. The premise — that renewal means opening a
  > client connection — was the whole of it; a board renews over the mesh
  > instead, so the target is now read, and `NodeRecord` persists the
  > provider's pinned key. The reasoning above stands as the record of why it
  > was right at the time.
- **The MAC.** It is `Keypair::from_seed(&seed).derived_mac()`. Storing it
  beside the seed is storing the same fact twice, and the two disagreeing is
  precisely the defect #60 reports.

### 4.3 First boot, and the boot that cannot reach flash

**First boot** mints a seed from the nRF's RNG peripheral and persists it.

**Not from FICR.** The device ID is a 64-bit factory value that is not secret —
it is printed on the part and readable by anything on the chip — so a
FICR-derived private key is derivable by anyone who knows it. That is a
different and much worse property than a FICR-derived *address*, which is
public by nature.

**When the store cannot be reached** — misconfigured geometry, or flash that
fails a write — the board falls back to `from_ficr()` as the MAC, **and no seed
at all**. (Today a misconfigured geometry *halts* instead; §4.6 and `resolve`'s
own doc record why degrading is better, since `FlashStore::new` rejects a bad
base rather than writing at it.) Two things follow, both wanted:

- The address stays deterministic across reboots, which is the property
  `from_ficr` was chosen for and which an in-memory random seed would destroy
  (a new address on every power cycle, churning every peer's originator table).
- A board with no seed **cannot hold a credential**, which is honest: it has
  nowhere to keep one, so refusing to pretend is the correct degradation.

`from_ficr` therefore survives, in two roles. The second is the USB serial:

> **The USB serial number becomes FICR-derived, not the mesh MAC.**

Today `usb_mgmt::init` uses the node's MAC for `config.serial_number`, so the
host's `/dev/serial/by-id/` symlink names the board by its mesh address. Once
the mesh address follows the seed, that symlink would change on first boot
after this lands and again on every `SetAuth` — and the HIL inventory
(`hil.toml`) pins boards by exactly that serial, so the rig would lose its
board mid-run every time a test installed a credential.

Splitting them is not a workaround, it is the right shape: the USB serial
identifies a **physical part**, the mesh MAC identifies a **mesh node**, and
those change on entirely different schedules. Because it stays `from_ficr()`,
the value does not change at all — the DK on the current bench keeps
`DA182C334BC4` and existing `hil.toml` files stay valid.

The NCM mesh link's host-side MAC keeps following the *node*, since that is a
mesh interface and not a hardware label.

### 4.4 Erasure: `DurableStore` grows `scrub` and `erase`

`FlashStore`'s A/B ping-pong keeps the previous blob **by construction** — that
is how a torn write falls back — and for a secret that is exactly wrong: after
a `SetAuth` rotates the seed, the old private key sits in the sibling page in
plaintext until some later save happens to overwrite it.

Two methods:

```rust
/// Erase every copy of the blob other than the current one.
fn scrub(&mut self) -> Result<(), Self::Error> { Ok(()) }

/// Return the store to never-written: a subsequent `load` reports `Ok(None)`.
fn erase(&mut self) -> Result<(), Self::Error>;
```

`scrub` is defaulted and `erase` is not, which this design originally had both
ways round. A no-op `scrub` is the honest answer on a medium that keeps no
second copy — `FileStore`'s rename leaves none — so the default is correct
rather than merely tolerated. A no-op `erase` is never the honest answer: a
caller reaching for it is disposing of something it believes is a secret, and
silently doing nothing is the exact failure the method exists to prevent. So
every store is made to answer for it.

- `FlashStore::scrub` erases the non-current page. `FlashStore::erase` erases
  both.
- `FileStore::scrub` is genuinely a no-op — an atomic `rename` leaves no second
  copy — and the default is therefore correct rather than merely tolerated.
  `FileStore::erase` removes the file.

**Ordering, and why it stays atomic.** The rotation write is `save(new)` then
`scrub()`. At every instant a power cut can occur, a valid page exists:

| cut during | on the next boot |
|---|---|
| `save`'s erase-then-write of the stale page | the *current* page still validates; the old value is read |
| after `save` returns, before `scrub` | the new page validates and wins on generation |
| `scrub`'s erase of the now-stale page | the new page validates; the old is gone or partly gone, and either way is not the highest generation |

What `scrub` gives up is the fallback for a *later* torn write — but a save
already begins by erasing the sibling, so that fallback only ever spanned the
gap between two saves. `scrub` closes that gap early; it does not remove a
guarantee that a completed save was relying on.

`erase` has a caller from day one: an undecodable stored record. Today
`load_or_init_identity` overwrites a corrupt blob in place. With a secret in
it, "overwrite" is the wrong verb — the bytes may be a readable old seed under
a damaged header — so the recovery becomes `erase()` then mint fresh. The boot
that finds it still reports the error, as today.

### 4.5 The checkpoint, and the wear arithmetic

Persisted value: `WallClock::estimate(now)`, per that method's own doc. Restored
at boot by passing it to `WallClock::anchor` — through the `max`, so a stale
page cannot pull a corrected estimate back.

The board rewrites it when **all** of:

1. the clock is anchored (an `Unknown` board has nothing to write, so an
   unanchored board causes no flash wear at all);
2. the estimate has advanced by at least `CHECKPOINT_INTERVAL` past what is
   stored.

**`CHECKPOINT_INTERVAL = 6 hours.`** The arithmetic, so it can be retuned
against evidence rather than re-derived:

- nRF52840 flash: 4 KiB pages, ~10 000 erase cycles, two pages.
- A checkpoint save is one erase, alternating pages, so the pair sustains
  ~20 000 saves.
- At 6 h that is 1 461 saves/year → **~13.7 years**. At 1 h it would be 2.3
  years, which is not a service life. At 24 h it would be 55, buying nothing
  worth the extra deficit.

Design 20 already settled that this is a wear trade-off and not a correctness
one: *"a coarser interval only widens the deficit, and can never make the clock
wrong in the other direction."* The deficit on restore is powered-off time plus
up to six hours, against certificate windows measured in months. Seed-rotating
saves cost two erases but are operator-driven and rare enough to ignore in this
budget.

### 4.6 Boot order

```
1. FlashStore::new(...)              -- geometry; failure ⇒ §4.3's FICR fallback
2. load record
     None            ⇒ mint seed from RNG, save, continue
     Some(bad)       ⇒ erase(), mint seed from RNG, save, report the error
     Some(v1 MAC)    ⇒ §6.1's migration: treat as never-provisioned
     Some(record)    ⇒ use it
3. mac = Keypair::from_seed(&seed).derived_mac()
4. build the Driver at `mac`
5. wall.anchor(record.checkpoint_unix, now)     -- and NOTHING else
6. if cert and trust_anchor verify under wall.posture(now):
        router.set_auth(OgmAuth::with_capacities(keypair, cert, anchor))
```

Step 5's *and nothing else* is design 20 §4.4's bold rule. In particular the
restored certificate's `not_before` must never reach the clock: it would reset
the expiry clock on every power cycle by an amount growing with the
certificate's age, triggerable by anyone who can pull the USB cable — and the
damage lands on the board's judgement of *everyone else's* certificates, not
just its own.

Step 6 is #55's first bullet, moved here on purpose. A credential that is
persisted and never reloaded is unobservable, so leaving it in #55 would mean
landing this design with no way to test the thing it exists to do. What stays
in #55 is the harder and genuinely separate half: enrolment, and the policy a
board applies when step 6 finds nothing.

A restored credential that **fails** to verify — a trust anchor rotated under
it, or a certificate that expired while the board was powered off — is reported
and dropped, not retried and not repaired. The board routes uncredentialed,
which is the state it was in before the credential was installed.

### 4.7 What the store does not promise

**No confidentiality at rest, and it must not claim any.**

An nRF52840's internal flash is readable over SWD unless APPROTECT is engaged.
Encrypting the record would need a key the CPU can obtain unattended at boot,
on a part with no secure element, no key storage a debugger cannot reach, and
no PUF — so that key lives in the same flash as the ciphertext, and the whole
construction is theatre that costs code and buys nothing against the stated
threat.

So: `DurableStore` already provides what this design needs (atomicity), plus
the two erasure operations §4.4 adds, and **at-rest confidentiality on these
parts is APPROTECT's control, not the store's.** The two boards differ here and
the difference is worth stating: the DK has a probe header and its seed should
be treated as a bench seed; the dongle has no header, but SWD pads exist, so
"harder" is not "protected".

The scope of the exposure is bounded and worth being precise about, because it
is the reason this is acceptable rather than merely unavoidable: the seed is
**one node's** membership. It is not the mesh root — that is minted offline by
`wayfinderctl cert` and never enters a node — so a read-out seed impersonates
one board until it is revoked, and revocation is exactly what design 16 and the
authority's enrollment queue exist for.

Enabling APPROTECT is its own change with its own consequence (it makes a board
unflashable over SWD without a full erase, including every board on the bench),
and it is filed rather than smuggled in here.

## 5. Correctness and edge cases

- **A power cut anywhere.** §4.4's table.
- **A seed that persists but whose credential does not.** The record is one
  blob written in one `save`, so this cannot happen — which is the argument for
  one blob rather than two stores.
- **A credential installed for a MAC that is not the board's.** `SetAuth`'s
  wholesale-install path is deliberately exempt from the MAC check because
  naming a new MAC is what it is for. After this design the board adopts the
  installed seed, so the address follows on the next boot and the two agree —
  which is the host's behaviour and closes #60. **The divergence still exists
  between the install and the reset**, and that is not a bug being tolerated: a
  mid-flight MAC change is a topology event (`CentralRouter::self_ident` is set
  in `new` and has no setter, deliberately, because every peer holds the old
  originator). §7 is how it is made visible instead of silent.
- **A seed rotated to the same value.** `save` then `scrub` is idempotent.
- **A board whose flash write fails during `SetAuth`.** `SettingsStore::persist`
  returns `Err` and the adapter's contract already says the change did not take
  effect and must not be applied in memory either. The board keeps the
  credential it had.
- **Both flash pages independently corrupt.** Indistinguishable from
  never-provisioned at the `DurableStore` layer — `load` reports `Ok(None)`.
  Today's `load_or_init_identity` documents this as acceptable *because a FICR
  mint is idempotent*. **That argument does not survive this change**: a random
  seed mint is not idempotent, so this case silently changes the board's mesh
  address. It is accepted anyway — the alternative is a board that refuses to
  boot after a double corruption, and a changed address on a board that has
  also lost its credential is the lesser harm — but the doc comment inherited
  from `load_or_init_identity` must be rewritten rather than carried over,
  since its stated justification is now false.

## 6. Migration and versioning

### 6.1 The v1 blob

A board updated in place holds `[1, mac0..mac5]` from `MacCodec`. It is
recognised explicitly and treated as **never provisioned**: a fresh seed is
minted and the board's mesh address changes once, at that boot.

Recognised rather than left to fail as a decode error, which is what would
happen otherwise. Both paths mint the same fresh seed; the difference is that
one logs a stated migration and the other logs corruption on a board that is
fine. A firmware update should not look like a fault.

The address change is real and unavoidable — the old blob holds a FICR MAC and
no key, so there is nothing to carry forward — but it is harmless in the only
way that matters: a v1 board by definition holds no credential, because
nothing could store one.

### 6.2 Security

Net: **stronger**, in three ways, and weaker in none.

- A board's key↔address binding becomes true by construction rather than
  reasoned about (#60).
- A rotated seed stops lingering in flash (§4.4).
- A self-revocation survives a reset, which is design 16's whole premise and
  today is lost on the first power cycle.

The new secret at rest is discussed in §4.7. The one genuinely new attack
surface is that `SetAuth` becomes *durable* on a board, so an attacker with the
cable can now change the node's identity permanently rather than until the next
reset. That port is unauthenticated (#59) and this raises the stakes of that
gap; it does not create it, and #59 is the fix.

### 6.3 The STM32

`bins/wayfinder-stm32f411` has a compile-time `Mac` constant, no `FlashStore`,
and no management port wired. Giving it a durable record is a board-support
change (its flash controller, its `memory.x` page carve-out) with no caller
yet — it cannot receive a `SetAuth`. Left alone deliberately; the
`wayfinder-embedded-driver` half of this design is HAL-agnostic and will be
there when that board grows a port.

## 7. Observability

The install-to-reset divergence in §5 must be visible, since a node routing
under an address its credential does not name is exactly the state #60 was
filed for and it remains reachable for the length of one session.

`GetSecurityStatus` already reports both halves — `node_mac` from the
certificate, and `GetNodeInfo`'s `node_id` from the router — so no new field is
needed. What is needed is that the node **says so itself**: raise
`AlarmKind::CertifiedAddressMismatch` (new kind, per `libs/wayfinder-alarm`)
when `SetAuth` installs a certificate for another MAC — a latch rather than a
continuously-evaluated condition, since the alarm board is in RAM and the reboot
that resolves this also clears it.

The boot path raises it too, and that one matters more: a record whose stored
certificate names an address the restored seed does not derive is refused, does
**not** self-clear, and would otherwise be the only case going unreported —
precisely because the install-time latch did not survive the reset. That turns a silent incoherent state into a latched, stated one
an operator reads over the API, which is the argument #60's option 1 makes and
which survives even though this design takes option 3.

## 8. Alternatives considered

- **Two stores, credential and checkpoint separate.** Halves the wear on the
  frequently-written half. Rejected: design 20 §4.5 requires the checkpoint be
  erased with the credential, two stores means two page pairs out of a flash
  budget that has other claims, and §4.5's arithmetic shows one store already
  reaches a 13-year service life.
- **Keep the MAC in the record beside the seed.** Rejected: it is the same fact
  twice, and the two disagreeing is the defect being fixed.
- **Encrypt the record.** Rejected in §4.7 — no key storage on this part that a
  probe cannot reach.
- **Seed the key from FICR** (no RNG, no first-boot write, address unchanged by
  this design). Rejected: the device ID is not secret, so every board's private
  key would be derivable from a value printed on the part.
- **Adopt the installed MAC immediately at `SetAuth`.** Rejected: `self_ident`
  is fixed at `CentralRouter::new` deliberately, and a mid-flight address
  change is a topology event that strands every peer holding the old
  originator. The host does not do this either.
- **#60 option 1 alone** (refuse a credential whose MAC is not the board's).
  Rejected as *sufficient* — it leaves a board unable to hold any credential at
  all, since no CA can issue for a FICR address. Its substance is kept as §7's
  alarm.

## 9. Open decisions for the implementing session

- **Where the checkpoint writer sits in the driver.** It needs `now` and the
  `WallClock`, both of which live in the loop, and a `&mut dyn` store. Whether
  that arrives as a parameter on `run_with_mgmt` or a builder on `Driver` is a
  taste call; `Driver` is already heavily const-generic, so prefer whichever
  adds no type parameter.
- **Whether `run()` (no mgmt) also checkpoints.** It anchors nothing and can
  receive nothing, so its clock is `Unknown` forever and the writer would never
  fire. Wiring it is free but proves nothing; skipping it is fine.
- **`AlarmKind::IdentityMismatch`'s exact subject encoding** — the certified
  MAC, the running one, or both.

Not open: the checkpoint interval (§4.5), the seed's source (§4.3), and whether
to encrypt (§4.7).

## 10. Key file map for the implementer

| file | change |
|---|---|
| `libs/wayfinder-storage/src/lib.rs` | `DurableStore::scrub` (defaulted) and `erase` (not) |
| `libs/wayfinder-storage/src/flash.rs` | erase the stale page / both pages |
| `libs/wayfinder-storage/src/file.rs` | `erase` removes the file |
| `libs/wayfinder-embedded-driver/src/identity.rs` | the record, its codec, `load_or_init_record`, the v1 migration |
| `libs/wayfinder-embedded-driver/src/settings.rs` (new) | `SettingsStore` over a `DurableStore` |
| `libs/wayfinder-embedded-driver/src/lib.rs` | restore at boot, `with_settings`, the checkpoint writer |
| `libs/wayfinder-nrf/src/identity.rs` | RNG mint, seed-derived MAC, FICR fallback |
| `libs/wayfinder-nrf/src/usb_mgmt.rs` | `init`'s `config.serial_number` from FICR, not the node MAC |
| `libs/wayfinder-nrf/src/node.rs` | thread the seed and record through `run` |
| `bins/wayfinder-nrf52840*/src/main.rs` | pass `RNG` alongside `NVMC` |
| `libs/wayfinder-alarm`, `-protos`, `-server`, `bins/wayfinder-tui` | `AlarmKind::CertifiedAddressMismatch` (named `IdentityMismatch` in §7 above) |
| `libs/wayfinder-hil/tests/clock.rs` | flip `a_reset_returns_the_board_to_unknown` |
| `libs/wayfinder-hil/src/mesh.rs`, `tests/fresh_board.rs`, `justfile` | the "known gap" section retires; `just hil-fresh` |

### Failing tests to write first

Host, in order of how much they pin down:

1. `FlashStore::scrub` leaves the current blob loadable and the stale page
   unreadable — asserted by reading the raw sibling page, not by `load`.
2. `FlashStore::erase` returns `load` to `Ok(None)`.
3. A power cut between `save` and `scrub` still loads the new blob (drive the
   two calls separately against a shared medium).
4. The record round-trips: seed, checkpoint, and all three optional blobs, in
   every present/absent combination.
5. A v1 (`MacCodec`) blob loads as never-provisioned, not as a decode error.
6. An undecodable blob calls `erase` before re-minting — asserted on a store
   double that records the call order.
7. Rotating the seed through `SettingsStore::persist` replaces it and calls
   `scrub`.
8. A restored checkpoint anchors the clock; a restored certificate's
   `not_before` **does not** (the §4.6 rollback rule — the load-bearing one).
9. `persist` failing leaves the recorded settings exactly as they were.

Hardware (`libs/wayfinder-hil`), which is where this design is actually proven:

10. **`a_reset_returns_the_board_to_unknown` flips**: after installing a
    credential and resetting, the board comes back credentialed and `AtLeast`.
    Its doc comment already says this is the intended edit.
11. **The board adopts the certified address across a reset** — `node_id`
    differs from the certificate's MAC before the reset and equals it after.
    That is #60, closed, on the hardware that found it.
12. A second reset does not move the posture backwards.

## 11. What the implementing session decided

### 11.1 §9's open decisions

- **The checkpoint writer** is a `&mut dyn NodeStore` parameter on
  `run_with_mgmt`, checked at the top of every pass of the loop. No new type
  parameter and no new deadline in the `select`'s `min`: the interval is hours
  and the loop wakes every few seconds, so a plain check fires on time. One
  trait rather than two parameters, because the settings and the checkpoint are
  one blob and a driver holding two handles could not honour §4.5.
- **`run()` (no mgmt) does not checkpoint**, as anticipated — it can be
  anchored by nothing, so the writer would never fire.
- **The alarm's subject is the certified MAC**, with the running one in the
  detail text. The subject is what a client groups rows by, and the certified
  address is the one that is about to become this node's.

### 11.2 What the design did not anticipate

- **`Persisted::mutate_sealed`** rather than a bare `scrub` at the call site.
  The seal is this repo's established pattern for persisted state, and a scrub
  that a caller has to remember is a scrub a caller will forget. It also forced
  the asymmetry worth stating: a failed save rolls back, a failed scrub does
  not, because the new value is durable either way.
- **`NullStore`**, for a board whose medium is unusable. §4.3 said such a board
  cannot hold a credential; the type is what makes `SetAuth` against it *fail
  with a reason* rather than appear to work until the next reset.
- **`Driver::restore` returns a `Restored` outcome** rather than logging
  internally, so a board reports it through whatever it has and a test can
  assert it. Its `Refused` arm is distinct from `Unauthenticated` because the
  two look identical from outside and mean very different things.
- **A held self-revocation refuses to arm**, rather than being judged. Nothing
  on a board writes one — the record carries the field so a `SetAuth` that
  *clears* it round-trips — so judging its window is speculative work against a
  clock model that differs from the host's. Fail closed and leave it to
  whatever wires self-revocation on embedded.

### 11.3 Two consequences for the bench, found while testing

Neither is a defect, and both change how the rig is used:

- **An installed identity now outlives a reflash.** The store sits in two pages
  the linker keeps clear of the image, which is the point of putting it there.
  A DK that has run the hardware suite therefore keeps a rig-minted mesh
  identity until its flash is erased outright, so `just hil-fresh` exists. Not a
  leak: the anchor is a fresh random root per call that never leaves the
  process, so the board is a member of a mesh that no longer exists anywhere.
- **Design 20's `Unknown` claims needed their own invocation**, and the first
  attempt at this got it wrong in a way only the bench revealed. Anchoring a
  board is now a one-way door, so every test that installs a credential
  destroys the precondition for testing an unanchored one. A skip guard was
  added for "a board that has already been clocked" — but nextest runs a
  binary's tests in name order, `a_reset_…` sorts before `an_unanchored_…`, and
  the test therefore skipped on **every** run, including against a freshly
  erased board. It had never once executed while the suite reported green,
  which is precisely the unfalsifiable failure design 21 §6.4 is about.

  Renaming it to sort first was rejected: that makes the suite depend on an
  ordering nextest does not promise, and the failure mode when it changes is
  silence again. It lives in `tests/fresh_board.rs` instead, with
  `just hil-fresh` to erase, reflash and run it — and the skip
  inside an ordinary `just hil` names that command.

  `hil-fresh` shells out to `probe-rs erase` and `probe-rs download` rather
  than growing harness surface for it: a reflash alone does not clear the
  record (that is the point of the pages it lives in), and `cargo run` — the
  better way to flash this board by hand — attaches RTT and never returns, so
  it cannot be chained ahead of a test. The same binary carries a second test
  worth having: a fresh board's minted address must **not** be its FICR board
  id, which is the one observable difference between a random seed and a
  FICR-derived one.
