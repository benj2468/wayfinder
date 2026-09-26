# libs/wayfinder-auth

Cryptographic identity and mesh membership. `no_std` core (verify + key
agreement, linked by embedded nodes); the `std` feature adds the `Authority`
(the CA) and OS-RNG keypair generation.

**Scope, and the thing to internalise first: payloads are never encrypted.**
This crate buys *authenticity* and *mesh segregation*, never confidentiality —
that is L3's job. Reviewing a change here means asking "could an outsider forge
or replay this?", not "could an outsider read this?".

## The identity chain

Everything derives from one 32-byte seed (`key.rs`):

```
seed ──> Ed25519 keypair  ──> signs OGMs, signs certs
     └─> X25519 secret    ──> pairwise_key(neighbor) for data-plane tags
             │
             └─> pubkey ──(Blake2s256 + domain label)──> Mac   (mac.rs)
```

A node's mesh `Mac` is *derived from its key*, not assigned by the OS
(`derive_mac`). That is why a node's address survives restarts and TAP
re-creation. A `MembershipCert` then attests `Ed25519 pubkey ↔ Mac ↔ mesh`, so
identity is additive over the existing addressing rather than replacing it.

**The derivation is enforced, not merely conventional.** `verify_cert` refuses a
certificate whose `node_mac` is not the address its `ed_pubkey` derives
(`AuthError::MacKeyMismatch`), and the three issuance paths — `submit_csr`,
`wayfinderctl cert issue`, `cert approve` — refuse to mint one. Two consequences
worth knowing before you design against this:

- **Impersonation is impossible rather than merely against policy.** Even a
  compromised authority cannot mint a credential for somebody else's address:
  it would need a `derive_mac` preimage, which a signing key is not. This is
  why the check sits *after* the signature check — it rejects a certificate the
  root genuinely signed, so it is a misissuance and the error says so.
- **An address cannot outlive its key.** Re-keying renumbers the node; a
  re-keyed node is a new originator. Certificate *renewal* (same key, new
  window) is the only shape that keeps an address, and it still changes the
  fingerprint, so the `CertFp` → `NeedCert` refetch path is still exercised.
  `issue_cert` itself stays permissive — it is the primitive a test uses to
  build a misissuance on purpose — so "the CA will sign it" and "a node will
  honour it" are deliberately different questions.

See `docs/design/implemented/09-mesh-auth-gaps.md` §5.

## Two mechanisms, chosen by fan-out

The split is not stylistic — it falls out of one-to-many vs. hop-by-hop:

- **Control plane (OGMs, broadcasts) — signatures.** One-to-many, so every
  member must be able to verify independently: the originator signs the
  immutable header and embeds its cert. A pairwise tag is impossible here (no
  single recipient to share a key with).
- **Directed data plane (unicast/mcast) — pairwise tags.** `frame_tag` /
  `verify_frame_tag` (`pairwise.rs`), a cheap symmetric Blake2s tag keyed by the
  X25519 shared secret, with a monotonic counter bound in for replay resistance.
  Hop-by-hop, recomputed at each hop — *not* end-to-end.

Consequence worth knowing before you debug a "why did my frame drop" report:
data-plane authentication is per-hop, so a tag failure implicates the two nodes
either side of one link, not the path.

## Domain separation

Every `Blake2s256` use folds in a distinct label (e.g. `MAC_DERIVE_LABEL =
b"wayfinder-mac-v1"`). Adding another hash use over the same key material
**must** add its own label — otherwise two uses over the same pubkey can be made
to collide. This is the easiest thing to get wrong here.

## What a verifier knows about the time

`verify_cert` does **not** take a `now_unix: u64`. It takes a `Clocked`
(`clock.rs`), which is the three states that actually exist:

| posture | `now < not_before` | `now > not_after` |
|---|---|---|
| `At(t)` — an authoritative reading | `NotYetValid` | `Expired` |
| `AtLeast(f)` — a lower bound | **never checked** | `Expired` when `f > not_after` |
| `Unknown` — no usable clock | not checked | not checked |

The rule to hold on to is one line:

> **Signature always, window when known.**

Everything above the window — the signature, the mesh id, the key↔MAC binding,
the reserved-address refusal — is checked identically under all three. Only
expiry varies. That is what lets a bare-metal node, which has no RTC and no NTP,
route and verify its peers at all; the window it skips is a revocation
*optimisation*, and its clocked peers still enforce it.

`AtLeast` is the shape a board's clock genuinely has — every source of it
under-counts — and modelling it honestly is what makes the design safe rather
than lucky: there is no `not_before` comparison an `AtLeast` verifier can fail,
so no amount of oscillator drift can make a board reject a healthy peer for
being "too early".

`WallClock` is the board-side producer: an anchor somebody handed it plus
elapsed monotonic time, never decreasing within a session, and unmovable by
anything that arrived over the radio. `MIN_PLAUSIBLE_UNIX` (2025-01-01) is the
floor below which a reading is treated as no reading — it catches a clock that
was never *set*; a clock that is plausible and wrong is `wayfinder-clock-trust`'s
question, not this crate's.

Revocation is the one dated path that does **not** go through the posture's
predicates: see `RevocationRecord::cancels_under`, which enforces a held record
whenever the window cannot be judged rather than silently enforcing nothing.

Full reasoning: `docs/design/implemented/20-embedded-clock-independence.md`.

## Revocation

`revoke.rs` is the *active* purge (a signed `RevocationRecord`, flooded), and
complements the *passive* purge of short-lived cert expiry. Both paths exist on
purpose: expiry bounds the damage window with no network, revocation shortens it
when the network is up. Note that expiry is no longer enforced by *every*
verifier — a node with no clock judges no window (see above), which is exactly
why `cancels_under` makes sure the active path still works there. See `docs/design/03-revocation-durability.md`.

## Wire structs

`MembershipCert`, `TrustAnchor`, `RevocationRecord` are `zerocopy` wire types
(`FromBytes`/`IntoBytes`/`Immutable`/`KnownLayout`/`Unaligned`, network-endian
integers). They are parsed straight from received bytes with no allocation — so
**any layout change is a wire break**. Both carry an explicit version constant
(`CERT_VERSION`, `REVOKE_VERSION`); bump it rather than reinterpreting old
bytes.

## Two builds of SHA-512

Ed25519 hashes with SHA-512 on every seed expansion, sign and verify. The host
uses `sha2`'s unrolled round; every board opts into `compact-sha512` (a rolled
loop — ~10 KiB smaller on Cortex-M, ~43 KiB on the ESP32). Same digest, so the
only risk is the two builds disagreeing, and that is what the RFC 8032
known-answer test in `key.rs` rules out — CI runs this crate's suite under both.
A board opts in on its own `wayfinder-auth` dependency; never enable the feature
from a shared crate, or the host gets it too.

`blake2` is not a candidate for the same treatment by *replacement*: every
derived value here — the MAC, cert fingerprints, pairwise keys and tags — is a
`Blake2s256` output that crosses the wire or is persisted, so swapping hash
families is a protocol migration, not a size change.

## Where the CA lives

`Authority` (`authority.rs`, `std` only) holds the mesh root key and issues
certs. Embedded nodes must never link it — they only verify. The management-API
side of the CA (provider mode, CSR handling, persistence) is *not* here; it's
`wayfinder-server`'s `authority.rs`/`persistence.rs` behind the `MeshAuthority`
trait.
