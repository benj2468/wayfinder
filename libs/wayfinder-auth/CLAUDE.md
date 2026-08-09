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

## Revocation

`revoke.rs` is the *active* purge (a signed `RevocationRecord`, flooded), and
complements the *passive* purge of short-lived cert expiry. Both paths exist on
purpose: expiry bounds the damage window with no network, revocation shortens it
when the network is up. See `docs/design/03-revocation-durability.md`.

## Wire structs

`MembershipCert`, `TrustAnchor`, `RevocationRecord` are `zerocopy` wire types
(`FromBytes`/`IntoBytes`/`Immutable`/`KnownLayout`/`Unaligned`, network-endian
integers). They are parsed straight from received bytes with no allocation — so
**any layout change is a wire break**. Both carry an explicit version constant
(`CERT_VERSION`, `REVOKE_VERSION`); bump it rather than reinterpreting old
bytes.

## Where the CA lives

`Authority` (`authority.rs`, `std` only) holds the mesh root key and issues
certs. Embedded nodes must never link it — they only verify. The management-API
side of the CA (provider mode, CSR handling, persistence) is *not* here; it's
`wayfinder-server`'s `authority.rs`/`persistence.rs` behind the `MeshAuthority`
trait.
