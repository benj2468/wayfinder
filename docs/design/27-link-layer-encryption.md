# 27 — Link-layer encryption (MACsec-shaped, per link)

**Status:** Proposed (revision 3). Buildable from this doc once the §10 gate
passes. Revision 3 makes **certificate-keyed exchange the primary keying** and
demotes a pre-shared key to a fallback for meshes with no trust anchor; it
replaces revision 2's two-phase plan.

**Scope:** a new `no_std` crate `libs/wayfinder-linksec` (the sans-I/O SecY:
framing, AEAD, replay state, and the key-exchange messages); a `LinkSec` table
and key agent owned by `CentralRouter`; two driver-core functions every shell
calls (`receive_frame` on ingress, `protect_for` on egress); an entropy source
handed to the router; one optional field on `LinkConfig`; a small management
RPC set; one optional `LinkT` method (`confirm_peer`, §5.6). **Not touched:**
the BATMAN engine; `OgmAuth`'s wire formats (OGM signatures, directed tags,
fan-out signatures keep working unchanged on top); any carrier except
`UdpMulti`'s address learning. **No persisted state** — revision 2's epoch
stores are gone (§4.4).

**Revision 3 changes, briefly:**

- **Keying.** Each sender protects with a random **sender key** minted at boot
  and handed to each neighbor over a one-hop exchange wrapped under the
  pairwise secret `OgmAuth` already derives from membership certificates
  (§4.3). A pre-shared key is the same exchange with a different wrapping
  secret (§4.11). Revision 2's static-key-first plan, and its separate Phase 2
  doc, are dropped: the review showed most of Phase 2's control plane already
  exists (§2).
- **No epoch store.** A fresh 256-bit sender key per boot makes nonces unique
  without persisting anything, which deletes revision 2's §4.4 and the three
  board flash stores it needed (§4.4).
- **The exchange was itself reviewed adversarially** before this revision was
  published: certificates must name the sender, every wrap is single-use,
  only the newest response sets a window, and revocation sweeps by
  fingerprint (§4.3, §4.5, §4.7).
- **Fixes from the review:** clone detection no longer lets an outsider
  silence a node (§4.6, §5.3); validation runs in the tick driver too (§4.1);
  protect is per (frame, interface) through one driver-core function (§4.1);
  the overhead is 27 B, not 25, and the table covers raw LoRa and BLE extended
  advertising (§4.2); the EtherType is `0x88B6` (§4.2); a rebooted receiver no
  longer accepts replays (§4.5); per-`src` drop state is gone (§4.12); the
  X25519 contributory premise in revision 2's §6.1 was false and is now issue
  #103 (§6.1).

---

## 1. Motivation

`wayfinder-auth` says: *"Payloads are never encrypted — wayfinder provides
authenticity and segregation only; confidentiality is left to L3."* That leaves
three gaps:

1. **Anyone in radio range reads everything.** LoRa and 802.15.4 are broadcast
   media with public modulations. Every bridged Ethernet frame — DHCP, ARP,
   mDNS, any application without its own TLS — is readable by a passive
   receiver.
2. **`Bcast` frames carry no authentication** (`required_proof` exempts them,
   `libs/wayfinder-driver-core/src/lib.rs:256`). A link key gives every hop an
   outsider-integrity check on them.
3. **Mesh state leaks.** OGMs are signed but cleartext: a listener learns
   originators, sequence numbers and TQs. With link encryption that content is
   hidden — though adjacency still leaks through outer `src`/`dst`, frame
   length and timing (§6).

The ask: a firmware author or a `wayfinder-tap` configurator turns this on
**per link**, without the carrier knowing, with crypto in the family we
already ship, and with admission that follows mesh membership and revocation.

## 2. Research: MACsec, and what maps

IEEE 802.1AE (MACsec) with its key agreement MKA (802.1X-2010 §9) is the
closest prior art: hop-by-hop L2 protection invisible to the layers above.

| MACsec concept | What it is | Wayfinder mapping |
|---|---|---|
| **SecY** | Data-plane shim: protects on tx, validates on rx. Knows nothing of how keys were agreed. | `wayfinder-linksec`'s pure core, state owned by the router (§4.1). |
| **KaY** | Control plane: runs MKA, elects a key server, installs SAs into the SecY. | The key agent inside `LinkSec` (§4.3). No key server: every sender owns its own key. |
| **Controlled / uncontrolled port** | Controlled = protected only; uncontrolled = cleartext, carrying only EAPOL/MKA. | `strict` admits only protected frames plus the one-hop key-exchange messages (§4.3, §4.8). Nothing else is exempt. |
| **SecTAG** | 8–16 B: EtherType `0x88E5`, TCI/AN, short length, 32-bit PN, optional 8 B SCI (MAC ‖ 16-bit port id). | §4.2. Outer `src` replaces the SCI's MAC half; a 3-bit `port` replaces its port id. |
| **ICV** | 16 B GCM tag. | 16 B Poly1305 tag (8 B option on small-MTU links, §4.2). |
| **PN** | Strictly increasing per SA; it is the nonce. 64-bit in **XPN** (802.1AEbw). | 64-bit `key id ‖ counter`; the key id names the SA (§4.2). |
| **AN** | 2 bits selecting one of four SAs for hitless rekey. | Replaced by the 32-bit key id: a newer key retires the older at once, so a receiver holds one live key per sender port (§4.7). |
| **CAK / SAK** | Long-term key, and the short-lived key on frames. MKA distributes **one SAK per CA**, shared by every SC. | The membership pairwise secret (or a PSK) plays CAK. Each **sender** has its own SAK — the sender key — which departs from MKA deliberately: no election, so nothing splits when a radio partitions. |
| **`validateFrames`** Strict / Check / Disabled | Under Check, invalid *integrity-only* frames are delivered and counted. | `strict` / `check`, but **deviates**: `check` still drops invalid protected frames and only passes *untagged* ones (§4.8). |
| **Confidentiality offset 0/30/50, `E`/`C` bits** | Clear prefix, or integrity-only. | Integrity-only kept (§4.9); offsets dropped. |
| **MKA liveness** | 2 s hellos, 6 s lifetime. | None. Exchange is pulled on demand by a frame under an unknown key (§4.3), so idle links cost no airtime. |

Why not MACsec itself:

- **One CA per LAN with a cheap, reliable control plane** (MKPDUs every 2 s).
  A duty-cycle-limited LoRa segment cannot afford it, and a partitioning radio
  splits a key-server election into two incompatible SAKs.
- **Ethernet framing, and the Linux `macsec` netdev only.** It covers none of
  the radio links or boards. Kernel MACsec can still be stacked under a
  `RawL2` link by an operator who wants it.
- **AES-GCM only.** The STM32F411 has no AES hardware and software AES needs
  care to be constant-time.

**What the repo already provides.** The review that produced revision 3 found
that most of an exchanged-key control plane exists:

- **An authenticated secret with every verified neighbor, at no airtime cost.**
  `Keypair::pairwise_key` (`libs/wayfinder-auth/src/key.rs:121`) is a
  static-static X25519 exchange computed when a peer's certificate first
  verifies (`libs/wayfinder/src/auth/ogm.rs:329`) and cached per neighbor in
  `NeighborKeys` (`libs/wayfinder/src/auth/mod.rs:439`).
- **A one-hop request that already carries the requester's certificate:**
  lazy distribution's `CertReq` (`libs/wayfinder/src/auth/distribution.rs`),
  the model for the key request in §4.3.
- **A revocation flood** in OGM tails, which is the rekey trigger (§4.7).

Other prior art: **802.15.4 MAC security** (AES-CCM\*; the source address and
frame counter go *in the nonce* under one group key — §9 compares);
**LoRaWAN** (`FCnt` reuse after reset is its classic bug, which a per-boot
random key cannot have); **BLE 5.4 Encrypted Advertising Data** (medium-
specific, unavailable on the SoftDevice in use); **WireGuard** (per-peer
sessions; its handshake is the closest analogue to §4.3's exchange, and it
shares §5.3's live-snapshot caveat).

### 2.1 Crypto choice

`wayfinder-auth` already uses X25519, Ed25519 and BLAKE2s — WireGuard's Noise
suite minus its AEAD. The AEAD here is **ChaCha20-Poly1305** (RFC 8439):
constant-time in plain software, fast on Cortex-M4 and Xtensa without an
accelerator, one primitive beside three we have. It is a **new dependency**
(`chacha20poly1305`, `no_std`): the `chacha20 0.10` in `Cargo.lock` comes only
through host-side `rand`, and is absent from the firmware lockfiles.

Rough cost: software ChaCha20-Poly1305 on an M4 is ~40–60 cycles/byte plus
~5 k cycles per frame — ~0.5 ms for 512 B at 64 MHz, small beside an Ed25519
verify, and no executor-blocking concern at radio rates. A USB-NCM management
link near 1 MB/s would eat most of the CPU, which is one reason it is never
offered `security` (§4.10).

RustCrypto's `chacha20poly1305` has a fixed 16-byte tag. The 8-byte ICV
(version 1, §4.2) therefore means assembling RFC 8439 from `chacha20` +
`poly1305` and truncating, with the RFC's test vectors and a constant-time
compare — part of the §10 spike.

The SecTAG version field leaves room for an AES-CCM suite where hardware
exists (nRF ECB, ESP32 AES, the WL55's AES engine).

## 3. Goals / non-goals

**Goals**

- Per-link, opt-in confidentiality and integrity against anyone without a
  sender key, on every carrier, in all three driver shells **from one
  implementation** (driver-core).
- **Admission follows membership.** A node reads a link only while it holds a
  valid, unrevoked certificate; revocation shuts it out without an operator.
- Broadcast stays one encryption, one transmission.
- No `(key, nonce)` reuse **by construction** — across reboots, crashes,
  restored backups, counter exhaustion and two interfaces — with no persisted
  counter.
- Replay protection that survives the sender *and the receiver* rebooting.
- Idle links cost no control-plane airtime.
- Metrics per interface, in `CentralRouter`.
- Keys never written onto a node: membership keying needs no key material at
  all; a pre-shared key arrives from an operator-side secret or over the
  management API.

**Non-goals**

- **End-to-end** encryption. Hop-by-hop, as MACsec: relays see plaintext.
- **Insider protection.** A neighbor holding a sender's key can read and forge
  that sender's link frames (§6). Member-to-member authenticity stays with
  `OgmAuth`, unchanged.
- **Traffic-analysis resistance.** No padding in v1.
- **Forward secrecy against long-term key compromise** in v1. Sender keys are
  wrapped under the static-static pairwise secret, so a stolen X25519 secret
  unwraps recorded exchanges. The message format reserves room for an
  ephemeral term (§4.3); adding it is a follow-up.

## 4. Design

### 4.1 Layering: router-owned state, driver-core functions

```
 carrier recv ─► driver-core::receive_frame(router, iface, frame, rx_scratch, sink)
                   ├─ control frame (key exchange) → router.linksec_mut().handle_control → reply staged on iface
                   ├─ drop → router.record_linksec_drop(iface, reason)
                   └─ plaintext LinkFrame → handle_mesh_frame (unchanged)
                 returns the accepted src, for the shell's confirm_peer (§5.6)

 router plans ─► plan_dispatch ─► for each target iface in the plan:
                   driver-core::protect_for(router, iface, &plan, tx_scratch) ─► link.send
```

- **`wayfinder-linksec`** — synchronous, allocation-free, no `LinkT`, no
  async, no clock, no store. SecTAG codec, AEAD calls, replay window, and the
  key-exchange message codec and state machine. All of the unit tests, a fuzz
  target on the validator and the control-message parser, the bench.
- **`LinkSec` in `CentralRouter`** — a const-generic table (a capacity
  profile, like `OgmAuth`'s): per-interface config (keying, validate, encrypt,
  port); this node's own sender key and counter per secured interface; the
  **SA table** of neighbors' sender keys with their replay state; in-flight
  exchanges; counters. Owning it in the router gives the management API
  (`RouterAdapter`) and the key agent one place to install keys, and satisfies
  "state lives in `CentralRouter`". The key agent reads `OgmAuth`'s keypair,
  trust anchor, verified-cert cache and revocation list directly.
- **driver-core** — two functions, one behavior for all three loops:
  - **`receive_frame`** is the one ingress path. `handle_link_result`
    (`libs/wayfinder-driver-core/src/lib.rs:1202`) calls it, and so does the
    tick driver, which today bypasses `handle_link_result` and calls
    `handle_mesh_frame` directly (`libs/wayfinder-tick-driver/src/lib.rs:364`).
    Without that change `wayfinder-test` and the sim would never validate.
  - **`protect_for`** runs **once per (frame, interface)**, not once per plan:
    a `DispatchPlan` is one payload for a whole `InterfaceSet` (`:1380`), but
    `port` and the sender key are per interface, and so is the counter. Each
    shell already loops over `plan.targets()` — tokio
    (`libs/wayfinder-driver/src/driver.rs:2462`), embedded
    (`libs/wayfinder-embedded-driver/src/lib.rs:1103`), tick
    (`libs/wayfinder-tick-driver/src/lib.rs:551`) — and calls `protect_for`
    inside that loop. The logic stays in driver-core; each shell gains one
    call.
- **The tokio lock rule.** The tokio driver drops the router write lock before
  any link I/O on purpose (`driver.rs:2420`). `protect_for` needs
  `&mut LinkSec` for the counter. So the tokio shell protects every target of a
  plan into its own buffer while it still holds the plan's guard, releases the
  lock, then sends. The host can afford one buffer per target; the embedded and
  tick shells are single-threaded and protect inline.
- **Scratch buffers** — validate needs a plaintext buffer, since
  `Received.frame` is immutable and borrows the link. Validation writes into a
  separate rx scratch, so it does not fight that borrow, and finishes before
  the next `recv` is polled. On boards both scratches are `Driver` fields
  beside `tx_buffer`, sized `FRAME_LEN` plus the overhead; the driver lives in
  the node task's poll frame (`libs/wayfinder-nrf/src/node.rs:227`,
  `bins/wayfinder-wl55jc/src/main.rs:279`), which `just stack-budget` already
  watches. Boards construct through `Driver::with_capacities`
  (`libs/wayfinder-embedded-driver/src/lib.rs:495`).
- **Entropy.** The router has no source of randomness today. The shell hands
  `LinkSec` an `Entropy` source at construction: the host draws from the OS
  (`getrandom`) on every call; a board seeds a ChaCha20 DRBG from its hardware
  RNG at boot (the nRF's `RNG`, the WL55's TRNG, the ESP32's SAR-ADC TRNG);
  the tick driver and the sim take a seeded one. Each board's `identity::
  resolve` currently consumes its RNG peripheral (for example
  `libs/wayfinder-nrf/src/identity.rs:154`) and must hand it, or a seed, on.
  A node with no hardware RNG (the STM32F411) is refused `security`. Three
  rules, because a weak or constant seed repeats every sender key, key id and
  nonce on every boot — total nonce reuse:
  - the board runs its TRNG's health and error checks (the WL55's and nRF's
    error flags, the ESP32's documented RF-subsystem precondition) and refuses
    `security` if they fail;
  - the seed is **never** derived from the identity seed, the tempting shortcut
    once `identity::resolve` has consumed the RNG;
  - the seeded `Entropy` the tick driver and the sim use is behind a feature
    that `wayfinder-tap` and the board binaries never enable.
- **`SecureLink<L: LinkT>`** — not built. Revision 1 used it; the review showed
  it had no key-install path, no error channel carrying `src`, and `recv`-loop
  borrow problems (E0499). An out-of-tree consumer that wants a decorator can
  wrap `wayfinder-linksec` itself.

### 4.2 Wire format

```
dst(6) src(6) protocol=LINKSEC(2) │ TCI(1) PN(8) │ ciphertext(inner_proto(2) ‖ payload) │ ICV(16|8)
                                  └── SecTAG ───┘
```

- `LINKSEC = 0x88B6`. IEEE's local-experimental EtherTypes are only `0x88B5`
  and `0x88B6`, and the router already demultiplexes `0x88B5`
  (`libs/wayfinder/src/lib.rs:2056`). Not `0x88E5`: this is not 802.1AE and
  must not confuse a real MACsec stack on a `RawL2` segment.
- `TCI` — `version:2 | E:1 | C:1 | port:3 | reserved:1`.
  - Version 0 = ChaCha20-Poly1305, 16-byte ICV; version 1 = the same with an
    8-byte ICV, allowed only on links configured for it (§4.6 step 2).
  - `E` = 1: encrypted, 0: integrity-only.
  - `C` = 1: a key-exchange control message (§4.3), carried in the clear and
    never forwarded. The rest of this section describes `C` = 0.
  - `port` = the sender's interface index, so only the first eight interfaces
    of a node can enable `security`.
- `PN` — 64-bit big-endian, `key id:32 ‖ counter:32`. The key id is chosen at
  random when the sender key is minted and names it; the counter starts at 0
  for each key.
- **Inner protocol is encrypted**, as in MACsec.
- **AAD** = `dst ‖ src ‖ LINKSEC ‖ TCI ‖ PN`, all fixed-width. In
  integrity-only mode the AAD additionally covers `inner_proto ‖ payload`, the
  plaintext is empty, and `E` (in the TCI) is authenticated.
- **Nonce** = `0x00000000 ‖ PN`. Unique because the key is fresh per key id
  and the counter never repeats under it (§5.1).

**Overhead is 27 B per frame** (TCI 1 + PN 8 + the relocated `inner_proto` 2
+ ICV 16), **19 B at version 1.** Measured against the carriers:

| Carrier | Fragment payload | Effect |
|---|---|---|
| 802.15.4 (`libs/ieee802154`) | 114 B | a lazy-auth OGM is already 112 B (OGM header 18, two TVLVs of 12 and 68, link header 14), so **any** overhead takes the most frequent frame from 1 fragment to 2 |
| BLE extended (`libs/blue`, design 07) | 231 B; `MAX_REASSEMBLED_LEN` = 270 | the binding limit is the 270 B reassembly cap: a full-cert OGM (~250 B) fits at version 1 (269 B) and **does not fit at version 0** (277 B) |
| BLE legacy | 18 B per fragment, same 270 B cap | as extended for the cap; one more fragment for a lazy-auth OGM |
| Raw LoRa (`libs/lora-link`, the WL55) | 250 B | a full-cert OGM goes from 1 fragment to 2 on a duty-cycled band |
| LoRa (RYLR998) | 178 B | a lazy-auth OGM stays at 1; a full-cert OGM is already 2; bridged frames of 152–178 B become 2 |
| UDP / `Tap` | MTU | full-size frames exceed a 1500 B underlay unless `DEFAULT_MTU` subtracts the overhead |

With the existing directed trailer, a directed LoRa frame carries 27 + 24 =
**51 B of security overhead**. §10 makes the fragment counts a gate.

Two things that overhead touches beyond the MTU:

- **The router's frame cap.** The nRF and WL55 capacity profiles pin
  `max_frame_len` equal to the link's 512 B reassembly limit, so a full-size
  frame plus overhead would be refused by the link. A secured interface
  advertises `link cap − overhead` as its payload cap to the router.
- **The fan-out merge.** `merged_frame_fits`
  (`libs/wayfinder-driver-core/src/lib.rs:663`) checks a merged multicast
  against `FanOut::max_frame_len` (PR #95). On a secured interface it must
  count the overhead too, or a merge that fits in plaintext is refused by the
  radio once protected.

### 4.3 Keying: sender keys, exchanged one hop

**Sender keys.** For each secured interface, a node holds one **sender key**
`SK` — 32 random bytes from its entropy source — and a random 32-bit key id.
It protects every frame it sends on that interface under `SK` and stamps the
key id into the PN. A fresh `SK` is minted at boot, on counter exhaustion, and
on a neighbor's revocation (§4.7). It is never persisted.

**Receivers learn sender keys on demand.** A receiver that gets a protected
frame under a `(src, port, key id)` it holds no key for drops it (`NoSA`) and
pulls the key with a one-hop exchange on the same interface:

```
B (receiver) ──── KeyReq ────► A (sender)
                  { target_port, wanted key id, req_nonce(16), B's fingerprint, [B's cert] }
B ◄─── KeyResp ── A
                  { req_nonce echo, resp_nonce(16), A's fingerprint, [A's cert],
                    port, key id, counter floor, wrap(SK_A), [want: B's port p, want_nonce(16)] }
B ──── KeyResp ──► A          (only if A asked: B's own key, answering want_nonce
                               with a fresh resp_nonce of B's own)
```

Every `KeyResp` answers exactly one request nonce — a `KeyReq`'s `req_nonce`
or a `want_nonce` — and carries a fresh `resp_nonce` of its own.

- **The wrapping key** is single-use, derived per exchange:

  ```
  W     = pairwise_key(A, B)                       (membership keying)
        | BLAKE2s-keyed(key = PSK, "wf-linksec-psk-v1")   (psk keying, §4.11)
  K_wrap = BLAKE2s-keyed(key = W,
             "wf-linksec-wrap-v1" ‖ src_mac ‖ dst_mac ‖ src_fpr ‖ dst_fpr
                                  ‖ request_nonce ‖ resp_nonce ‖ port ‖ key id)
  ```

  `wrap(SK)` is ChaCha20-Poly1305 under `K_wrap` with a zero nonce and the
  message header as AAD. The zero nonce is safe only because `K_wrap` is
  single-use, which three rules make true on every path: each `KeyResp`
  *transmission* draws a fresh `resp_nonce` (a retransmit resends the identical
  cached bytes, never a re-encryption); a node answers a given request nonce
  at most once, replaying its cached response to duplicates; and message 3
  answers `want_nonce` with B's own fresh `resp_nonce`, so it has a fresh
  value of its own in the derivation. Without the last rule, B answering one
  `want` twice — a retransmit, a duplicated radio frame, or a replayed
  message 2 — would wrap twice under one key and reuse Poly1305's one-time
  key. The label separates it from
  `frame_tag`'s use of the same pairwise key (`"wayfinder-tag-v2"`,
  `libs/wayfinder-auth/src/pairwise.rs:30`), so no second X25519 per neighbor
  and no raw DH output kept in memory.
- **Authenticity.** Only A and B can compute `W` (given #103's contributory
  check), and B did not produce the response, so a `KeyResp` that opens came
  from A. A's certificate in the response, or the one already cached for A's
  fingerprint, is verified against the trust anchor and the revocation list
  before `W` is computed.
- **The certificate must name the sender.** In both directions, a message is
  refused unless the certificate it uses — attached, or cached for its
  fingerprint — has `node_mac == src`. Without this an insider M answers B's
  request to A with `src = A` and M's own cert; it opens under `W(B, M)` and
  installs an SA for A that M controls, locking A's real key out of B and
  surviving M's revocation. Both fingerprints are in `K_wrap` for the same
  reason. Each SA records the fingerprint of the certificate that installed
  it.
- **Freshness.** The `req_nonce` is B's, fresh from its entropy source, and is
  bound into `K_wrap`. A replayed `KeyResp` opens for nobody. This does not
  rely on the pairwise replay counter, which a rebooted receiver re-anchors on
  first sight (`libs/wayfinder/src/auth/pairwise.rs:375`).
- **The request is unauthenticated, and needs no signature.** Anyone can send
  a `KeyReq` naming B's certificate (it is public), but the response is
  wrapped under `W`, which the forger cannot compute. What it costs is the
  responder's CPU and airtime — a first-contact request means an Ed25519
  verify (tens of milliseconds on an M4) and one X25519, and a 42 B request
  draws a 114–262 B response — so the limits are explicit (§5.2): a backoff
  per requester fingerprint, a per-interface budget, and no per-request state
  at the responder. The `want_nonce` is `PRF(secret, B, req_nonce, time
  bucket)`, so a responder can check message 3 without having stored
  anything for the forged requests that never complete.
- **The request names the key id it wants**, taken from the frame that
  triggered it. A responder answers only for its current key; if the wanted
  key id is older, the response says which key id superseded it, and the
  requester records that and does not pull again for frames under the stale
  id.
- **Certificates ride along on first contact.** The requester attaches its
  certificate unless it has completed an exchange with that peer since boot. A
  responder that no longer holds the requester's cert (its `NeighborKeys` entry
  was evicted) answers `NeedCert`, and the requester retries with it. A
  certificate learned here is fed into `OgmAuth`'s verified cache, so
  `OgmAuth` needs no `CertReq` for that neighbor. When a cert is attached, the
  fingerprint is omitted (it is derived from the cert).
- **One response sets the window.** An in-flight request is consumed by its
  first valid response, and only a response to the requester's newest
  outstanding request for that `(src, port)` may install an SA. A delayed or
  duplicate response is dropped, so two responses with floors `f0 < f1` cannot
  arrive out of order and lower the window. A response never lowers an
  existing window.
- **Mutual in three messages.** A responder that also lacks the requester's key
  sets `want` with a `want_nonce`, and the requester answers it in message 3.
  First contact between two nodes is therefore one round trip and a half.
- **The counter floor.** A response carries the sender's current counter under
  that key id. The receiver anchors its replay window there, so frames
  captured earlier under the same key are `Late` (§4.5).
- **Ephemeral term (reserved).** The `KeyReq`/`KeyResp` formats reserve a flag
  and an optional 32-byte field for an ephemeral X25519 key. Mixing
  `DH(e_A, e_B)` into `K_wrap` gives forward secrecy against long-term key
  compromise at one X25519 per side per exchange. It is a follow-up, not v1
  (§3) — and it does not fit as specified: a `KeyResp` carrying both a
  certificate and an ephemeral key is ~294 B, over BLE's 270 B cap (§9).

**Message sizes**, with the 14 B link header and the 1 B TCI:

| Message | Without cert | With cert (156 B) |
|---|---|---|
| `KeyReq` | ~46 B | ~194 B |
| `KeyResp` | ~114 B | ~262 B |
| `KeyResp` with `want` | ~130 B | ~278 B |

(`KeyReq` grew 4 B for the wanted key id; `want` adds its 16 B nonce.) First
contact with both certs is ~194 + 278 + 114 ≈ 590 B per pair of nodes, once per
boot. A lazy-distribution `CertReply` already costs a cert, so on
LoRa this is the same order as what `OgmAuth` pays now; there is no periodic
cost. A `KeyResp` with a cert fits BLE's 270 B cap with 8 B to spare, but not
when it also carries `want` (278 B). On BLE a first-contact responder therefore
sends its own key request as a separate `KeyReq` instead of `want` — four
messages instead of three.

**Where it lives.** The key agent is part of `LinkSec` in the router.
`receive_frame` hands `C` = 1 frames to `LinkSec::handle_control`, which may
stage a reply. A `NoSA` drop queues a `KeyReq` for the tick after it, subject
to the rate limits. Both go out as one-hop frames on the interface they
concern, through the same sink as everything else, and are never forwarded.

### 4.4 Nonce uniqueness without persistence

Repeating `(key, nonce)` under ChaCha20-Poly1305 leaks plaintext XOR and allows
Poly1305 forgery. Revision 2 prevented it with a persisted boot counter, which
needed an append-only flash page on every board, a directory `fsync` on hosts,
a reserve-before-use protocol, and a refusal on nodes with no store — and the
review still found crash windows in it. Revision 3 removes the counter's need
to persist:

- **Every sender key is fresh 256-bit randomness**, minted at boot and on
  every rekey. Two keys never coincide with any meaningful probability, so a
  counter that restarts at 0 under a new key never meets an old nonce.
- **The counter never wraps under one key.** At 2³² − 1 the node mints a new
  key and pulls receivers onto it (§4.7). That is unreachable on a radio link
  and takes ~12 h at 100 k frames/s on host UDP.
- **Nothing is stored**, so a restored backup, a reflashed board or a copied
  Docker volume brings back no key and no counter.

This needs a working entropy source at boot (§4.1), and there is no fallback
without one: a node with no hardware RNG is refused `security`. The one way to
repeat a nonce left is to duplicate a *running* process's memory — a live VM
snapshot restored twice (§5.3).

### 4.5 Replay state

- **Keyed `(src, port, key id)`, node-wide**, and each sender key is
  **installed per receiving interface**. A key B pulled on `lora0` is accepted
  only on `lora0`, so a frame relayed from one segment onto another is `NoSA`
  there. That closes the cross-segment steering attack: jam B's copy on `S0`,
  replay it on `S1`, and B's BATMAN would place A on the wrong interface. When
  B hears A's port on two of its own interfaces, it pulls the key on each, and
  the node-wide replay entry still stops a frame counting twice — but then the
  steering attack is open again between those two interfaces, since the key is
  legitimately valid on both. The protection holds where each of a neighbor's
  ports is heard on one interface.
- Each entry: high-water counter plus a sliding bitmap (default 64).
- **Allocated and updated only after AEAD verification.** Otherwise a forged
  PN advances the window and black-holes the real sender, and a flood of fake
  `src`s evicts real entries. A new entry's window starts at the counter floor
  from the exchange that installed it (§4.3).
- **A rebooted receiver does not accept replays.** It starts with no keys, so
  every captured frame is `NoSA` until it pulls the sender's current key, and
  the counter floor in that response rejects everything captured under that
  key before the pull. Frames under the sender's older key ids stay `NoSA`
  forever: the sender no longer answers for them. (Revision 2 claimed a
  rebooted receiver accepts "one replay" — that was wrong in its own design,
  where the inner guards are also RAM and re-anchor on first sight.)
- **Capacity.** Installing a newer key for a `(src, port)` retires the older
  one at once (§4.7), so normally one entry per sender port is live. Each
  **neighbor** has a quota (default 2 entries across all its ports), so an
  insider advertising eight ports cannot take sixteen slots; the SA table is
  sized `neighbors × quota`. When the table or a quota is full, a new key is
  refused (`NoSA`, alarmed as `LinkSecTableFull`) rather than evicting a live
  entry, and only entries idle past a threshold are reclaimed. The
  coupling matters: `OgmAuth`'s `NeighborKeys` cache (64 by default,
  `libs/wayfinder/src/auth/mod.rs:182`) overwrites a live entry when full
  (`libs/wayfinder/src/auth/pairwise.rs:603`), which costs the next exchange a
  `NeedCert` round trip but never an SA. See the open table-full advert-storm
  finding before raising either cap.

### 4.6 Validate pipeline

In order, each a distinct `SecDrop` reason counted per interface:

1. `protocol != LINKSEC` → `strict`: drop (`Untagged`). `check`: pass, counted,
   unless this `src` has already validated a protected frame (§4.8).
2. `version` not allowed on this link (version 1 only where configured),
   length below SecTAG + ICV, or `port` ≥ 8 → `BadTag`.
3. `C` = 1 → hand to the key agent (§4.3); never reaches the router.
4. `encrypt: true` and `E = 0` → `Downgrade`.
5. **`src` is this node's own MAC** — always dropped, never stops transmit:
   - key id not one of ours → `NoSA`, and no `KeyReq`;
   - counter at or below what we have sent under that key → `SelfEcho`: a
     replay of our own frame or a loopback, silent;
   - otherwise open it under our own sender key: fails → `NotValid`; opens →
     `Clone` (§5.3), alarm only.
6. No SA for `(src, port, key id)` on this interface → `NoSA`; queue a
   rate-limited `KeyReq`.
7. Counter at or below the window floor, or already seen → `Late`. Checked
   before decryption, read-only.
8. AEAD open fails → `NotValid`.
9. Update replay state; yield `LinkFrame { dst, src, inner_proto, payload }`
   from rx scratch, and return `src` to the shell for `confirm_peer`.

Revision 2 checked `Clone` before `Late` and stopped transmitting on a match,
so anyone who replayed one of a node's own frames back at it silenced every
secured link — and so did a carrier that loops multicast back
(`libs/wayfinder-driver/src/net.rs:455`).

Drops are `trace!` (remote input on a hot path). They never latch the
interface's `LinkErrors` alarm.

### 4.7 Rekey

- **On a neighbor's revocation:** drop every SA whose installing
  certificate's fingerprint is the revoked one — by fingerprint, not by MAC —
  mint a new sender key on every interface where the revoked node held ours,
  and switch to it. Remaining neighbors get `NoSA` on the next frame and pull
  the new key; the revoked node's `KeyReq` is refused because its certificate
  is revoked. Each neighbor loses one round trip of frames per rekey, which
  revocation can afford.
- **The residual window is revocation propagation.** Until a neighbor C has
  processed the revocation and rekeyed, the revoked node still holds C's
  sender key and can read C's frames and forge frames as C to C's other
  neighbors. The window lasts as long as the revocation takes to flood.
- **A newer key retires the older one.** When a receiver installs a newer key
  for a `(src, port)`, it drops the older SA immediately: the sender has
  already switched, so nothing in flight still needs it, and an old key left
  to idle out is one more key a revoked node may hold.
- **On counter exhaustion:** mint the next key and switch to it. Receivers pull
  it on their first `NoSA`, losing one round trip of frames.
- **On boot:** implicit — there is no previous key.
- **Periodic rekey** is a config option (`rekey_after`), off by default. It
  bounds how much traffic one stolen sender key exposes, at one exchange per
  neighbor per period.

### 4.8 Rollout policy (`validate`)

- `strict` — default. Only valid protected frames, plus key-exchange control
  messages, reach `LinkSec`; only valid protected frames reach the router.
- `check` — protected frames are still validated **and dropped if invalid**.
  Untagged BATMAN frames pass, counted, **until that `src` has validated a
  protected frame**; after that its untagged frames are dropped, so a node
  that has upgraded cannot be impersonated in cleartext. That deviates from
  802.1AE's Check (which delivers invalid integrity-only frames). It is for a
  rolling upgrade; the counter at zero is the signal to flip to `strict`.

A `check` link admits outsiders by definition (§6, §5.5).

### 4.9 Integrity-only mode (`encrypt: false`)

Same SecTAG and ICV, payload in the clear, authenticated as described in §4.2.
Amateur-radio rules (e.g. FCC Part 97) prohibit encryption that obscures
meaning but allow authentication, and much LoRa mesh hardware sits on ham
bands. Also useful for debugging with `wayfinder-shark`. A link configured
`encrypt: true` rejects `E = 0` frames (§4.6 step 4), so integrity-only cannot
be forced on it. The exchange still wraps the sender key, since an
integrity key must stay secret too; whether wrapping key material is permitted
on a given band is the operator's call, and the payload itself stays readable.

### 4.10 Configuration

**`wayfinder-tap` YAML** — sibling of `features`, orthogonal to the transport:

```yaml
links:
  - name: lora0
    type: Rylr998
    # …transport fields…
    security:
      keying: membership        # membership | psk
      validate: strict          # strict | check
      encrypt: true             # false = integrity-only
      replay_window: 64
  - name: sim0
    type: UdpMulti
    security:
      keying: psk               # a mesh with no trust anchor
      key_file: /run/secrets/sim0.key   # exactly 32 bytes, hex or base64
  - name: vpn
    type: UdpMulti              # already inside WireGuard — leave unsecured
```

- **`membership` needs no key material**: it uses the node's identity and
  certificate. It requires a trust anchor (`auth` configured); without one it
  is refused at startup.
- **`psk`**: `key_file`, never an inline key, because
  `services.wayfinder.config` lands in the world-readable Nix store.
  `nix/modules/wayfinder.nix` gains `LoadCredential=` — not a capability. In
  Docker, `key_file` points at a mounted secret (`/run/secrets/…`). This is an
  operator-side input, like `auth.seed_path` (`libs/wayfinder/src/config.rs:
  559`), not a file the node is expected to be provisioned through.
  Key material is **exactly 32 bytes**; no passphrase derivation, because a
  fingerprint of a low-entropy key is an offline guessing oracle.
- **Validation at startup:**
  - `security` on a node whose MAC is not identity-derived is refused (a
    configured or `mac_state_path` MAC is copy-pasteable, §5.3).
  - `security` on a node with no entropy source is refused (§4.4).
  - More than eight secured interfaces is refused.
  - A `warn!` when `strict` links coexist with `check` or unsecured links on
    the same node (§5.5).
- `DEFAULT_MTU` (`libs/wayfinder/src/config.rs:449`, `TAP_ENCAP_OVERHEAD` at
  `:485`) subtracts the overhead when the egress link is secured; the test
  pinning the literal changes.
- **Boards:** the nRF's USB-NCM management link is never offered `security`
  (pass-through), for CPU reasons (§2.1) and because it is not a mesh medium.

**Runtime** — `SetLinkSecurity { interface, keying, validate, encrypt }`,
`SetLinkKey { interface, key }` and `ClearLinkKey { interface }` (both `psk`
only), declared in `rpc.rs`'s `rpc_table!` at the admin tier and audited,
reaching `LinkSec` through `RouterAdapter`. **Keys are write-only.** A key set
over RPC is persisted through `Persisted` (host: `runtime_state_path`; board:
the existing `DurableStore`) and **overrides** `key_file` until cleared;
`ClearLinkKey` falls back to `key_file`. Persisting a PSK is safe under §4.4:
it is a wrapping secret, never a nonce-bearing key. The boards' serial
management port is unauthenticated by decision (#57); setting a PSK there
assumes physical access, the same trust that port already has.

### 4.11 Keying modes

Both modes run the same exchange and the same data plane; only the wrapping
secret `W` (§4.3) differs.

| `keying` | `W` from | Admission follows | Fits |
|---|---|---|---|
| `membership` | the pairwise X25519 secret of two verified certificates | certificates and revocation | every mesh with a trust anchor — the default |
| `psk` | a 32-byte pre-shared key | possession of the key | meshes with no trust anchor: the sim, Docker test setups, integrity-only ham deployments; also the first integration target, since it exercises the SecY and the exchange without a CA |

A link never mixes modes: a revoked member holding a PSK would still get in.

Radios that already encrypt their own link make this layer redundant for
confidentiality; `membership` is still worth enabling there to tie admission to
mesh membership.

The WL55 relay can use neither mode yet. It has no `OgmAuth` (nothing in
`bins/wayfinder-wl55jc/src` references it) and no management port to carry a
PSK; both are design 28's to decide, since the port is 42.1 KiB over flash
(design 28 §2). The relay has ~37.8 KiB of flash free today, so §10's spike
measures the AEAD on `thumbv7em-none-eabi` against this image. Its hardware
AES engine makes an AES-CCM suite (TCI version 2) the fallback if
ChaCha20-Poly1305 does not fit. The F411 stays the external-module LoRa proof
and is not a `security` target (no RNG).

### 4.12 Observability

Through `add-metric`, all in `CentralRouter`, **per interface** — no per-`src`
state is created for unverified input:

- protected-tx rate, validated-rx rate, `check`-passed cleartext rate, drop
  rate by `SecDrop` reason;
- key exchanges started, completed, refused (revoked, rate-limited,
  `NeedCert`), and rekeys;
- SA-table and in-flight-exchange occupancy;
- `GetLinkSecurity`: per interface keying, validate, encrypt, suite, port,
  this node's current key id, the number of neighbor SAs, a PSK's
  **fingerprint only** — `BLAKE2s("wf-linksec-fpr" ‖ K)[..8]`,
  domain-separated — and a node-level "weakest admitting link" (§5.5).

`src` appears only in `trace!` records.

**Alarms** — raised from `LinkSec` itself (detectors live beside their state):

- `LinkKeyMismatch(iface)`: a frame fails AEAD under an SA installed by a
  successful exchange within the last window — keyed on verified SAs, never on
  unverified sources;
- `LinkSecClone`: a frame verified under this node's own `src` with a counter
  it never issued (§5.3);
- `LinkSecCounterJump(iface)`: a sender's counter jumped far ahead of its
  rate (insider pinning, §6);
- `LinkSecTableFull(iface)`: a new SA was refused for capacity (§4.5).

The board coalesces each, so a hostile flood is one row.

## 5. Correctness argument and edge cases

### 5.1 Nonce uniqueness

`(SK, nonce)` is unique because:

- each `SK` is 256 bits of fresh randomness, minted per boot and per rekey, so
  two sender keys coincide only with negligible probability;
- under one `SK`, the counter strictly increases and `LinkSec` mints a new key
  instead of wrapping;
- `K_wrap` is single-use: it binds two fresh nonces and the key id;
- nothing nonce-bearing is ever persisted or restored.

The remaining assumptions are a working entropy source and that a running
process's memory is not duplicated (§5.3).

### 5.2 Forgeries cannot poison state

Replay entries are created and moved only after AEAD success (§4.5), and a
forged `KeyResp` does not open. The exchange is still a DoS surface on a
duty-cycled band, in both directions:

- **Forged `NoSA` frames** with random `src` values would each cost the
  receiver a `KeyReq`. So a receiver pulls only after it has seen the same
  `(src, port, key id)` more than once within a short window, and spends its
  per-interface budget on sources with a cached verified certificate first.
  Per-`src` limits mean nothing against forged sources, which is why the
  budget is per interface.
- **Forged `KeyReq`s** naming any member's public fingerprint draw a response
  several times their size. The responder backs off per requester
  fingerprint and keeps no per-request state (the stateless `want_nonce`,
  §4.3), so forged requests cannot fill the in-flight table.

An attacker who keeps transmitting can still delay genuine joins for as long
as they transmit — that is jamming at the protocol layer, and it is not
bounded by the rate limit; the limits bound what it costs the victim.

### 5.3 Duplicate senders

Two nodes with the same derived MAC — a cloned image, a copied identity — no
longer threaten nonce reuse: each mints its own random `SK` at boot. What is
left is the routing confusion of two nodes sharing an address, and that is
what clone detection reports:

- `security` requires an identity-derived MAC (§4.10);
- a frame verifying under this node's own `src` and sender key with a counter
  it never issued raises `LinkSecClone` — the signature of a forked live
  process. It is alarm-only: any insider holding our key can forge one, and
  stopping transmit on it would hand them a kill switch. A replay of our own
  frame, or a loopback, is `SelfEcho` and silent (§4.6). A clone that minted
  its own key is not detectable here, since its frames cannot be verified; it
  shows up as two nodes answering for one address.

**Live snapshots.** Restoring a *running* VM snapshot twice yields two
processes with the same in-memory `SK` and counter, which do reuse nonces.
That is the same limit WireGuard has. Disk backups and stopped-VM images are
safe, since nothing is persisted; the NixOS module and the Docker docs say not
to fork running nodes.

### 5.4 Fail-closed routing

A neighbor that cannot complete an exchange — wrong mesh, revoked, wrong PSK —
is never heard, so it never earns TQ: no half-working routes. `check` is the
only intentional exception. Dropped frames never reach `LinkMetrics`, so the
link-quality EWMA ignores them.

### 5.5 Trust is hop-by-hop

A frame admitted on a `check` link, an unsecured link (the YAML's `vpn`), or a
`psk` link is re-protected onto every other link without provenance. "Every
broadcast is authenticated" holds only if every link the frame crossed was
`strict`. Hence the startup warning and the "weakest admitting link" gauge.

### 5.6 `UdpMulti` learns before validation

`libs/wayfinder-driver/src/net.rs:244` calls `peers.learn(frame.src, …)` as
soon as the frame arrives; the at-capacity eviction at `:65` then lets a flood
of forged `src`s evict real peers. Encryption invites the assumption that this
is closed, so the fix is in scope:

- An optional `LinkT::confirm_peer(&mut self, src: Mac)` (default no-op).
- driver-core cannot call it: it has no `LinkT`, and `Received` holds the
  link's `&mut` borrow while the frame is alive. `receive_frame` returns the
  accepted `src`, and **each shell** calls `links[idx].confirm_peer(src)` after
  the frame's borrow ends.
- A `src` is confirmed only by a proof that binds the link-layer sender: a
  `LinkSec` AEAD open (the AAD covers `src`), or an `OgmAuth` directed tag.
  **Not an OGM signature**: it covers the originator's fields, not the
  forwarding hop's `src`, and a forwarder rewrites TTL and TQ unsigned
  (`libs/wayfinder/src/auth/ogm.rs:259`), so anyone can relay a captured
  signed OGM with `src = V` from their own socket and bind V to their address.
  Frames whose `required_proof` is `None` (`Ogm`, `Bcast`, `Keepalive`,
  `CertReq`, `CertReply`, `libs/wayfinder-driver-core/src/lib.rs:256`), and
  every frame on a node with no trust anchor, never confirm.
- `UdpMulti` keeps the `(src, SocketAddr)` of the datagram it last returned and
  commits that pair on confirm, so a confirmation binds to the address the
  verified frame actually came from.

### 5.7 Fan-out and `send_all`

Because `dst` is in the AAD, one ciphertext serves one `dst`. The design-17
collapse emits one `send` to `Mac::BROADCAST`, which is one `protect_for`, and
its fit check counts the overhead (§4.2). Nothing in production calls
`send_all` (only tests, `libs/wayfinder-driver/src/transport.rs:275`), and its
default — one `send` per destination — is correct under protection.

### 5.8 Header compression composes below

Designs 00/02 compress the outer `dst`/`src`/protocol below the link boundary
without inspecting BATMAN. They compose under the SecY unchanged, and because
`dst` is in the AAD, a frame decompressed against the wrong binding fails
verification. That is also the lever for 802.15.4 (§10): its MAC header
already carries short addresses, so eliding the 12 redundant address bytes
would pay for most of the overhead.

### 5.9 Fragments

Fragmentation stays below the SecY: one ICV per frame. Fragment injection can
spoil one reassembly; the ICV then fails. That is a DoS on one frame and is
already true of unauthenticated fragmentation.

### 5.10 Stack budget

Mark the AEAD and X25519 calls `#[inline(never)]` (the reason is on
`verify_signature`) and run `just stack-budget`.

### 5.11 Bootstrap

A node that has just booted can read nothing until it holds its neighbors' keys,
and they cannot read it. The first protected frame each side hears triggers the
exchange (§4.3), so both directions are keyed after one and a half round trips
per neighbor. OGMs stay encrypted throughout — motivation 3 holds — because
the only cleartext on a `strict` link is the exchange itself, which carries
certificates and nonces, not routing state. Its certificate exposure is the
same as `OgmAuth`'s full-cert OGMs today.

## 6. Security considerations

| Threat | `membership` | `psk` |
|---|---|---|
| Passive eavesdropper reads payloads, inner types, OGM contents | ✅ prevented | ✅ |
| Adjacency (who talks to whom), sizes, timing; certificates during exchange | ❌ visible | ❌ |
| Outsider injection/modification | ✅ on `strict` links; ❌ on `check` links | ✅ same |
| Replay, receiver up, sender rebooted | ✅ new key per boot | ✅ |
| Replay into a freshly rebooted receiver | ✅ counter floor from the exchange | ✅ |
| Cross-segment relay of a frame | ✅ SAs installed per interface | ✅ |
| Revoked member keeps reading | ✅ rekey on revocation; its `KeyReq` refused | ❌ until the operator rotates the PSK |
| Restored backup, reflash, copied volume reuses nonces | ✅ nothing persisted | ✅ |
| Live VM snapshot forked twice reuses nonces | ❌ as WireGuard (§5.3) | ❌ |
| Stolen long-term X25519 key reveals recorded traffic | ❌ until the ephemeral term (§4.3) | ❌ PSK theft reveals all |
| Insider forges a neighbor's frames on the link | ❌ by design: every neighbor holds the sender's key; `OgmAuth` still catches OGMs and directed frames | ❌ any PSK holder, as any `src` |
| **Insider pins a victim's window** (one frame, `src` = victim, counter = 2³² − 1) | ❌ alarmed (`LinkSecCounterJump`) only; it lasts until the victim rekeys, and a response never lowers a window (§4.3) | ❌ same |
| Insider answers a key request in another node's name | ✅ the certificate must name `src` (§4.3) | ❌ any PSK holder can |
| Revoked node reads or forges as a third neighbor | ❌ until the revocation reaches that neighbor (§4.7) | ❌ until PSK rotation |
| Forged `KeyReq` flood | CPU cost on the responder, rate-limited; leaks nothing | same |

Update `wayfinder-auth`'s crate docs: "per-hop confidentiality is optional
(design 27); end-to-end is left to L3".

### 6.1 X25519 contributory check — issue #103

`Keypair::pairwise_key` never checks `was_contributory()`, and nothing
upstream rejects a low-order `x_pubkey`: the CA's enrollment paths check only
its length (`libs/wayfinder-server/src/authority.rs:861`), `issue_cert` stores
it as given, and `verify_cert` never inspects it. Revision 2 called this "safe
as long as the CA validates `x_pubkey`"; the CA does not. An enrolled member
with such a key makes every pairwise secret it shares computable by anyone.
`membership` keying wraps sender keys under that secret, so **#103 is a hard
prerequisite** (§10 step 0).

## 7. Migration and versioning

- **Old nodes** treat a `LINKSEC` frame as an unknown protocol and drop it —
  but not without effect: before the protocol demux the router records link
  quality, `record_rx` and an ident-table entry for every frame
  (`libs/wayfinder/src/lib.rs:1482` onward). An old node therefore believes the
  link to an upgraded neighbor is good while learning no route through it. The
  rollout test asserts *no route learned and no alarm*, not *no effect*.
- **Rollout:** upgrade every node's binary with `security` off; enable `check`
  everywhere (nodes send protected frames and still accept cleartext from
  peers that have not yet switched); watch the cleartext-passed counter fall to
  zero; flip to `strict`.
- **Suites:** a version not allowed on the link is `BadTag`. A new suite is a
  new version value plus a config field; old nodes cannot talk to it, by
  design.
- **`wayfinder-shark`:** dissect the SecTAG and the key-exchange messages, show
  ciphertext as opaque, and show integrity-only payloads.

## 8. Alternatives considered

- **Static link key first, exchange later.** Revision 2's plan. Rejected after
  review: the static key needed the persisted epoch store — the most expensive
  and most error-prone part of the design — and left revocation to the
  operator, while most of the exchange's control plane already existed (§2).
  `psk` survives as the same exchange with a different wrapping secret.
- **A `LinkT` decorator (`SecureLink<L>`).** Revision 1's design. Rejected: no
  path for a management RPC or a key agent to install keys; no `src` on the
  error channel for metrics; `recv`-loop borrow problems; the tick driver
  would need a separate integration.
- **Encrypt frames with the existing pairwise keys.** Broadcast would cost one
  transmission per neighbor. Pairwise keys wrap sender keys instead.
- **CA-distributed group key.** The CA mints a per-epoch link group key and
  delivers it, wrapped to each member's X25519 key, over the design-24
  renewal path. Certificate-bound admission with no per-neighbor exchange
  airtime, but rotation depends on reaching the CA, and a group key needs the
  sender inside the nonce (as in 802.15.4) rather than its own key. Kept in
  reserve for a segment where even one exchange per neighbor per boot is too
  much airtime; the data plane would not change.
- **MKA-style liveness (periodic hellos).** Too much airtime on LoRa, and
  unnecessary once exchange is pulled by `NoSA` and replay floors come from the
  exchange.
- **802.15.4-style nonce = source address ‖ frame counter under one group
  key.** Needs a reboot-safe counter, i.e. the store revision 3 removed.
- **Persisted epoch with a random or clock-based fallback.** Revision 2's
  mechanism and its rejected fallbacks. A random sender key replaces both.
- **Linux kernel MACsec.** Ethernet and Linux only.
- **Noise/WireGuard sessions per neighbor.** Break broadcast. Noise's patterns
  inform the exchange (and its reserved ephemeral term), not frame protection.
- **MLS/TreeKEM group keying.** Needs totally ordered commits through a
  delivery service, which a partitioning mesh does not have.
- **Native medium security** (802.15.4 CCM\*, BLE LL, BLE 5.4 EAD).
  Inconsistent and unavailable on several carriers.
- **AES-GCM/CCM as the default.** No hardware on the STM32F411 or the
  nRF52840's SoftDevice path; a future suite, and the WL55's fallback (§4.11).
- **Random per-frame nonces (XChaCha20).** +16 B per frame and an entropy draw
  per frame, where a per-key counter costs neither.

## 9. Open questions

- **802.15.4's lazy-auth OGM** goes to two fragments under any overhead
  (§4.2). Accept that, or land the address elision of §5.8 first? The spike
  measures both; the decision is made before step 2.
- **Rate-limit values** for `KeyReq` (per `src`, per interface) and the SA
  idle threshold: set from the sim's scale and crowded-LoRa scenarios, not
  guessed.
- **Ephemeral term:** in the first release, or a follow-up? It costs one
  X25519 per side per exchange (milliseconds on an M4) and 32 B per message,
  which pushes a `KeyResp` with a certificate past BLE's 270 B cap — so it
  needs a fingerprint-only first contact or a split message on BLE.

## 10. Plan and gate

0. **Prerequisite: #103** (contributory check in `pairwise_key` and at the CA).
1. **Spike (the gate):**
   - ChaCha20-Poly1305 on `thumbv7em-none-eabihf` and `thumbv7em-none-eabi`
     (the WL55 image): flash cost and cycles/byte in `wayfinder-bench`; the
     8-byte-ICV construction with RFC 8439 vectors.
   - **Fragment-count tests with the overhead**, extending
     `extended_format_collapses_realistic_ogm_fragment_counts`
     (`libs/blue/src/frame.rs:508`) and adding the equivalents for
     `ieee802154` and `lora-link` (none exist today): full-cert and lazy-auth
     OGMs, a keep-alive, a bridged frame, and both key-exchange messages, at
     version 0 (27 B) and version 1 (19 B).
   - **Decision rule:** a full-cert OGM must fit BLE's 270 B cap at the version
     BLE links use, or the cap rises; a `KeyResp` with a certificate must fit
     every carrier's reassembly cap; 802.15.4's answer is §9's first question.
2. **`wayfinder-linksec`**: SecTAG, AEAD, replay window, exchange messages and
   state machine, with §11's tests and fuzz targets on the validator and the
   control parser.
3. **`LinkSec` in `CentralRouter`**: capacity-profile entries (below), the
   entropy source, `receive_frame` and `protect_for` in driver-core and their
   call sites in all three shells, `record_linksec_drop` on `RouterOps`,
   alarms, metrics (`add-metric`).
4. **`psk` keying end to end** in `wayfinder-test` and the sim — the first
   integration target, since it needs no CA.
5. **`membership` keying**: `W` from `OgmAuth`, certificates in the exchange,
   feeding verified certs into `NeighborKeys`, rekey on revocation.
6. **Provisioning**: tap `security:` config and validation, the RPCs,
   `LoadCredential`, `wayfinderctl link security|key`, a TUI/web column,
   `DEFAULT_MTU`, the secured-interface frame cap (§4.2).
7. **`confirm_peer` and `UdpMulti`** (§5.6).
8. **Integration**: keyed topologies (a revoked node is shut out; a mismatched
   PSK partitions; rollout `check` → `strict`; a rebooted receiver accepts no
   replay; a cross-segment relay is `NoSA`); `wayfinder-shark`.

**Capacity profiles.** `define_profile!` is positional with no defaults
(`libs/interfaces/src/lib.rs:69`), so new `LinkSec` capacities touch every
profile — default, host, nRF, ESP32, F411, WL55, test and bench — and add const
generics to `CentralRouter` (`libs/wayfinder/src/lib.rs:547`). Sizes: an SA
entry is ~64 B (key 32, key id, counter, bitmap, `src`, port, interface,
flags), a quota of two per neighbor (§4.5); an in-flight exchange ~48 B. At the WL55's 16
originators that is ~2 KiB plus a 512 B rx scratch, which fits the RAM design
28 §4 projects.

## 11. Test list (red first)

`wayfinder-linksec` — data plane:

- protect → validate round trip;
- flipping any byte of `dst`, `src`, TCI, PN, ciphertext or ICV → `NotValid`;
- the same frame with `src` rewritten → `NotValid`;
- exact replay → `Late`; reordering within the window accepted once each;
  below the window → `Late`;
- a forged frame with a huge counter does not move the window or allocate an
  entry;
- a new entry's window starts at the exchange's counter floor;
- two ports from one `src` interleave without `Late`;
- unknown `(src, port, key id)` → `NoSA`; disallowed version or `port` ≥ 8 →
  `BadTag`; version 1 on a link not configured for it → `BadTag`;
- `encrypt: true` receiver and an `E = 0` frame → `Downgrade`;
- integrity-only leaves the payload readable, rejects tampering with payload
  or `inner_proto`;
- our own frame replayed back → `SelfEcho`, no alarm, transmit continues;
- a frame verifying under our own `src` at a counter we never issued → `Clone`
  alarm, transmit continues;
- `check` passes untagged frames, stops passing them from a `src` once it has
  validated, and still drops invalid protected ones; `strict` drops untagged;
- empty payload; payload at the scratch size limit; one byte over → error, not
  truncation;
- the PSK fingerprint is domain-separated (differs from an unlabelled BLAKE2s
  of `K`).

`wayfinder-linksec` — exchange:

- `KeyReq` → `KeyResp` installs the sender's key with its counter floor;
- a `KeyResp` replayed into a new request → does not open;
- a `KeyResp` under the wrong `W` (another pair, another PSK) → does not open;
- a `KeyResp` with a revoked or wrong-mesh certificate → refused before any
  X25519;
- `want` completes the reverse direction in the third message, under B's own
  fresh `resp_nonce`;
- B answering the same `want` twice sends identical cached bytes, never a
  second wrap;
- a response whose certificate's MAC is not the frame's `src` → refused, in
  both directions;
- of two responses to one `(src, port)`, only the newest request's installs an
  SA, and a response never lowers a window;
- revocation drops SAs by installing-certificate fingerprint;
- a request for a superseded key id is answered with the current one, and the
  requester does not pull for the stale id again;
- `NeedCert` → retry with the certificate → success;
- the wrap label differs from `frame_tag`'s (property test: the same pairwise
  key gives unrelated outputs);
- a `KeyReq` flood from forged requesters creates no responder state and is
  limited per requester fingerprint and per interface;
- a single forged `NoSA` frame triggers no `KeyReq`;
- installing a newer key for a `(src, port)` retires the older SA.

`LinkSec` and driver-core:

- the tick driver validates (a protected frame pushed through `push_rx`/`tick`
  reaches the router only after `receive_frame`);
- `protect_for` runs once per target interface, with that interface's port and
  key;
- the tokio shell protects all targets under the plan guard and sends after
  releasing it;
- a merged multicast that fits in plaintext but not with the overhead falls
  back to directed copies;
- a key accepted on interface 0 does not validate the same frame injected on
  interface 1;
- across a scripted reboot of the sender, no `(SK, nonce)` pair is emitted
  twice (the entropy source is seeded per boot);
- after a scripted reboot of the receiver, a recorded frame stream is never
  delivered again;
- a neighbor's revocation drops its SAs, mints a new sender key, and refuses
  its `KeyReq`;
- a full SA table refuses the new key and alarms; it does not evict a live one;
- a drop increments a per-interface counter and creates no per-`src` state;
  it does not latch `LinkErrors`;
- `confirm_peer` is called only after a verified proof, with that datagram's
  address;
- no entropy source, or no trust anchor under `membership` → `security`
  refused at startup.

## 12. Key file map

- `libs/wayfinder-driver-core/src/lib.rs` — `handle_link_result` (~L1202),
  which calls the new `receive_frame`; `required_proof` (~L256);
  `DispatchPlan`/`plan_dispatch` (~L1380, ~L1424); `merged_frame_fits`
  (~L663) and `flush_mcast_groups` (~L698), which must count the overhead.
- Each shell's per-target send loop, for `protect_for`:
  `libs/wayfinder-driver/src/driver.rs` (~L2462; the lock is dropped at
  ~L2420), `libs/wayfinder-embedded-driver/src/lib.rs` (~L1103),
  `libs/wayfinder-tick-driver/src/lib.rs` (~L551).
- `libs/wayfinder-tick-driver/src/lib.rs` — the rx loop that calls
  `handle_mesh_frame` directly (~L364) and must call `receive_frame` instead.
- `libs/wayfinder-embedded-driver/src/lib.rs` — `with_capacities` (~L495):
  the rx scratch field and the entropy source.
- `libs/wayfinder/src/lib.rs` — the `LinkSec` field and its const generics on
  `CentralRouter` (~L547); the pre-demux link-quality recording (~L1482);
  the `0x88B5` demux (~L2056) beside which `0x88B6` goes.
- `libs/wayfinder/src/router_ops.rs` — `record_linksec_drop` beside
  `record_tx` (~L308).
- `libs/interfaces/src/lib.rs` — `define_profile!` (~L69).
- `libs/wayfinder/src/auth/` — `ogm.rs` (~L329, where `pairwise_key` is
  computed), `mod.rs` (`NeighborKeys` ~L439, `MAX_NEIGHBOR_KEYS` ~L182),
  `pairwise.rs` (eviction ~L603, receive-counter anchoring ~L375),
  `distribution.rs` (the `CertReq` shape the exchange follows).
- `libs/wayfinder-auth/src/key.rs` (~L121) and
  `libs/wayfinder-server/src/authority.rs` (~L861) — #103.
- `libs/wayfinder/src/link.rs` — `LinkT::confirm_peer` (default no-op).
- `libs/wayfinder-driver/src/net.rs` — `UdpMulti` learning (~L244), eviction
  (~L65), multicast loopback (~L455).
- `libs/wayfinder-nrf/src/identity.rs` (~L154),
  `bins/wayfinder-wl55jc/src/identity.rs`, `bins/wayfinder-esp32` — hand the
  RNG on to the driver instead of consuming it.
- `libs/blue/src/frame.rs` (~L103, tests ~L508), `libs/ieee802154/src/lib.rs`
  (~L151), `libs/lora-link` — fragment-count gate.
- `libs/wayfinder/src/config.rs` — `LinkConfig.security`, `Rylr998` (~L188),
  `DEFAULT_MTU`/`TAP_ENCAP_OVERHEAD` (~L449, ~L485).
- `libs/wayfinder-protos/src/rpc.rs` — `rpc_table!` entries.
- `nix/modules/wayfinder.nix` — `LoadCredential`.
