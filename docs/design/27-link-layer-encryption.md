# 27 — Link-layer encryption (MACsec-shaped, per link)

**Status:** Proposed (revision 2) — revised after a three-way review (crypto,
embedded feasibility, architecture). Phase 1 is buildable from this doc once the
§10 gate passes; Phase 2 (`keying: exchanged`) needs its own design doc, and
§8 records what it must satisfy.

**Scope:** a new `no_std` crate `libs/wayfinder-linksec` (the sans-I/O SecY:
framing, key schedule, replay state); a `LinkSec` table owned by
`CentralRouter`; two driver-core steps (`linksec_validate` on ingress,
`linksec_protect` on egress); a dedicated epoch store per target; one optional
field on `LinkConfig`; one management RPC set; one optional `LinkT` method
(`confirm_peer`, §5.6). **Not touched:** the BATMAN engine; `OgmAuth`'s wire
formats (OGM signatures, directed tags, fan-out signatures keep working
unchanged on top); any carrier except `UdpMulti`'s address learning.

**Revision 2 changes, briefly:** the SecY moved from a `LinkT` decorator into
router-owned state driven from driver-core (§4.1); the key schedule now binds
AN, port and epoch (§4.3); the epoch store is reserve-before-use with a crash-
durability requirement, and nodes without one refuse `security` (§4.4); replay
state is node-wide per `(key, src, port)` (§4.5); clone detection added (§5.3);
the overhead problem on BLE and 802.15.4 is now a gate, not a footnote (§4.2,
§10); factual errors in the MACsec research corrected.

---

## 1. Motivation

`wayfinder-auth` says: *"Payloads are never encrypted — wayfinder provides
authenticity and segregation only; confidentiality is left to L3."* That leaves
three gaps:

1. **Anyone in radio range reads everything.** LoRa and 802.15.4 are broadcast
   media with public modulations. Every bridged Ethernet frame — DHCP, ARP,
   mDNS, any application without its own TLS — is readable by a passive
   receiver.
2. **`Bcast` frames carry no authentication** (the documented scope limit in
   `wayfinder::auth`; `required_proof` exempts them). A link key gives every
   hop an outsider-integrity check on them.
3. **Mesh state leaks.** OGMs are signed but cleartext: a listener learns
   originators, sequence numbers and TQs. With link encryption that content is
   hidden — though adjacency still leaks through outer `src`/`dst`, frame
   length and timing (§6).

The ask: a firmware author or a `wayfinder-tap` configurator turns this on
**per link**, without the carrier knowing, with crypto in the family we
already ship.

## 2. Research: MACsec, and what maps

IEEE 802.1AE (MACsec) with its key agreement MKA (802.1X-2010 §9) is the
closest prior art: hop-by-hop L2 protection invisible to the layers above.

| MACsec concept | What it is | Wayfinder mapping |
|---|---|---|
| **SecY** | Data-plane shim: protects on tx, validates on rx. Knows nothing of how keys were agreed. | `wayfinder-linksec`'s pure core, state owned by the router (§4.1). |
| **KaY** | Control plane: runs MKA, elects a key server, installs SAs into the SecY through a narrow management interface. | Phase 1: none (static key). Phase 2: a KaY next to `OgmAuth`, installing into the router's `LinkSec` table. |
| **Controlled / uncontrolled port** | Controlled = protected only; uncontrolled = cleartext, carrying only EAPOL/MKA. | `strict` + an explicit, one-hop-only exemption list (Phase 2, §8). |
| **SecTAG** | 8–16 B: EtherType `0x88E5`, TCI/AN, short length, 32-bit PN, optional 8 B SCI (MAC ‖ 16-bit port id). | §4.2. Outer `src` replaces the SCI's MAC half; a 3-bit `port` replaces its port id. |
| **ICV** | 16 B GCM tag. | 16 B Poly1305 tag (8 B option on small-MTU links, §4.2). |
| **PN** | Strictly increasing per SA; it is the nonce. 32-bit in base MACsec; 64-bit in **XPN** (802.1AEbw), where the IV is `(SSCI ‖ PN) XOR salt` with a 32-bit SSCI per SC and a 96-bit salt from the KaY. At 10 Gb/s with minimum frames 2³² PNs last ~290 s, at 100 Gb/s ~29 s — hence XPN. | 64-bit `epoch ‖ counter`. Per-sender key derivation (§4.3) takes the role of XPN's SSCI + salt. |
| **AN** | 2 bits selecting one of four SAs for hitless rekey. | Kept (§4.7). |
| **CAK / CKN / SAK** | Long-term key, its name, and the short-lived key on frames. MKA distributes **one SAK per CA**, shared by every SC; each SC is told apart only by the SSCI/SCI in the IV. | Phase 1: the static link key plays CAK; per-sender keys are *derived*. Phase 2 departs from MKA deliberately: per-sender random keys, no key server (§8). |
| **`validateFrames`** Strict / Check / Disabled | Under Check, invalid *integrity-only* frames are delivered and counted. | `strict` / `check`, but **deviates**: `check` still drops invalid protected frames and only passes *untagged* ones (§4.8). |
| **Confidentiality offset 0/30/50, `E`/`C` bits** | Clear prefix, or integrity-only. | Integrity-only kept (§4.9); offsets dropped. |
| **MKA liveness** | Member Identifier + Message Number; live/potential peer lists; 2 s hello, 6 s lifetime. | Phase 2 (§8). |

Why not MACsec itself:

- **One CA per LAN with a cheap, reliable control plane** (MKPDUs every 2 s).
  A duty-cycle-limited LoRa segment cannot afford it, and a partitioning radio
  splits a key-server election into two incompatible SAKs.
- **Ethernet framing, and the Linux `macsec` netdev only.** It covers none of
  the radio links or boards. Kernel MACsec can still be stacked under a
  `RawL2` link by an operator who wants it.
- **AES-GCM only.** The STM32F411 has no AES hardware and software AES needs
  care to be constant-time. (The nRF52840's ECB peripheral *is* a general
  AES-128 block engine — 802.15.4/Thread stacks build CCM\* on it — so a
  future AES-CCM suite is reasonable there; §2.1.)

Other prior art: **802.15.4 MAC security** (AES-CCM\*; the source address and
frame counter go *in the nonce* under one group key; key-id modes ≈ our
AN/port — §9 compares); **LoRaWAN** (`FCnt` reuse after reset is its classic
bug — §4.4's trap); **BLE** (LL encryption is connection-only, but BLE 5.4
**Encrypted Advertising Data** does exist — medium-specific and not available
on the nRF52840's SoftDevice in use, so not a general answer); **WireGuard**.

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

The SecTAG version field leaves room for an AES-CCM/GCM suite where hardware
exists (nRF ECB, ESP32 AES, nRF54).

## 3. Goals / non-goals

**Goals**

- Per-link, opt-in confidentiality and integrity against anyone without the
  link key, on every carrier, in all three driver shells **from one
  implementation** (driver-core).
- Broadcast stays one encryption, one transmission.
- No `(key, nonce)` reuse **by construction** — across reboots, crashes, PN
  exhaustion, key reinstalls, and two interfaces sharing a key — not by
  relying on config validation.
- Replay protection that survives the sender rebooting.
- Metrics per interface and per source, in `CentralRouter`.
- Keys provisioned from a secret file on a host, or over the management API to
  a board — never a file written onto a node.

**Non-goals**

- **End-to-end** encryption. Hop-by-hop, as MACsec: relays see plaintext.
- **Insider protection.** Any holder of a link key can read and forge on that
  link, including denial of service (§6). Member-to-member authenticity stays
  with `OgmAuth`, unchanged.
- **Traffic-analysis resistance.** No padding in v1.
- **Forward secrecy** in Phase 1.
- Automatic key agreement in Phase 1.

## 4. Design

### 4.1 Layering: router-owned state, driver-core steps

```
 carrier recv ─► driver-core::handle_link_result
                   └─ linksec_validate(router.linksec_mut(), iface, frame, rx_scratch)
                        ├─ drop → router.record_linksec_drop(iface, src, reason)
                        └─ plaintext LinkFrame → router.handle_frame_with_metrics (unchanged)

 router plans ─► driver-core::plan_dispatch (unchanged) ─► for each egress iface:
                   linksec_protect(router.linksec_mut(), iface, frame, tx_scratch) ─► link.send
```

- **`wayfinder-linksec`** — synchronous, allocation-free, no `LinkT`, no
  async, no clock, no store. SecTAG codec, key schedule, AEAD calls, replay
  window. All of the unit tests, a fuzz target, the bench.
- **`LinkSec` in `CentralRouter`** — a const-generic table (capacity profile like
  `OgmAuth`'s): per-interface config (keying, validate, encrypt, port, tx AN,
  tx counter); the installed keys by AN; the node's epoch; the node-wide replay
  table keyed `(key fingerprint, src, port)`; the derived-key cache; counters.
  Owning it in the router is what gives the management API (`RouterAdapter`)
  and the Phase 2 KaY a path to install keys — which a `LinkT` decorator,
  buried in a driver's opaque `[L; N]`, never had. It also satisfies "state
  lives in `CentralRouter`".
- **driver-core** — two steps, one behavior for all three loops: the tokio
  driver, the embedded driver, and the tick driver (which validates when `tick`
  drains its rx queue — `push_rx` stays a parse-only enqueue — and protects at
  staging).
- **Scratch buffers** — protect needs an output buffer and validate a
  plaintext buffer, since `Received.frame` is immutable. The shells already own
  scratch: one shared tx scratch per driver (sends are sequential) and one rx
  scratch per driver (validation finishes before the next `recv` is polled). On
  boards these come from `StaticCell`, not from inside a per-link value — links
  are moved by value into `Driver::with_capacities`, whose frame the stack
  budget already watches.
- **`SecureLink<L: LinkT>`** — dropped from Phase 1. Revision 1 used it; the
  review showed it had no key-install path, no `src`-bearing error channel, and
  `recv`-loop borrow problems (E0499). An out-of-tree consumer that wants a
  decorator can wrap `wayfinder-linksec` itself.

§9's "inside the router/driver-core" rejection from revision 1 is reversed:
driver-core is per-interface and protocol-agnostic, so the objection that it
couples confidentiality to BATMAN did not hold.

### 4.2 Wire format

```
dst(6) src(6) protocol=LINKSEC(2) │ TCI(1) PN(8) │ ciphertext(inner_proto(2) ‖ payload) │ ICV(16|8)
                                  └── SecTAG ───┘
```

- `LINKSEC` — a new EtherType-style constant beside `0x4305`, from the
  local-experimental range. Not `0x88E5`: this is not 802.1AE and must not
  confuse a real MACsec stack on a `RawL2` segment.
- `TCI` — `version:2 | AN:2 | E:1 | port:3`. Version 0 = ChaCha20-Poly1305 +
  BLAKE2s, 16-byte ICV; version 1 = same with an 8-byte ICV (§10). `E` = 1:
  encrypted, 0: integrity-only. `port` = the sender's interface index, so only
  the first eight interfaces of a node can enable `security`.
- `PN` — 64-bit big-endian, `epoch:32 ‖ counter:32`.
- **Inner protocol is encrypted**, as in MACsec.
- **AAD** = `dst ‖ src ‖ LINKSEC ‖ TCI ‖ PN`, all fixed-width. In
  integrity-only mode the AAD additionally covers `inner_proto ‖ payload`, the
  plaintext is empty, and `E` (in the TCI) is authenticated.

**Overhead is 25 B per frame (17 B at version 1), and that breaks things on
the small-MTU carriers:**

| Carrier | Per fragment | Effect of +25 B |
|---|---|---|
| BLE legacy (`libs/blue`) | 18 B, `MAX_REASSEMBLED_LEN` = 270 | a full-cert OGM (~250 B) becomes ~275 B and **cannot be sent at all**; a lazy-auth OGM goes from 6 to 7 fragments |
| 802.15.4 | 114 B | a lazy-auth OGM (~100 B) goes from **1 fragment to 2** — doubled airtime and loss exposure on the most frequent frame |
| LoRa (RYLR998) | 178 B | mostly survives; bridged frames of 154–178 B become 2 fragments |
| UDP / `Tap` | MTU | full-size frames exceed a 1500 B underlay unless `DEFAULT_MTU` subtracts it |

With the existing directed trailer, a directed LoRa frame carries 25 + 24 =
**49 B of security overhead**. §10 makes the fragment counts a gate.

### 4.3 Key schedule

Phase 1 configures one 32-byte **link key** `K` per AN (up to four). The key on
a frame is derived from everything that must make it unique:

```
K_tx = BLAKE2s-keyed(key = K[AN],
         "wf-linksec-v0" ‖ version ‖ AN ‖ port ‖ epoch ‖ src)
nonce(96) = 0x00000000 ‖ PN(64)
```

- **`src`, `port`, `AN`, `epoch` are all inputs.** Two interfaces sharing a
  key, the same key reinstalled in a different AN, or a key added at runtime by
  `SetLinkKey` to a second interface, all yield distinct keys whatever the
  config says. Nonce separation follows from the derivation, not from a
  validator.
- **`epoch` in the key** means a counter that was cloned *alone* (§5.3) does
  not collide with the original's traffic under a fresh epoch.
- Receivers derive `K_tx` on the first frame of each `(src, port, AN, epoch)`
  and cache it in a bounded table. Evicting a cache entry only costs one
  BLAKE2s; forged random `src`s can thrash the cache (CPU cost only, said here
  so nobody mistakes it for a bug).
- `K` is used **only** as a BLAKE2s key in this derivation and as input to the
  fingerprint (§4.11). It never keys an AEAD directly. (Revision 1 claimed this
  "matched `pairwise_key`'s keyed style" — it does not: `pairwise_key` and
  `frame_tag` hash with the key as a prefix in unkeyed BLAKE2s. Keyed mode here
  is a deliberate choice, not a match.)
- **Never trial-decrypt.** ChaCha20-Poly1305 is not key-committing; the design
  is safe because AN, `port` and `src` select exactly one key per frame.

### 4.4 The epoch: reserve before use

Repeating `(K_tx, nonce)` under ChaCha20-Poly1305 leaks plaintext XOR and
allows Poly1305 forgery. The PN's `epoch` half is a **persisted, monotonic,
node-wide boot counter**, and the store holds **the next epoch not yet used**:

1. At boot: read `next`. Write `next + 1` durably. **Read it back.** Only then
   adopt `epoch = next` and enable transmit on secured links.
2. On counter wrap: the same reserve step for `epoch + 1` before any frame
   uses it. If the write fails, stop transmitting on secured links
   (`error!` + alarm) — never reuse.
3. On any key install or AN change: also reserve a fresh epoch (§4.7). That
   makes "remove a key and reinstall it" safe for replay state.

Per target:

- **Host (`wayfinder-tap`)** — a dedicated epoch file under
  `runtime_state_path`, written with temp-file + `fsync` + `rename` **+ fsync of
  the parent directory**. `FileStore` deliberately skips the directory fsync
  (`libs/wayfinder-storage/src/file.rs:20`) and is therefore **not** good
  enough: a power cut after transmitting under `e` but before the rename is
  durable boots back to `e`. Either add a `DurableStore` variant with a
  directory fsync, or a small purpose-built store.
- **Boards** — a **dedicated append-only epoch page**, not the identity record:
  program one fresh word per boot (NOR flips 1→0 without erasing), erase only
  when the page is full (~1024 boots per erase on a 4 KiB page). The A/B
  `FlashStore` would erase a page per boot; at ~10 k erase cycles a 2-second
  crash loop (the open nRF HardFault is a live example) wears it out in about
  11 hours. Keeping it out of the identity record also stops a per-boot
  rewrite of the identity seed.
- **No store** — `security` is **refused** at startup. A random epoch is below
  the receivers' high-water mark about half the time, which silences the node
  as `Late` until every receiver forgets it, and collides with probability 2⁻³²
  per pair of boots. Neither is acceptable. The tick-driver and the sim inject
  an explicit epoch source.
- **The STM32 LoRa relay — the STM32WL55JC (design 25, PR #79), not the
  F411** — cannot enable `security` today, and is the board that most needs it.
  Two of its prerequisites have landed; the two left are a **separate
  workstream that should land first**:
  1. *Flash headroom is the binding constraint.* 256 KiB of flash and 64 KiB of
     RAM; the management port is built (branch `bjc/wl55jc-mgmt-port`) but is
     42.1 KiB over flash against today's relay (design 28 §2), and design 28 is
     where closing that gap is decided. Link encryption adds the AEAD and
     `LinkSec` on top, so §10's spike must measure on `thumbv7em-none-eabi` (no
     FPU) against this image, not the nRF's.
  2. *A durable store* — **done** (PR #94): an A/B `FlashStore` on two 2 KiB
     pages that `memory.x` carves from the top of `FLASH`. The epoch still needs
     its own append-only pages beside it (~512 boots per 2 KiB page erase; use
     more than one page), which `memory.x` must carve out as well.
  3. *An identity* — **done** (PR #94): a seed minted once from the hardware
     TRNG and kept in that store (`bins/wayfinder-wl55jc/src/identity.rs`), so
     §4.10 is satisfied. Its fallback, an address derived from the factory UID
     with no seed behind it, is not, so `security` must be refused on it.
  4. *The management port*, so `SetLinkKey` has something to reach — the same
     port design 25 §4.9 needs for enrollment, and blocked on item 1.

  The WL55 also has a **hardware AES-256 engine** (and a PKA). If the
  ChaCha20-Poly1305 code does not fit, an AES-CCM suite (TCI version 2) on
  that engine is the fallback — measure both in the spike. The F411 stays the
  external-module LoRa proof and is not a `security` target.

The epoch blob **must never be restored from a backup or snapshotted** (VM
images, Docker `state` volumes). The doc for `runtime_state_path` and the
NixOS module both say so; clone detection (§5.3) is the backstop.

PN wrap is unreachable on radio links and takes ~12 h at 100 k frames/s on
host UDP, so step 2 is a host concern in practice. On boards the epoch is
reserved once at boot and handed to `LinkSec` as a value, so no store borrow
has to live inside the router.

### 4.5 Replay state

- **Keyed `(key fingerprint, src, port)`, node-wide** — not per receiving
  interface and not per AN. Node-wide closes the cross-interface replay (a
  frame `A` sent on `lora0` injected on `lora1`, which validates there under the
  same key and pushes `lora1`'s high-water to `A`'s `lora0` counter). Per-port
  stops two of `A`'s interfaces, each with its own counter, from marking each
  other `Late`. Per-fingerprint rather than per-AN means reinstalling a key into
  a different slot does not hand an attacker fresh state.
- Each entry: high-water 64-bit PN plus a sliding bitmap (default 64).
- **Allocated and updated only after AEAD verification.** Otherwise a forged
  PN advances the window and black-holes the real sender, and a flood of fake
  `src`s evicts real entries.
- **Evicting an entry re-opens replay for that sender** until its next epoch.
  Capacity is sized to the neighbor table, and occupancy is a metric.
- A **receiver** that reboots starts empty and accepts one replay of each
  sender's recorded traffic. Inner layers (BATMAN seqnos, OGM signatures,
  directed-tag counters) reject most of what that delivers. Phase 2's liveness
  closes it; Phase 1 documents it.

### 4.6 Validate pipeline

In order, each a distinct `SecDrop` reason recorded with `(iface, src)`:

1. `protocol != LINKSEC` → `strict`: drop (`Untagged`). `check`: pass, counted.
2. Unknown `version`, length below SecTAG + ICV, or `port` ≥ 8 → `BadTag`.
3. No key in that AN on this interface → `NoSA`.
4. `encrypt: true` and `E = 0` → `Downgrade`.
5. `src` is this node's own MAC and the frame verifies → `Clone` (§5.3).
6. PN at or below the window floor, or already seen → `Late`. Checked before
   decryption, read-only.
7. AEAD open fails → `NotValid`.
8. Update replay state; yield `LinkFrame { dst, src, inner_proto, payload }`
   from rx scratch.

Drops are `trace!` (remote input on a hot path). They never latch the
interface's `LinkErrors` alarm.

### 4.7 Key rotation via AN

Install the new key into a free AN on every node (rx accepts all installed
ANs), switch each node's tx AN, remove the old slot. Rx works throughout. Each
install or tx-AN switch reserves a fresh epoch (§4.4).

### 4.8 Rollout policy (`validate`)

- `strict` — default. Only valid protected frames reach the router.
- `check` — protected frames are still validated **and dropped if invalid**;
  only untagged BATMAN frames pass, counted. That deviates from 802.1AE's Check
  (which delivers invalid integrity-only frames). It is for a rolling upgrade;
  the counter at zero is the signal to flip to `strict`.

A `check` link admits outsiders by definition (§6, §5.5).

### 4.9 Integrity-only mode (`encrypt: false`)

Same SecTAG and ICV, payload in the clear, authenticated as described in §4.2.
Amateur-radio rules (e.g. FCC Part 97) prohibit encryption that obscures meaning
but allow authentication, and much LoRa mesh hardware sits on ham bands. Also
useful for debugging with `wayfinder-shark`. A link configured `encrypt: true`
rejects `E = 0` frames (§4.6 step 4), so integrity-only cannot be forced on it.

### 4.10 Configuration

**`wayfinder-tap` YAML** — sibling of `features`, orthogonal to the transport:

```yaml
links:
  - name: lora0
    type: Rylr998
    # …transport fields…
    security:
      keying: static            # static | exchanged (Phase 2)
      key_file: /run/credentials/wayfinder.service/lora0.key  # exactly 32 bytes, hex or base64
      validate: strict          # strict | check
      encrypt: true             # false = integrity-only
      replay_window: 64
  - name: vpn
    type: UdpMulti               # already inside WireGuard — leave unsecured
```

- `key_file`, never an inline key: `services.wayfinder.config` lands in the
  world-readable Nix store. `nix/modules/wayfinder.nix` gains `LoadCredential=`
  — not a capability.
- Key material is **exactly 32 bytes**. No passphrase derivation: an 8-byte
  fingerprint of a low-entropy key is an offline guessing oracle.
- **Validation:**
  - `security` on a node whose MAC is not identity-derived is refused (a
    configured or `mac_state_path` MAC is copy-pasteable, §5.3).
  - More than eight secured interfaces is refused.
  - One link never mixes `static` and `exchanged` keys: a revoked node holding
    the static key would still get in.
  - A `warn!` at startup when `strict` links coexist with `check` or unsecured
    links on the same node (§5.5).
- `DEFAULT_MTU` (`config.rs:447`, `TAP_ENCAP_OVERHEAD`) subtracts the SecTAG +
  ICV when the egress link is secured; the test pinning the literal changes.
- **Boards:** the nRF's USB-NCM management link is never offered `security`
  (pass-through), for CPU reasons (§2.1) and because it is not a mesh medium.

**Runtime and boards** — `SetLinkKey { interface, an, key, make_tx }`,
`ClearLinkKey { interface, an }`, `SetLinkSecurity { interface, validate,
encrypt }`, declared in `rpc.rs`'s `rpc_table!` at the admin tier and audited,
reaching `LinkSec` through `RouterAdapter`, persisted through `Persisted`
(host: `runtime_state_path`; board: `DurableStore`). **Keys are write-only.**
This is how a board gets a key at all. The boards' serial management port is
unauthenticated by decision (#57); setting a key there assumes physical
access, the same trust that port already has.

### 4.11 Keying is a per-link choice

Both keying modes feed the same `LinkSec` table and wire format; only the
source of `K_tx` differs, so the mode is chosen per link and a node may run
both:

| `keying` | Sender key | Control-plane airtime | Fits |
|---|---|---|---|
| `static` | derived from the link key (§4.3) | none | LoRa, 802.15.4, duty-cycle-limited or tiny-MTU links; small fixed deployments |
| `exchanged` | random per sender, delivered to each neighbor (Phase 2) | announce + delivery + ack per neighbor per rekey | BLE (measure first), Wi-Fi, high-rate MANET radios (Silvus-class), wired/UDP |

`exchanged` makes link admission follow certificates and revocation, with no
shared secret and with forward secrecy. Its airtime is too expensive for LoRa,
which is why `static` is the default rather than a stopgap. §8 records a third
option that may suit LoRa better than either.

Radios that already encrypt their own link make this layer redundant for
confidentiality; it is still worth enabling there to tie admission to mesh
membership.

### 4.12 Observability

Through `add-metric`, all in `CentralRouter`:

- per interface: protected-tx rate, validated-rx rate, `check`-passed
  cleartext rate, drop rate by `SecDrop` reason;
- node: current epoch, epoch reservations (boot and wrap), store-write
  failures, replay-table and key-cache occupancy;
- `GetLinkSecurity`: per interface keying, validate, encrypt, suite, port, tx
  AN, installed ANs with **fingerprints only** —
  `BLAKE2s("wf-linksec-fpr" ‖ K)[..8]`, domain-separated — and a node-level
  "weakest admitting link" (§5.5).

**Alarms** — raised from `LinkSec` itself (detectors live beside their
state):

- `LinkKeyMismatch(iface)`: `NotValid` from a `src` from which nothing has
  validated over a window — a neighbor on the wrong key, e.g. a botched
  rotation;
- `LinkSecClone`: a frame verified under this node's own `src` (§5.3);
- `LinkSecEpochJump(src)`: a sender's epoch jumped by more than a few (insider
  pinning, §6);
- `LinkSecStoreFailure`: transmit stopped because an epoch could not be
  reserved.

The board coalesces each, so a hostile flood is one row.

## 5. Correctness argument and edge cases

### 5.1 Nonce uniqueness

`(K_tx, nonce)` is unique because:

- distinct `(K[AN], port, epoch, src)` give distinct `K_tx`;
- for one such tuple, `counter` strictly increases and `LinkSec` refuses to
  send instead of wrapping;
- `epoch` is reserved durably — with a directory fsync on hosts and a read-back
  on both — *before* it is used, so no crash sequence brings back a used value;
- a key install bumps the epoch.

The remaining assumptions are operational: the epoch store is never rolled
back, and `src` is unique. §5.3 detects violations of either.

### 5.2 Forgeries cannot poison state

Replay entries are created and moved only after AEAD success (§4.5).

### 5.3 Duplicate senders

Cloned images, restored backups, VM snapshots and copied Docker volumes give
two nodes the same derived MAC and possibly the same epoch, hence the same
keystream. Defences:

- `security` requires an identity-derived MAC (§4.10);
- **clone detection**: a node that verifies a frame carrying its own `src`
  stops transmitting on secured links and raises `LinkSecClone`. One
  comparison per frame;
- the "never restore the epoch" rule is documented where operators will see it.

### 5.4 Fail-closed routing

A neighbor on the wrong key is never heard, so it never earns TQ: no
half-working routes. `check` is the only intentional exception. Dropped frames
never reach `LinkMetrics`, so the link-quality EWMA ignores them.

### 5.5 Trust is hop-by-hop

A frame admitted on a `check` link, an unsecured link (the YAML's `vpn`), or a
`static` link is re-encrypted onto every other link without provenance. "Every
broadcast is authenticated" holds only if every link the frame crossed was
`strict`. Hence the startup warning and the "weakest admitting link" gauge.

### 5.6 `UdpMulti` learns before validation

`net.rs:244` calls `peers.learn(frame.src, …)` as soon as the frame arrives;
the at-capacity eviction at `:66` then lets a flood of forged `src`s evict real
peers. Encryption invites the assumption that this is closed, so the fix is in
scope: an optional `LinkT::confirm_peer(&mut self, src: Mac)` (default no-op).
driver-core calls it after `linksec_validate` accepts a frame, or after
`OgmAuth` accepts one on an unsecured link. `UdpMulti` moves its learning
there.

### 5.7 Fan-out and `send_all`

Unchanged and unaffected. Because `dst` is in the AAD, one ciphertext serves
one `dst`. The design-17 collapse already emits one `send` to `Mac::BROADCAST`
(`wayfinder-driver-core/src/lib.rs` ~681–760), which is one protect. Nothing
in production calls `send_all`, and its default — one `send` per destination —
is correct under protection. (Revision 1's claim that `send_all` encrypts once
was wrong.)

### 5.8 Header compression composes below

Designs 00/02 compress the outer `dst`/`src`/protocol below the link boundary
without inspecting BATMAN. They therefore compose under the SecY unchanged, and
because `dst` is in the AAD, a frame decompressed against the wrong binding
fails verification. (Revision 1 said the opposite; it was wrong.)

### 5.9 Fragments

Fragmentation stays below the SecY: one ICV per frame. Fragment injection can
spoil one reassembly; the ICV then fails. That is a DoS on one frame and is
already true of unauthenticated fragmentation.

### 5.10 Stack budget

Mark the AEAD calls `#[inline(never)]` (the reason is on `verify_signature`)
and run `just stack-budget`. The scratch buffers live in statics (§4.1).

## 6. Security considerations

| Threat | Phase 1 (`static`) | Phase 2 (`exchanged`) |
|---|---|---|
| Passive eavesdropper reads payloads, inner types, OGM contents | ✅ prevented | ✅ |
| Adjacency (who talks to whom), sizes, timing | ❌ visible | ❌ |
| Outsider injection/modification | ✅ on `strict` links; ❌ on `check` links | ✅ on `strict` |
| Replay, receiver up | ✅ including sender reboots and across interfaces | ✅ |
| Replay into a freshly rebooted receiver | ❌ once per sender | ✅ liveness |
| Revoked member keeps reading | ❌ until the operator rotates | ✅ rekey on revocation |
| Key compromise reveals history | ❌ | ✅ with the ephemeral term (§8) |
| Insider forges another member's frames | ❌ by design; `OgmAuth` still catches OGMs and directed frames | ❌ same |
| **Insider pins a victim's high-water** (one frame, `src` = victim, PN = 2⁶⁴−1) and silences the victim's link-layer traffic until receivers reboot | ❌ alarmed (`LinkSecEpochJump`), not prevented | ❌ same: every neighbor holds `K_victim` |
| Cloned or restored node reuses nonces | detected (§5.3), not prevented | random keys per boot prevent it |

Update `wayfinder-auth`'s crate docs: "per-hop confidentiality is optional
(design 27); end-to-end is left to L3".

### 6.1 Pre-existing finding: X25519 contributory check

`Keypair::pairwise_key` never checks `was_contributory()`. A low-order
`x_pubkey` gives an all-zero shared secret that anyone can compute. That is
safe today only as long as the CA validates every certificate's `x_pubkey`.
It is independent of this design and Phase 2 depends on it: reject
non-contributory results in `pairwise_key`. File it as its own issue.

## 7. Migration and versioning

- **Old nodes** treat a `LINKSEC` frame as an unknown protocol. Confirm in a
  test that it is dropped at `trace!` without an alarm before rollout.
- **Rollout:** every node to `check` with the key installed; watch the
  cleartext-passed counter fall to zero; flip to `strict`.
- **Suites:** an unknown `version` is `BadTag`. A new suite is a new version
  value plus a config field; old nodes cannot talk to it, by design.
- **`wayfinder-shark`:** dissect the SecTAG, show ciphertext as opaque, and
  show integrity-only payloads.

## 8. Phase 2 requirements (`keying: exchanged`)

Non-normative sketch; the Phase 2 doc owns the design. It must satisfy:

- **Per-sender random keys, no key server.** On partitioning radios an MKA-style
  election splits.
- **Uncontrolled port**: exempt only the KaY EtherType and a **one-hop**
  `CertReq`/`CertReply` (today these are BATMAN `0x4305` and routed multi-hop).
  Each exemption is unauthenticated attack surface: list them explicitly.
- **Announce**: Ed25519-signed, carries a cert or fingerprint, a per-boot nonce,
  an ephemeral X25519 key, and a monotonic announce epoch. Rate-limited per
  `src` and globally; each `(src, boot nonce)` verified once and cached (an
  Ed25519 verify is tens of ms on an M4). `CertReq` rate-limited. An announce
  never resets a peer's replay state.
- **Key delivery**: wrap under a **per-exchange** key derived from the static
  DH, both nonces and the ephemerals (Noise-KK style, including the `es`
  terms to rule out key-compromise impersonation) — never a fixed KEK with an
  unspecified nonce. AAD binds direction (sender → receiver), both X25519
  public keys (not the 46-bit MACs), AN and generation. Derive from the raw DH
  output under its own label, not from `pairwise_key`'s output, which already
  keys `frame_tag`.
- **Batched** deliveries in one broadcast; **join** needs no rekey;
  **revocation** forces every former neighbor of the revoked node to rekey.
- Depends on §6.1's contributory check.

## 9. Alternatives considered

- **A `LinkT` decorator (`SecureLink<L>`).** Revision 1's design. Rejected: no
  path for a management RPC or a KaY to install keys; no `src` on the error
  channel for metrics; `recv`-loop borrow problems; the tick driver would need a
  separate integration.
- **Encrypt with the existing pairwise keys.** Broadcast would cost one
  transmission per neighbor. Pairwise keys wrap Phase 2 deliveries instead.
- **CA-distributed group key** (the strongest omission from revision 1). The
  CA mints a per-epoch link group key and delivers it, wrapped to each member's
  X25519 key, over the design-24 renewal path, which already reaches every
  member over the mesh. That gives certificate-bound admission and revocation
  **without per-neighbor exchange airtime** — plausibly the right `exchanged`
  for LoRa. Costs: depends on the CA being reachable to rotate, and a group key
  needs the sender inside the nonce (as in 802.15.4) rather than in a derived
  key. Evaluate in the Phase 2 doc alongside per-sender keys.
- **802.15.4-style nonce = source address ‖ frame counter under one group
  key**, with key-id modes. Equivalent uniqueness to §4.3 if the counter is
  reboot-safe, with fewer derivations. Rejected for Phase 1 because folding AN,
  port and epoch into a derived key makes uniqueness independent of config,
  which the review showed matters.
- **Linux kernel MACsec.** Ethernet and Linux only.
- **Noise/WireGuard sessions per neighbor; Noise broadcast patterns.**
  Per-neighbor sessions break broadcast. The one-way and broadcast Noise
  patterns are a reasonable base for the Phase 2 announce/delivery messages, not
  for frame protection.
- **MLS/TreeKEM group keying.** Needs totally ordered commits through a
  delivery service, which a partitioning mesh does not have. Rejected.
- **Native medium security** (802.15.4 CCM\*, BLE LL, BLE 5.4 EAD).
  Inconsistent and unavailable on several carriers.
- **AES-GCM/CCM as the default.** No hardware on the STM32F411 or the
  nRF52840's SoftDevice path; the WL55 and ESP32 do have engines. A future
  suite, and the WL55's fallback if flash is short (§4.4).
- **Random per-frame nonces (XChaCha20).** +16 B per frame and a TRNG draw per
  frame. A no-store fallback was considered and rejected: §4.4 refuses
  instead.
- **Unix-seconds epoch on hosts with no store.** Monotonic only while the clock
  is; a clock step backward reuses nonces. Rejected.

## 10. Phase 1 plan and gate

1. **Spike (the gate)**:
   - `chacha20poly1305` on `thumbv7em-none-eabihf`: flash cost and cycles/byte
     in `wayfinder-bench`.
   - **Fragment-count tests with security overhead**, extending
     `extended_format_collapses_realistic_ogm_fragment_counts` and its 802.15.4
     equivalent: full-cert and lazy-auth OGMs, a keep-alive, and a bridged
     frame, at version 0 (25 B) and version 1 (17 B).
   - **Decision rule:** if a lazy-auth OGM still crosses a fragment boundary on
     802.15.4 at version 1, or a full-cert OGM exceeds BLE's ceiling, then
     either raise `MAX_REASSEMBLED_LEN` or adopt a short PN (4 B on the wire,
     the epoch carried only on broadcasts) **before** building anything else.
     The 8-byte ICV is only allowed on links whose config says so.
2. **`wayfinder-linksec`** with its tests (§11) and a fuzz target on the
   validator.
3. **`LinkSec` in `CentralRouter`, the driver-core steps in all three shells,
   `record_linksec_drop` on `RouterOps`, alarms, metrics** (`add-metric`).
4. **Epoch stores**: host (with directory fsync), nRF, ESP32 and WL55
   append-only pages. What remains of the WL55 bring-up (§4.4: flash
   headroom and the management port, both decided by design 28; the store and
   identity landed in PR #94) is a prerequisite that proceeds in parallel with
   step 1; it blocks only the WL55's own use of `security`.
5. **Provisioning**: tap `security:` config and validation, the RPCs,
   `LoadCredential`, `wayfinderctl link key set|clear|show`, a TUI/web column,
   `DEFAULT_MTU`.
6. **`confirm_peer` and `UdpMulti`** (§5.6).
7. **Integration**: `wayfinder-test` keyed topologies (mismatched keys
   partition; AN rotation loses no frames; `check`→`strict` rollout; a
   simulated reboot never reuses a nonce); `wayfinder-shark`.

## 11. Test list (red first)

`wayfinder-linksec`:

- protect → validate round trip;
- flipping any byte of `dst`, `src`, TCI, PN, ciphertext or ICV → `NotValid`;
- the same frame with `src` rewritten → `NotValid`;
- exact replay → `Late`; reordering within the window accepted once each;
  below the window → `Late`;
- a forged frame with a huge PN does not move the window or allocate an entry;
- a higher epoch is accepted;
- two ports from one `src` under one key interleave without `Late`;
- the same key on two interfaces, two ANs, or reinstalled → different `K_tx`
  (property test over the derivation inputs);
- unknown AN → `NoSA`; unknown version or `port` ≥ 8 → `BadTag`;
- `encrypt: true` receiver and an `E = 0` frame → `Downgrade`;
- integrity-only leaves the payload readable, rejects tampering with payload or
  `inner_proto`;
- a frame verifying under our own `src` → `Clone`;
- `check` passes untagged frames and still drops invalid protected ones;
  `strict` drops untagged;
- empty payload; payload at the scratch size limit; one byte over → error, not
  truncation;
- fingerprint is domain-separated (differs from an unlabelled BLAKE2s of `K`).

`LinkSec` and driver-core:

- the epoch is reserved and read back before the first protect; a failed
  reservation refuses transmit;
- counter wrap reserves a new epoch; failure stops transmit;
- key install bumps the epoch;
- across a scripted reboot sequence (including a crash between reserving and
  persisting) no `(K_tx, nonce)` pair is emitted twice;
- cross-interface replay: a frame captured on interface 0 and injected on
  interface 1 → `Late`;
- a drop records `(iface, src, reason)` and does not latch `LinkErrors`;
- `confirm_peer` is called only after acceptance;
- no store → `security` refused at startup.

## 12. Key file map

- `libs/wayfinder-driver-core/src/lib.rs` — `handle_link_result` (~L1202) for
  validate; `DispatchPlan`/`plan_dispatch` (~L1380, ~L1424) and the shells'
  send loops for protect; the fan-out collapse
  (`flush_mcast_groups`, ~L698), which since PR #95 abandons a merge that
  would exceed the link's `FanOut::max_frame_len` — protect's overhead must
  count against that cap.
- `libs/wayfinder/src/lib.rs`, `router_ops.rs` — the `LinkSec` field, its
  capacity profile, `record_linksec_drop` beside `record_tx` (~L308).
- `libs/wayfinder/src/link.rs` — `LinkT::confirm_peer` (default no-op).
- `libs/wayfinder-driver/src/net.rs` — `UdpMulti` learning (~L244, eviction ~L66).
- `libs/wayfinder-tick-driver/src/lib.rs` — validate in `tick` (~L334, not
  `push_rx` at ~L308); protect at staging.
- `libs/wayfinder-embedded-driver/src/lib.rs` — static scratch; epoch handed
  in at construction (`Driver::new`, ~L446).
- `libs/wayfinder-storage/src/file.rs` (~L20) — the missing directory fsync.
- `libs/wayfinder-nrf/src/identity.rs`, `bins/wayfinder-esp32`,
  `bins/wayfinder-wl55jc/src/identity.rs` and `memory.x` — epoch pages beside
  the WL55's identity store (PR #94).
- `libs/blue/src/frame.rs` (~L103, tests ~L508) and
  `libs/ieee802154/src/lib.rs` (~L151) — fragment-count gate.
- `libs/wayfinder/src/config.rs` — `LinkConfig.security`, `Rylr998` (~L188),
  `DEFAULT_MTU`/`TAP_ENCAP_OVERHEAD` (~L449, ~L485).
- `libs/wayfinder-protos/src/rpc.rs` — `rpc_table!` entries.
- `libs/wayfinder-auth/src/key.rs` — §6.1's contributory check.
- `nix/modules/wayfinder.nix` — `LoadCredential`.
