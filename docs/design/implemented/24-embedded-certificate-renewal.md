# Design: how a board renews a certificate it cannot renew

**Status:** Implemented. §11 records what the implementing session decided,
where it deviated, and the one thing it deliberately did not build.

Finishes the embedded-auth work that GitLab #50 opened. Designs 20, 21 and 22
gave a board a clock posture, hardware tests and a durable credential, and #53
put it on an authenticated mesh. This is the one thing left: a board that has
enrolled cannot stay enrolled.

Owns the renewal half of GitLab #50's follow-on. Depends on nothing unlanded.

## 1. Scope

**In play:**

- `libs/batman` (`wire.rs`: two new `BatmanPacketType` values and their
  headers; `engine.rs`: two relay arms structurally identical to the
  cert-control ones — which the implementation then merged into one
  `handle_credential_control`).
- `libs/wayfinder` (`lib.rs`: the `DeliverLocal` arms; `auth/renewal.rs`:
  building and verifying a renewal request. Planned to sit beside
  `build_cert_request`/`verify_cert_request`; §4.3's note records why the two
  exchanges ended up in separate files instead).
- `libs/wayfinder-driver` (the CA side: handing a delivered request to the
  authority task and injecting the reply; `renew.rs` grows a second caller
  shape).
- `libs/wayfinder-embedded-driver` (the board side: a renewal timer on the
  existing due-poll, and persisting a provider it currently discards on
  purpose).
- `libs/wayfinder-server` (`authority.rs`: the re-issue path reached from the
  mesh rather than from `SubmitCsr`).

**Not touched:** the management-API wire format, `MembershipCert`'s layout, the
TLS transport, `decide_access`'s tiers, or the host node's existing
`SubmitCsr`-over-TLS renewal — which keeps working unchanged and stays the path
a host node uses.

## 2. Motivation

### 2.1 A board drops off the mesh every seven days

`nix/machines/wayfinder-ca/common.nix:283` sets `cert_ttl_secs` to 7 days, and
deliberately: a certificate's lifetime is the only revocation bound that reaches
a member which is offline when the revocation floods. A host node renews itself
against the provider recorded by the enrollment that certified it
(`libs/wayfinder-driver/src/renew.rs`). A board cannot, and the code says so
outright — `libs/wayfinder-embedded-driver/src/settings.rs:99` refuses to
persist a renewal provider at all, with a test named
`a_renewal_provider_is_not_persisted`, and `lib.rs:892` gives the reason:
renewal means opening a *client* connection to the authority, and a board has no
IP stack to open one with.

So `csr install --renew-from` against a board is silently useless, and every
embedded node on a real mesh needs a three-step operator ritual every week —
`csr request` over serial, `csr submit` at the CA (which parks for approval,
since `auto_approve = false`), `csr install` back over serial — per board.

That is not a rough edge. It is the difference between a board being a mesh
member and a board being a demo.

### 2.2 The thing a board *does* have is a route to the authority

The blocker was always stated as "no IP stack", which is true and beside the
point. A board that is due for renewal is by definition still holding a valid
certificate, which means it is a **routing member of the mesh** — and the
authority is a mesh node too. `nix/machines/wayfinder-ca` joins its own tunnel
and carries a `UdpMulti` mesh link precisely so that it routes as well as signs.

A board therefore already has the one thing renewal needs: a path to the
authority. What it lacks is a way to *speak* to it over that path, because every
management conversation in this project is TLS over TCP.

### 2.3 The exchange already exists, under another name

Lazy cert distribution needs a node to ask a *specific other node* for a
credential and get one back, over routed unicast, on a mesh where neither end
has a socket. That is `CertReq`/`CertReply` (`BatmanPacketType` 0x05/0x06),
relayed hop-by-hop by `next_hop` with a TTL and delivered locally at the
destination (`libs/batman/src/engine.rs:1916`).

The request body is the shape that matters. `verify_cert_request`
(`libs/wayfinder/src/auth.rs:2139`) takes `cert || signature`: it verifies the
requester's certificate against the trust anchor, checks revocation, and
requires proof of possession of the named key *before* spending a rate-limit
token. A renewal request is that same body, asked of a different node for a
different reason.

And the authority's renewal rule needs nothing more. Per `renew.rs`'s header,
re-issue is a **holder match** — same address, same identity key, while
`now_unix <= not_after` — which is exactly what a verified `cert || signature`
proves. There is no new credential format to design.

## 3. Goals and non-goals

**Goals**

1. A board holding a valid certificate obtains a fresh one unattended, with no
   operator action and no serial cable.
2. No weakening of the 7-day bound. The point is to make short lifetimes
   survivable on boards, *not* to argue for long ones.
3. The `no_std` core gains no dependency on the authority. A CA is a host
   concern; `libs/batman` and `CentralRouter` learn a packet type, not a policy.
4. Reuse `CertReq`'s relay shape rather than inventing a second routed
   request/reply idiom.

**Non-goals**

- **Enrollment over the mesh.** A board with no credential cannot route
  authenticated, so it cannot reach the authority this way. First enrollment
  stays an operator act over the serial port — which #57 just resolved is a
  trusted boundary. This design renews an existing membership and nothing else.
- **Renewal for a lapsed board.** One second past `not_after` a node is a
  stranger, not a renewing holder (`renew.rs`); the authority parks it for
  approval. That stays true here, and §5.2 argues it should.
- **Pushing certificates.** The authority still answers; it never initiates.
- **Replacing host renewal.** A host node has a socket and keeps using it.

## 4. Design

### 4.1 Two packet types, cut from `CertReq`'s pattern

```rust
RenewReq   = 0x0c,
RenewReply = 0x0d,
```

0x0a/0x0b are `EchoRequest`/`EchoReply`, so 0x0c is the next free value.

Headers mirror `BatmanCertReqPacket`/`BatmanCertReplyPacket` — a destination,
a TTL, and a requester/responder address — and the relay arms in `engine.rs`
are the same nine lines: deliver locally when `dst == self.self_ident`, drop at
`ttl <= 1`, otherwise decrement and forward to `next_hop`, accounting an
oversize relay drop through `note_relay_oversize_drop`. Nothing here is novel,
which is the argument for doing it this way.

**Why not a `Unicast` payload.** The same reason `Mcast` and `CertReq` are their
own types: credential-control traffic stays identifiable on the wire, separate
from data, so a dissector and an operator can both see it. It also keeps the
frame off the host TAP by construction — a `DeliverLocal` of this type
terminates in auth state, never in the local device.

### 4.2 The request body is the certificate the board already holds

`RenewReq` body: `current_cert || sig(nonce || cert)`, byte-identical in shape
to what `build_cert_request` produces and `verify_cert_request` consumes. A new
`build_renewal_request` / `verify_renewal_request` pair sits beside them in
`auth.rs` rather than overloading the existing two, because the *meaning* of a
verified body differs — one says "I am a member, give me your cert", the other
says "I am this member, give me a new one for me" — and a rate limiter that
cannot tell them apart is a rate limiter on the wrong thing.

The nonce is the board's replay defence and is drawn from the same source the
existing next-hop challenge uses; §5.3 covers what it must survive.

**No CSR is transmitted.** The authority re-issues from the identity it just
verified. Anything the board could put in a request beyond its own certificate
would be a field the authority must then decide whether to trust, and there is
nothing it needs.

### 4.3 The CA side, and the seam design 13 forces

This is the one genuinely new piece of plumbing, and it exists because
**design 13 moved the authority off the router loop**. The router cannot answer
a `RenewReq` the way it answers a `CertReq` — it does not own a `CertAuthority`
and must not learn to.

So the flow forks at `DeliverLocal`:

1. `CentralRouter` verifies the body (anchor, revocation, proof of possession)
   — everything decidable from `no_std` auth state — and on success surfaces the
   verified requester plus its certificate to the driver as a *decision-free
   fact*. It does not consult policy and does not mint anything.
2. `wayfinder-driver` forwards that to the authority task over the channel
   design 13 already established for management requests.
3. The authority applies the holder match and re-issues, or declines.
4. The driver asks the router to emit a `RenewReply` addressed back to the
   requester.

Step 4 is asynchronous, which `CertReply` is not — and that asymmetry is why
this cannot simply extend the cert-reply path. The parked-reply machinery
`CertReq` already has for "verified requester, no route yet" is the right
precedent for holding the request across the round trip, and §9 asks whether it
should be reused directly or copied.

**The router core stays clean.** It gains a packet type, two relay arms, a body
verifier, and an outbound fact. It gains no notion of an authority, which
preserves goal 3 and keeps `libs/batman` and `CentralRouter` linkable on a
board that will never be a CA.

> **Where this landed.** Review of the implementing MR found the seam drawn one
> layer too high: `CentralRouter` was verifying the body *and* building both
> frames, so every sentence above that says "the router" was describing code
> interleaved with the routing engine rather than code that belongs to auth.
>
> It now sits in `libs/wayfinder/src/auth/renewal.rs`. `OgmAuth` owns the
> verification, the pacing (`next_renewal_poll`), the one-slot
> `pending_renewal` hand-off, and both frames — headers included. The router
> lends it a `Paths` view (`self_ident` and the two next-hop questions, nothing
> that can change what the engine believes) and otherwise only delegates:
> `poll_renewal`, `next_renewal_after`, `send_renew_reply`,
> `take_renewal_request`, `take_renewed_cert` and the two counters are each one
> line, and the `RenewReq`/`RenewReply` `DeliverLocal` arms are one call apiece.
> The fork itself is unchanged: the `no_std` core still surfaces a decision-free
> fact and still cannot reach a `CertAuthority`.
>
> Read "`CentralRouter`" as "`OgmAuth`, through `CentralRouter`" throughout this
> section. The same correction applies to lazy cert distribution (design 01),
> whose §5 now carries the matching note.

### 4.4 The board side: a provider it stops discarding

`settings.rs` currently drops the renewal provider on purpose, and that comment
becomes wrong with this design. It is replaced by a provider whose target is a
**`Mac`, not a socket address** — the authority's mesh address, recorded by the
`SetAuth` that certified the board, exactly as the host records an IP. The
reasoning in `renew.rs`'s "where the provider comes from" carries over
unchanged: it comes from the enrollment that certified this node, never from
configuration, so a board moved between providers renews against the one it now
belongs to.

Pinning survives the change of address family. The host pins its provider by
public key (`RenewalProviderData::node_key`) and so does this: a `RenewReply` is
a certificate, and a certificate that does not verify against the held trust
anchor is discarded regardless of which MAC it arrived from. The MAC is a
routing hint, not a trust input.

The timer is the due-poll in `Driver::run_once_with_mgmt`, which already
computes a next-deadline across OGM, challenge and ping arms. Renewal joins it
at the same 15-minute cadence `renew.rs` uses, for the same reason: the question
is answered from state already in memory but asked from a path that runs per
frame.

**`run_once_with_mgmt`, not `run_once`** — this planned to join the plain loop
and deliberately does not, which is an operational property with no other
statement in this document. `run_once` is the arm a board takes when it has no
management port, and it holds no store. A renewal it could not make durable
would install a certificate, move `renewal_replies_accepted`, and be lost at the
next reset: a board that reads healthy and comes back stale, which is worse than
one that never renewed. So `poll_due_all` omits `poll_due_renewal` and every
shell that wants renewal calls it explicitly. **A board with no management port
does not renew over the mesh.**

### 4.5 What the board can and cannot prove about the time

This is where design 20's posture does real work, and it produces a result worth
stating plainly because it looks like a bug.

`due_renewal(now) = !expired(now) && now >= renew_from()`. A board holds
`Clocked::AtLeast(floor)` — a monotone lower bound. A floor **can** prove an
instant is past (`proves_past`) and **can never** prove one is still ahead
(`proves_before` is false for every `AtLeast`, asserted at
`libs/wayfinder-auth/src/clock.rs:530`).

So a board can prove it is *due* and cannot prove it is *not yet expired*.

The honest consequence: **a board attempts renewal whenever it can prove
`renew_from` is past, and lets the authority be the judge of expiry.** It does
not try to evaluate `due_renewal` locally, because half of that predicate is
unprovable to it. A board whose floor has drifted behind reality may therefore
send a request the authority refuses as lapsed — which costs one round trip and
produces an operator-visible signal (§7), rather than a wrong local decision
made silently. That is design 20 §5.1's "enforcement is distributed" applied to
one more case.

## 5. Correctness and edge cases

### 5.1 Termination and loops

`RenewReq`/`RenewReply` carry a TTL decremented at every relay and are dropped
at `ttl <= 1`, identically to `CertReq`. They are never flooded, so the seqno
high-water loop protection is not involved and no new loop surface is created.

### 5.2 A lapsed board stays locked out, deliberately

If a board is offline past `not_after`, renewal cannot help it: it can no longer
route authenticated, so it cannot reach the authority, and even over a working
path the holder match would refuse it. Recovery is the operator ritual over the
serial port.

That is the correct outcome rather than a limitation to engineer away. The
7-day lifetime is a revocation bound (§2.1); a mechanism that let an expired
credential bootstrap a fresh one over the mesh would convert that bound into a
formality, because a revoked-and-offline board is exactly the case the bound
exists for.

### 5.3 Replay

The request carries a nonce and the reply is a certificate that must verify
against the trust anchor, so a replayed request yields at worst a re-issue of a
certificate to its rightful holder. The board must not accept a `RenewReply`
that does not answer an outstanding request of its own — the same rule
`ingest_cert_reply` applies — and must not roll its stored credential *backwards*
to an older certificate, which is design 22 §4.6's clock-rollback prohibition
reaching the credential beside the checkpoint.

### 5.4 A route that does not exist

A board with no path to the authority simply fails to renew and retries at the
next poll. This is the ordinary case on a partitioned mesh and must be quiet —
`trace!`, not `warn!` — until it becomes urgent, at which point §7's alarm is
the operator-facing channel.

**Precondition worth stating:** this works only where a board's mesh actually
reaches the authority, which today means a multi-hop path through a host node
that carries both a board-facing radio and the CA's tunnel link. That is a
deployment property, not something this design guarantees.

### 5.5 Frame size on a small-MTU radio

The request carries a full `MembershipCert` plus a signature, and the reply
carries a certificate. On 802.15.4 and LoRa that is several fragments through
`wayfinder-link-utils`. It is comparable to what lazy cert distribution already
moves, and it happens a handful of times per certificate lifetime rather than
per frame — but the fragment count belongs in the implementing session's
measurements, not in an assumption here.

## 6. Security

**What this widens.** The authority begins answering a request that arrives over
the mesh rather than over authenticated TLS. The request is not unauthenticated
— it carries a certificate verified against the anchor, a revocation check and
proof of possession, all before any policy runs — but it is reachable by any
mesh member rather than by anything holding a management credential. It must
therefore be rate-limited at the authority as `SubmitCsr` is, and the cheapest
refusals (malformed body, failed verification, revoked requester) must come
before the expensive ones, as `verify_cert_request` already orders them.

**What it does not widen.** No new authority is trusted; the board pins by trust
anchor. No credential crosses the wire in the clear that is not already public —
a membership certificate is a public document. Nothing here lets a non-member
obtain a first certificate (§3 non-goals), which is the property that keeps the
enrollment approval queue meaningful.

**Revocation interaction.** A revoked member's renewal is refused at
`is_revoked` before reaching the authority, so revocation still bites at the
first hop that knows about it, not only at the CA.

## 7. Observability

Per the root `CLAUDE.md`, in the `no_std` core and not the driver, so a board
has them — on `OgmAuth`, projected through `CentralRouter` (see §4.3's note):

- `renewal_requests_sent` / `renewal_replies_accepted` — counters. The gap
  between them is the signal.
- **An alarm** (`libs/wayfinder-alarm`) when this node is inside the renewal
  window and has not succeeded — latched on `(kind, subject)`, coalescing, which
  is exactly the shape for a condition that persists and retries. This is the
  operator-facing half, and the thing that turns a silent weekly drop-off into a
  visible one.
- The authority side counts refusals by reason, so "boards are failing to renew"
  is distinguishable from "boards are not asking".

`GetNodeInfo` already carries the certificate's `not_after`, so a dashboard can
render time-to-expiry against renewal state without new wire.

## 8. Alternatives considered

- **A long-lived certificate for boards.** Per-approval TTL already ships
  (`122e448`), and `MAX_CERT_TTL_SECS` is 10 years, so an operator can approve a
  board for a year today with **zero code**. Rejected as the answer, kept as the
  stopgap: it trades the revocation bound away on precisely the members most
  likely to be lost or stolen, and a board is the node an attacker can put in a
  pocket. Worth applying now to stop the bleeding while this is built.
- **A host node renews on the board's behalf.** The CSR must be signed by the
  board's key, so the host can only relay — which needs a mesh request/reply
  exchange anyway, plus a designated proxy and a story for what happens when it
  is the node that is down. Strictly more machinery than §4 for strictly less
  independence.
- **Mgmt-over-BLE / an IP stack on the board.** Would let a board be a real
  client and renew the host's way. Much larger, parked elsewhere, and it
  re-opens #57's authentication question (a transport with no physical
  precondition does not inherit that decision). Not a prerequisite for this.
- **Accept the weekly ritual.** What happens if nothing is done. It makes
  embedded membership an operator subscription, and it scales with the number of
  boards, which is the wrong direction for a mesh.

## 9. Open decisions for the implementing session

1. **Reuse or copy the parked-reply machinery** for holding a verified request
   across the authority round trip (§4.3). Reuse is less code; copying keeps
   lazy-cert-distribution's table from being sized by a second, unrelated user.
2. **Nonce source on a board.** The next-hop proof uses a monotonic counter
   feeding a nonce PRF (`libs/wayfinder/src/auth.rs:589`), and design 06 F7
   noted the weakness that counter has on a board: **it restarts at every
   reboot.** Renewal should share that source rather than add a second one — but
   design 22 changed the options, because a board now has a durable record that
   could checkpoint the counter beside the clock. Decide whether renewal simply
   reuses the counter as-is (acceptable: a repeated renewal nonce costs a
   re-issue to the rightful holder, per §5.3) or whether this is the occasion to
   checkpoint it, which would improve the next-hop proof too.
3. **Whether the provider block should carry a MAC *and* an address**, so one
   encoding serves host and board, or two shapes. §4.4 assumes a MAC for boards;
   a single union may be tidier at the proto.
4. **Retry cadence under failure.** 15 minutes matches the host, but a board on
   a duty-cycle-limited radio may want backoff — and the renewal window is
   ~42 hours at a 7-day TTL, so there is room.

## 10. Key file map for the implementer

> **Written before implementation; kept as a record of the plan.** The paths and
> line numbers below are as of the design, and several have moved — most of all
> `libs/wayfinder/src/auth.rs`, which is now the `libs/wayfinder/src/auth/`
> directory (see §4.3's note). Read this for *what to copy from*, not for where
> anything is; `libs/wayfinder/CLAUDE.md` carries the current map.

- `libs/batman/src/wire.rs` — the two packet types and headers.
- `libs/batman/src/engine.rs:1916` — the cert-control relay arm to copy; the
  implementation merged all four into `handle_credential_control`.
- `libs/wayfinder/src/auth.rs:2139` — `verify_cert_request`, the body verifier
  to copy, including its ordering of cheap checks before the rate limiter. Now
  `auth/distribution.rs`.
- `libs/wayfinder/src/lib.rs:1823` — the `DeliverLocal` arms.
- `libs/wayfinder-driver/src/renew.rs` — the host renewal semantics this must
  match: holder match, `due_renewal`, provider from state not config.
- `libs/wayfinder-embedded-driver/src/settings.rs:99` — the deliberate
  provider-drop this design reverses, and its test.
- `libs/wayfinder-server/src/authority.rs` — the re-issue path.

### Failing tests to write first

Per the repo's test-first rule, each is its own red checkpoint:

1. `a_board_persists_a_renewal_provider` — replaces
   `a_renewal_provider_is_not_persisted`, which is the current behaviour's
   guard and must be deleted in the same change that makes it false.
2. `a_renewal_request_verifies_like_a_cert_request` — anchor, revocation and
   proof-of-possession, in that order.
3. `a_renewal_request_from_a_lapsed_holder_is_refused` (§5.2).
4. `a_renew_reply_that_answers_no_outstanding_request_is_dropped` (§5.3).
5. `a_board_attempts_renewal_on_a_proven_floor_without_proving_non_expiry`
   (§4.5) — the posture case, and the one most likely to be got wrong.
6. `a_renew_req_is_relayed_with_a_decremented_ttl` (§5.1).
7. A hardware test in `libs/wayfinder-hil`: a board renews across a real mesh
   and keeps routing. Design 21 §5's list grows by one.

## 11. What the implementing session decided

### 11.1 §9's open decisions

- **The parked-reply machinery was copied, not reused** (§9.1), and shrank in
  the copying: the router holds **one** verified request, not a table. The
  driver drains it on the very next turn of its loop, so a request that finds
  the slot occupied is one that arrived inside a single iteration of a request
  not yet picked up — displacing costs that requester one round trip, where a
  table would size bounded state for something nothing is asking for, and carry
  it forever unused on a board that will never be an authority.
- **The nonce reuses the next-hop counter as-is** (§9.2), under its own PRF
  domain. Checkpointing it stayed out of scope: a repeated renewal nonce costs a
  re-issue to the rightful holder, and the reply is matched against the node's
  own outstanding slot rather than against the nonce's uniqueness, so the reboot
  weakness buys an attacker nothing here. Improving the next-hop proof is its
  own change.
- **The provider block needed no new field at all** (§9.3), which is better than
  either option the design offered. Since design 09 §5 a node's mesh address
  *is* the address its identity key derives, so the authority's MAC is already a
  function of the `node_key` the block pins. `RouterAdapter::set_auth` derives
  it; the board's record stores the key. There is no second field for an
  operator to fill in wrong, and no way for the address a renewal travels to and
  the authority it is pinned against to disagree. It also keeps the derivation —
  and the crypto it needs — out of the proto crate every board links.
- **Fifteen minutes, no backoff** (§9.4). At the seven-day lifetime
  `wayfinder-ca` issues, the renewal window is about 42 hours, so a fixed
  quarter-hour cadence gives a partitioned board roughly 170 attempts, each one
  small frame. Backoff would trade that margin for an airtime saving nothing
  asked for, on a node that spends more on a single OGM round.

### 11.2 What the design did not anticipate

- **The renewal packets require a pairwise tag.** §4.1 argued from `CertReq`'s
  pattern, and `CertReq` is *exempt* from the tag — because lazy cert
  distribution is what supplies the keys a tag needs, so gating it would
  deadlock bootstrap. Renewal has no such circularity: a node renewing is by
  definition still holding a valid certificate and routing authenticated (§2.2),
  so it already holds a pairwise key with the neighbour it hands the frame to.
  The exemption would buy nothing and would let a party with no credential put
  renewal traffic into the mesh for the authority to spend verification on.
  Both directions therefore take the **proof-gated** next hop, like a
  reachability probe and unlike cert control.
- **The four relay arms became one.** §4.1 argued that copying `CertReq`'s nine
  lines a third and fourth time was the point. It is the argument for the
  *shape*, not for the duplication: a fourth copy that forgot its TTL decrement
  is a renewal that circulates forever on a mesh with a transient loop, and
  nothing else in the engine would catch it. The four are now one generic
  function over a private header trait.
- **`renew_holder` is its own entry point on the authority**, not a second
  caller of `submit_csr`. The two agree exactly on the case that succeeds and
  differ on every case that does not: `submit_csr` *parks* what it cannot
  answer, which is right over authenticated TLS where an operator is standing
  there, and wrong over the mesh — a held CSR is credential-bearing state, and a
  lapsed board would create one unattended, once per rate-limit interval, for as
  long as it stayed lapsed.
- **A refusal never travels back.** §4.3 said the authority "declines" without
  saying what reaches the asker. Nothing does: a `RenewReply` carries a
  certificate or it does not exist. A node that cannot be renewed hears silence
  and reads it off the gap in its own counters, which is honest — it needs an
  operator either way — and is one fewer message for an attacker to forge.
- **The alarm's two variants were unreadable, and so were the ones already
  shipped.** An alarm's detail is truncated at 64 bytes, and the host renewer's
  "renewing against its provider" and "no renewal provider recorded, this will
  never happen by itself" differed only well past that boundary — so both
  rendered as the same row and the distinction reached nobody. Every variant now
  front-loads its distinguishing clause.

### 11.2.1 What adversarial probing of the install path found

§5.3 reasoned that "a replayed request yields at worst a re-issue of a
certificate to its rightful holder". True of the *request*; the **reply** needed
one more check than the design specifies.

A `RenewReply` is relayed hop by hop with no end-to-end integrity of its own, so
any node on the path can replace the body. Three of the four substitutions
available to it are refused by what §4 already implies — a forgery under a
foreign root fails the anchor, another member's certificate fails the
names-this-node check, and an older *shorter* certificate fails
"must move forward". The fourth is a genuine, root-signed certificate **this
board used to hold**: certificates are public, so an adjacent member can keep a
copy, and once an operator *shortens* the device's approved lifetime that copy
outlives the current one and passes a `not_after` test. Installing it undoes the
reduction silently, on exactly the node whose exposure the operator was
limiting.

`ingest_renew_reply` therefore compares **both ends** of the window. The
authority stamps `not_before` at the instant of issue, so a genuine re-issue
never moves it backwards and a replay always does.

Two things bound this that are worth recording, because they are why it is a
narrow hole rather than a wide one. The attacker must be an **authenticated
neighbour**: a `RenewReply` is a directed sub-type, so it carries a pairwise tag
the board verifies against the immediate link sender — which is the §11.2
decision to require a tag paying for itself. And a board that has heard a
revocation naming itself has no auth state at all (`apply_self_revocation`
clears it), so the install path is unreachable rather than merely unguarded.

### 11.2.2 Findings raised against the implementation and rejected

Recorded so they are not re-litigated; everything that was *accepted* is in the
commit history, not here.

- **"Collapse the four credential-control headers onto one shared struct and
  drop `CredentialControlHeader`."** They are byte-identical today, and that is
  exactly what the trait makes *checkable*: a fifth type with a different shape
  fails to compile rather than silently relaying a `dest` read from the wrong
  offset. It would also cost the four packet types their names at the relay,
  which is half of why they are separate types at all (§4.1).
- **"`MembershipCert::to_bytes` is redundant with `as_bytes`."** Rejected on the
  facts: `zerocopy` is a **dev**-dependency of `wayfinder-embedded-driver`, so
  the `as_bytes` calls offered as precedent are all in `#[cfg(test)]` code.
  Production there cannot name the trait without promoting `zerocopy` into a
  crate every board links.

### 11.3 What was not built

- **Authority-side refusal counters.** §7 asks the authority to count refusals
  by reason. What shipped is a **structured log line per refusal**, at `debug!`
  or `warn!` by cause, served over `GetLogs` like everything else on a node with
  no probe attached. A counter with no request to read it from would be state
  nobody can see, and the management API has no provider-statistics response to
  put one in; adding one is its own change. The distinction §7 actually cares
  about — "boards are failing to renew" versus "boards are not asking" — is
  answered from the board's side by the two counters that *did* ship, which is
  the side an operator is usually looking at.

