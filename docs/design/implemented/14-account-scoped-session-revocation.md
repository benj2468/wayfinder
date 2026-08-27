# Design: account-scoped session revocation

**Status:** Implemented. §8 records what landed that this design did not
anticipate — a pre-existing bug the work uncovered.

**Scope:** `libs/wayfinder-server` (`users.rs`: an `AccountId` on `UserRecord`;
`authority.rs`: stamping it on a session certificate, and two new revocation
paths; `persistence.rs`: a schema-version bump and one combined mutation;
`authority_task.rs`: one signed revocation per request becomes many;
`authz.rs`), `libs/wayfinder-protos` (one request/response pair — `.proto` *and*
`service.rs`), `libs/wayfinder-client`, `bins/wayfinder-web` (a Revoke control on
the Accounts tab, a hint widget, `api.rs`, `mock.rs`), `bins/wayfinder-ctl` (a
warning on the offline removal path). **No change** to `MembershipCert`'s layout
or flag semantics, to `RevocationRecord`, to OGM authentication, to the `no_std`
core, to the mgmt-TLS handshake, or to `decide_access`'s tier derivation.

## 1. Motivation

Deleting an account does not end its access.

`CertAuthority::remove_user` retains the account out of the user store and does
nothing else. Its own doc says so: "A certificate it has already been issued is
unaffected — that is what `RevokeNode` and expiry are for — so this ends the
ability to obtain *new* sessions, not any session in flight." The same is true of
`disabled`, which `UserRecord::authenticate` consults at sign-in and nowhere
else.

What a sign-in produces is a real `MembershipCert` carrying `CERT_FLAG_USER` plus
`CERT_FLAG_ADMIN` or `CERT_FLAG_VIEWER`, bound to a MAC derived from a keypair
the dashboard generated for that session. Per-connection authorization
(`authz.rs`) consults exactly three things: the signature against the trust
anchor, the revocation set, and the capability bits. It never reads the user
store. So a deleted administrator keeps administering the mesh until `not_after`
— eight hours by default (`DEFAULT_SESSION_TTL_SECS`), and as long as the admin
who granted the account chose.

**"That is what `RevokeNode` is for" does not hold up in practice.** The
machinery would work: `MeshAuthority::revoke` marks the issued record and signs a
`RevocationRecord` the mesh floods, and session certificates *are* in the issued
log with `user: true`. Two things make it unreachable:

1. **`IssuedCertData` records no owner** — MAC, ed pubkey, validity window,
   revoked, and the three capability booleans. Nothing correlates a session
   certificate back to the account that minted it, so an operator cannot tell
   *which* certificate to revoke.
2. **`ListCerts` is not in the dashboard at all.** It is a `wayfinderctl`
   command. The Members tab's Revoke button reads `security.nodes`, the mesh
   member table — devices, not user sessions.

So the only account control a dashboard offers is Remove, Remove does not remove
access, and the mechanism that would has neither the data to target it nor a
surface to reach it from.

## 2. Goals / Non-goals

**Goals**

- Revoking an account's sessions is one action an administrator can take from
  the dashboard, and it ends every certificate that account currently holds.
- **Removing an account revokes its sessions as part of the same act.** The
  destructive control that an operator reaches for when an account is
  compromised must not leave the compromise running.
- The link from a certificate to its account **survives the account's deletion**,
  so an orphaned session is still findable.
- Revoke and Remove are told apart at the point of use, not in a manual.

**Non-goals**

- Revoking *one* session while leaving an account's others alive. The data model
  here permits it (each session is its own MAC) and the wire does not need to
  change to add it later; no UI is built for it now.
- Making `disabled` revoke. Disabling stays what it is — a reversible stop on new
  sessions — and §5.4 explains why coupling it to an irreversible mesh-wide flood
  would be wrong.
- Re-flooding revocations at startup. Unchanged and still out of scope; see
  design 03.
- Any change to how the *offline* `wayfinderctl user remove` behaves beyond
  warning about what it cannot do (§5.5).

## 3. Design

### 3.1 An account id, and which way the reference points

`UserRecord` gains an `id: AccountId` — 16 bytes from the OS CSPRNG, minted once
when the account is created and never reused.

`IssuedCertData` gains `account_id: Vec<u8>`: the id of the account whose sign-in
produced this certificate, empty for a device's membership certificate.
`sign_user_session` stamps it; `sign` leaves it empty.

**The reference points from the certificate to the account, not the other way,
and that is the load-bearing decision.** The obvious alternative — a list of
certificate ids on the `UserRecord` — makes removal and revocation one atomic step
*forever*: the moment they are not, the live certificates are orphaned with
nothing anywhere naming them, and no later pass can find them, because the index
left with the account. That is not hypothetical. It is the state of every
deployment today, it is what the offline `wayfinderctl user remove` does (§5.5),
and it is what a crash between two writes would leave behind. With the reference
on the certificate, the record outlives its owner and an orphan stays findable.

**An id rather than the username**, because a name can be recycled: delete `ops`,
create a new `ops`, and a name-keyed reference silently hands the new account the
old one's certificates. An id cannot be recycled, so a session belongs to the
account that actually minted it or to nothing.

**No new identifier on the certificate itself.** `MembershipCert` is a fixed
`zerocopy` struct with no spare field, and `signed_body()` is `size_of - 64`, so
any added field changes what every verifier must parse — including nRF52840
firmware in the field, which would need reflashing before it could verify a
certificate the CA issues. The mesh already has the only per-session identifier
revocation can act on: the MAC, which `derive_mac(&ed)` makes fresh at every login
and which `RevocationRecord` names. A CA-side id that the mesh cannot see would
buy nothing here and force an id→MAC translation at the moment of acting.

### 3.2 The two paths

Both resolve `username` → `AccountId`, then select the account's **live** session
certificates from the issued log:

```
c.user && c.account_id == id && !c.revoked && c.not_after > now
```

Already-revoked entries are skipped deliberately: re-sending costs mesh airtime to
say something the mesh already believes, which is the same rule the Members tab
applies to an already-revoked node.

**`revoke_user_sessions(username)`** signs a `RevocationRecord` per selected
certificate, marks each entry `revoked` in one `mutate_issued` write, and returns
the records to be flooded and the count to report.

**`remove_user(username)`** does that *and* deletes the account, through a single
`mutate_users_and_issued` write. One write, because two would leave a crash window
in both directions: an account deleted whose sessions came back un-revoked, or
sessions revoked under an account that still exists and can mint more. The
last-administrator guard on `MeshAuthority::remove_user` is unchanged and is
evaluated before anything is signed.

Signing is stateless local computation, so it happens before the mutation and
outside it. If the persist fails, `Persisted::mutate` rolls both collections back
and the signed records are dropped without ever being flooded — the operator is
told the removal did not take effect, which is true.

### 3.3 One request may now sign many revocations

`AuthorityAdapter` holds `signed_revocation: Option<RevocationRecord>` with a
`debug_assert!` that one request signs at most one. Both become plural:
`Vec<RevocationRecord>`, `finish()` yields the vector, and the task's serve loop
floods each in turn, folding the first failure into the response exactly as
`signed_but_not_flooded` does today. The `#[must_use]` on `finish` stays and
matters more, not less.

Ordering is unchanged in the way that counts: signing and flooding stay adjacent,
with no other command served in between, because nothing re-derives a signed
record after a crash.

**Cost, stated plainly.** Each login mints a new MAC, so an account holds one live
certificate per sign-in within its TTL window, and revoking it floods one ~92-byte
record each. A person signing in from a laptop and a phone costs two; an
automation account logging in every minute against an eight-hour TTL would cost
several hundred, on a mesh whose slowest segment may be duty-cycle-limited LoRa.
The issued log already grows this way and already has no per-account cap — this
change does not make that worse, it makes the existing shape visible. Back-pressure
is real rather than notional: the revocation channel is bounded and the authority
task awaits the router's verdict for each record, so a large batch paces itself
instead of buffering. A per-account live-session cap is the right follow-up and is
deliberately not in this change, because every way of introducing one either
locks people out or silently strands an unexpired certificate outside the log,
which is the exact failure this design exists to end.

### 3.4 The wire

One request/response pair, purely additive:

```protobuf
message RevokeUserSessionsRequest { string username = 1; }
message RevokeUserSessionsResponse { uint32 revoked = 1; }
```

`RemoveUserRequest` keeps answering with the shared `Empty`. Giving it a count
would mean a new response kind, and an older client matching `ResponseKind::Empty`
would break for a field it never asked for. The count is worth reporting for the
control whose entire purpose is the count, and is not worth a compatibility break
for the one where it is incidental.

`RevokeUserSessions` joins the admin tier in `permits` — refused to viewers for
the same reason `RemoveUser` is: it administers who may administer the mesh — and
is audited as a `Mutation`, taking access away.

### 3.5 The dashboard

The Accounts table gains a second per-row control, **Revoke**, beside Remove, and
both sit behind the existing confirmation dialog.

A **`Hint`** widget carries the floating description: a small `?` affordance that
reveals a short panel explaining what Revoke does and how it differs from Remove.
It is a focusable `<button>`, not a `title=` attribute — `title` is invisible to
keyboard and touch users, and this is precisely the explanation somebody needs
before pressing an irreversible control.

The panel is a native **`popover`**, which puts it in the browser's top layer.
That is not decoration: the hint sits in the header of a table inside
`.wf-table-scroll`, and any absolutely-positioned panel is clipped by that scroll
container — with a short roster the explanation is cut off partway down, and no
z-index fixes it, because the problem is the clipping context rather than the
stacking order. The top layer escapes both, and adds nothing to the container's
height. `popovertarget` also hands the browser the open/close state and the
light-dismiss, so the widget carries no signal and no click handler.

What it says is the distinction itself: **Revoke ends the account's current
sessions and leaves the account able to sign in again. Remove does both — it
revokes and then deletes the account.** Revoke is the one to reach for when
somebody's laptop is lost and they still work here.

## 4. Migration and versioning

Snapshot schema **6 → 7**. Both new fields carry serde defaults, so a version-6
snapshot loads without a bespoke transformation: each existing `UserRecord` takes a
freshly generated `AccountId` (per record, so no two accounts collide), and each
existing `IssuedRecord` takes an empty `account_id`.

The empty id on existing records is the honest answer, not a loss: nothing in a
version-6 snapshot ever recorded which account a session belonged to, so those
certificates genuinely cannot be attributed, and they expire on their own schedule.
`RevokeNode` on the MAC remains the tool for one of them.

**One ordering property is load-bearing** and is worth a test rather than a
comment. Ids minted at load are in memory only until the next write, so a
certificate stamped with an id that never reached disk would be orphaned by a
restart. It cannot happen on the path that stamps one: `authenticate_user`
performs its `mutate_users` — which persists the whole state, ids included —
before the `mutate_issued` that records the certificate. A test asserts the whole
property end to end: load a pre-id snapshot, sign in, restart, and the session is
still attributed to its account.

## 5. Correctness and edge cases

**5.1 Revoking the session making the request.** An administrator may revoke or
remove their own account, and the certificate authenticating that very connection
is among the revoked. The request is already served by then. This is deliberate
and matches `RevokeNode`, which can already be pointed at the node the operator is
talking to. The dashboard shows the resulting denial as an ordinary session expiry.

**5.1a How quickly a revoked session actually stops.** Not instantly, and the
bound is worth stating because the UI states it too. A management connection's
authorization is decided at the handshake and cached; `transport.rs` re-decides
only when a request arrives at least `REVALIDATE_AFTER` (60 s) after the last
decision. So a session *already connected* keeps working for up to a minute,
while anything reconnecting is refused at the handshake immediately.

That constant predates this design and applies equally to `RevokeNode`; nothing
here changes it. It is the right place to look first if a minute turns out to be
too long for an account — the options being to lower it globally, to make it zero
for `CERT_FLAG_USER` certificates alone (a session is a person, and a per-request
round trip to the router is affordable at human rates), or to close open
connections carrying a just-revoked key rather than waiting for their next
request. None is in this change.

**5.2 An account with no live sessions.** Both paths succeed, sign nothing, and
report zero. Remove behaves exactly as it does today, including on a node with mesh
authentication disabled.

**5.3 Mesh authentication disabled.** Signing a revocation that cannot be flooded
leaves the operator believing access ended when nothing was announced, so — as
`revoke_node` already does — both paths refuse *when there is something to
revoke*, and are unaffected when there is not. Remove on a sessionless account
keeps working on such a node, which is what today's behavior is.

> **Since superseded.** §5.4's conclusion — that disabling must not revoke —
> was reversed by design 15, which makes `SetUserEnabled` revoke the account's
> live sessions so that "disabled" describes access now rather than only
> future sign-ins. §5.5's offline path no longer exists at all: `wayfinderctl
> user` is RPC-only.

**5.4 Why `disabled` does not revoke.** Disabling is reversible by design and is
how an operator parks an account. A revocation is not reversible: it floods, every
node holds it until the certificate would have expired anyway, and re-enabling the
account cannot recall it. Making a reversible control fire an irreversible one
would make disabling more destructive than the word suggests. An operator who
wants both presses both, which is now possible for the first time.

**5.5 The offline path is honest about what it cannot do.** `wayfinderctl user
remove` operates on the state file with no router to flood to, so it cannot revoke
— and since nothing re-floods revocations at startup, marking the entries would not
help either. It keeps its current behavior and gains a printed warning naming the
sessions it is leaving live and pointing at the online path. Stating the gap is the
fix available offline; hiding it is what it does today.

**5.6 Removal and revocation cannot durably split**, by construction: one
`Persisted::mutate` covers both collections, so either the account is gone and its
sessions are revoked, or neither happened.

## 6. Observability

`revoke_user_sessions` and the revoking half of `remove_user` log at `info!` with
the account name and the number of certificates revoked — a lifecycle event about
who lost access, which is the same reasoning that puts "issued a user session
certificate" at `info!` on the way in. Zero is logged too: "revoked nothing" is
the answer to a question an operator asked, and its absence would read as failure.

No new metric. The counter that would matter — live sessions per account — is a
projection of the issued log, and the log is already served by `ListCerts`; the
field that would make it readable per account is the natural follow-up to §2's
non-goal, not part of this change.

## 7. Alternatives considered

**Store the username on the certificate record.** Simpler by one type, and wrong
for the reason §3.1 gives: names are reusable and a recycled name silently
re-parents old certificates.

**A `certs: Vec<CertId>` on the `UserRecord`.** The shape this design was first
proposed as. Rejected in §3.1: deleting the account destroys the index to the
thing that needed revoking, which converts today's bug from "present" into
"unfixable after the fact".

**Check the user store at authorization time.** Would end the gap with no new
state at all — and would require every node serving the management API to hold the
CA's user store, which is exactly the thing a certificate exists to avoid. A node
that is not the provider has no user store and never will.

**Make `remove_user` refuse until sessions are revoked separately.** Two deliberate
acts, no atomicity worry, and no risk of Remove flooding a mesh unexpectedly.
Rejected because the two-step is the failure mode being fixed: the operator
reaching for Remove in a hurry is precisely the one who must not be handed a
half-measure.

## 8. What the implementation found

**The last-administrator guard was never on the live path.** `CertAuthority` has
an inherent `remove_user` (the offline tool's raw store operation) and a
`MeshAuthority::remove_user` (which carries the guard). Rust resolves an inherent
method ahead of a trait one, so `AuthorityAdapter::remove_user`'s
`self.ca.remove_user(..)` had always reached the raw version: no guard, on the
one path a dashboard's Remove button actually takes. The guard was written and
unit-tested against the trait directly, which is why nothing showed it.

It surfaced here only because this design changed the trait method's return type
and the workspace still compiled — proof the call was resolving elsewhere. The
adapter now names `MeshAuthority::remove_user` explicitly, and
`removing_an_account_through_the_adapter_applies_the_last_admin_guard` in
`authority_task.rs` is the regression test. Worth recording as a hazard rather
than a fixed bug: any trait whose implementer also has inherent methods of the
same name has this shape, and `CertAuthority` deliberately keeps both.

**A session revocation's window is the certificate's own expiry**, not the
authority's `cert_ttl_secs`. `CertAuthority::revoke` uses the latter, which is a
safe over-estimate for a device but not for a session: an account's
`session_ttl_secs` may exceed the authority's, and the revocation would then stop
being enforced while the certificate it cancels still verified. The session paths
read `not_after` off the issued record they are already holding, which is both
exact and tighter.

**The Hint went through two wrong shapes before the popover.** The first used
`aria-describedby` pointing at a panel rendered only while open, leaving the
reference dangling whenever it was closed — almost always. The second fixed that
with `aria-expanded`/`aria-controls` and a `hidden` panel, and was still wrong for
a reason no amount of ARIA addresses: an absolutely-positioned panel is clipped
by `.wf-table-scroll`, so on a short roster the explanation was simply cut off.

The lesson is worth keeping: *a panel that must escape its container is not an
`absolute`/`z-index` problem.* `overflow` establishes a clipping context, and
stacking order has no bearing on it. The native `popover` attribute is the
purpose-built escape, and it removes the state handling as a side effect.
