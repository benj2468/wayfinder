# Design: self-service user registration by one-time invite

**Status:** Implemented (§11 records what landed and what did not). Built on
design 13, which is what makes an Argon2id hash on a link-carrying certificate
authority safe — completing a registration runs one, and before 13 it would have
executed inside the router's `select!` arm.

**Scope:** `libs/wayfinder-protos` (five request/response pairs — `.proto` *and*
`service.rs`: the `WayfinderDataProvider` trait, the dispatch, the request-name
maps and the audit allowlist), `libs/wayfinder-server` (`users.rs`: a
`UserInvite`; `authority.rs`: mint/start/complete/revoke/evict; `persistence.rs`:
a new persisted collection, a **schema-version bump** and its migration;
`authz.rs`: two of the five join the enrollment tier; `transport.rs`: per-source
limiters; `provider.rs`, `adapter.rs`), `libs/wayfinder-client`,
`bins/wayfinder-web` (a registration page, `api.rs` server functions, `mock.rs`),
`bins/wayfinder-ctl` (`user invite`). **No change** to `MembershipCert`'s layout
or flag semantics, to OGM authentication, to the `no_std` core, to the mgmt-TLS
handshake, or to `decide_access`'s tier derivation.

## 1. Motivation

Creating an account today mints both of its secrets on the administrator's
behalf and hands them to the administrator.

`CreateUserRequest` (`wayfinder.proto`, oneof tag 26) takes a `username` and
a `password` chosen by the admin, and `CreateUserResponse` returns the
account's `totp_enrolment_uri` — the `otpauth://` URI carrying the raw TOTP
secret, generated server-side inside `UserRecord::new` (`users.rs`, minted at
`:208`). The proto comment says it is "shown once", which is true, and shown *to
the wrong party*, which is the problem. The admin must then relay both the
password and the second factor to the person the account is for, over whatever
channel is at hand.

The result is an account whose second factor is permanently known to at least one
other party. That is not a second factor; it is a second thing the admin knows.
On a store where — per `bins/wayfinder-ctl/src/user.rs` — every account can
mint a certificate the whole mesh honours, it is the wrong property to build on.

**The obvious repair does not work.** "Create the account for them, let them
change the password" leaves the TOTP secret exactly where it was:
`UserRecord::set_password` (`users.rs`) rewrites `password_hash` (and the
lockout fields) and touches nothing else, so the admin's copy of the second
factor survives the change. It is also more machinery, not less. There is no
`ChangePassword` in the request oneof and no `must_change_password` flag anywhere
in the repository; `set_password` is reachable only from the offline CLI
(`bins/wayfinder-ctl/src/user.rs`). Doing it properly would need a new
request, a tier that can invoke it while holding only a temporary credential, a
forced-change gate on every *other* request, and TOTP re-enrolment on top to
actually fix the custody problem — landing somewhere worse than where this design
lands.

## 2. Goals / Non-goals

**Goals**

- The person the account belongs to is the first party to see its TOTP secret,
  and chooses its password. The admin sees neither.
- **Any other party learning that secret must cost the invite**, so it cannot
  happen silently. This is the load-bearing goal; §3.3 and §3.6 exist to serve
  it, and §5.1 bounds what it can and cannot promise.
- The admin decides *who* gets an account and *what role it has*, once.
- Redemption proves the second factor was actually enrolled before the account
  exists — a property `user add` does not have today.
- The invite travels as a URL a person can be sent and can open, because that is
  the flow non-technical users complete without help.
- An unredeemed invite is bounded, expiring, revocable and visible to the admin.

**Non-goals**

- **Not public registration.** An invite is minted by an admin for a named
  account; nothing here lets a stranger reach the account store.
- **Not a pending-approval queue.** The mint *is* the approval, taken at a moment
  the admin chose, with the role baked in.
- Not email delivery. The CA is deliberately minimal (design 11) and has no mail
  infrastructure; how the URL reaches the person is the operator's problem.
- Not password reset, and not TOTP re-enrolment for an existing account. Both are
  natural follow-ups on the same record; neither is in scope.
- Not removing `CreateUser`. It stays for automation accounts, which have nobody
  to send a URL to.

## 3. Design

### 3.1 A new record: `UserInvite`

A pending invite is **not** a `UserRecord` with a flag. It lives in its own
persisted collection beside the user store, so no code path that iterates
accounts can ever authenticate one. A half-built account that can log in is a
strictly worse failure mode than an invite that cannot, and the distinction
should not depend on every future reader of the user store remembering a flag.

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserInvite {
    /// The account name this invite will create.  Reserved from mint (§4.1).
    pub username: String,
    /// The role the created account will hold.  Decided by the admin at mint
    /// and never by the redeemer.
    pub role: UserRole,
    /// Session-certificate lifetime for the created account.  Re-clamped to the
    /// authority's cap at completion, not only at mint (§4.6).
    pub session_ttl_secs: u64,
    /// Blake2s256 of the invite token under this crate's invite label.  The
    /// token itself is never stored.
    pub token_hash: [u8; 32],
    /// The account's TOTP secret, minted here and revealed exactly once, to
    /// whoever starts registration.  Not an `Option`: a second factor is
    /// mandatory on this path (§3.7).
    pub totp_secret: Vec<u8>,
    /// Unix seconds; drives operator triage and TTL eviction.
    pub created_at: u64,
    /// Unix seconds after which the invite is refused.
    pub expires_at: u64,
    /// Whether registration has been started, and by whom.  `Pending` until the
    /// secret is revealed; `Started` thereafter, which is both the single-use
    /// interlock and the anomaly signal an admin reads (§3.6).
    pub status: InviteStatus,
}

pub enum InviteStatus {
    Pending,
    Started {
        /// Blake2s256 of the registration handle issued at start.  Only the
        /// party holding the handle can complete.
        handle_hash: [u8; 32],
        /// Unix seconds the secret was revealed at.
        started_at: u64,
        /// Unix seconds after which the handle is dead and the invite is spent.
        handle_expires_at: u64,
    },
}
```

The TOTP secret is minted at invite time. That keeps a single record with a
single lifetime and eviction rule, rather than a second provisional store keyed
by the same token.

### 3.2 The token

256 bits from `OsRng`, rendered base32 without padding (the alphabet the TOTP URI
already uses, and unambiguous if it ever has to be read aloud).

Stored as `Blake2s256(INVITE_LABEL || token)`, never in the clear — it is a
bearer credential sitting in the provider state file and should be no more
readable there than `password_hash` is. The domain-separation convention is
`libs/wayfinder-auth/src/cert.rs`'s `CERT_FINGERPRINT_LABEL`; this label is
`b"wayfinder-invite-v1"` and is owned by `wayfinder-server`, which already
depends on `blake2` transitively and must take it directly. Lookup compares
hashes in constant time — note this is a scan of a `Vec` bounded by
`MAX_PENDING_INVITES`, so the *work* is occupancy-dependent even though each
comparison is not.

### 3.3 The five requests

| Request | Tier | Effect |
|---|---|---|
| `CreateUserInvite` | full grant | Mint. Returns the token **once**. |
| `ListUserInvites` | full grant | Triage: who was invited, who started, who never finished. |
| `RevokeUserInvite` | full grant | Delete an unredeemed or started invite. |
| `BeginUserRegistration` | enrollment | **Consumes the token.** Returns username + `otpauth://` URI + a short-lived registration handle. |
| `CompleteUserRegistration` | enrollment | Verify handle + TOTP code, set password, create account, delete invite. |

The two redemption requests join `SubmitCsr`, `GetTrustAnchor` and
`AuthenticateUser` on the enrollment tier (`authz.rs`), for the reason
`authz.rs` already gives for `AuthenticateUser`: someone who has not
registered yet holds no credential, so a tier that required one would close the
door they need to knock on. Admission control is the token, its expiry, its
single use, and the fact that an admin minted it.

**`BeginUserRegistration` consumes the token, and this is the design's most
important decision.** The obvious alternative — a non-consuming `begin` that
reveals the secret to any presenter, so a page refresh is free — quietly destroys
the entire motivation. Under it, anyone who reads the URL out of a chat log, a
clipboard, or the browser history that §3.5 concedes it lands in can call
`begin`, take the raw `otpauth://` URI, and walk away; the legitimate
registration then completes normally, and nothing anywhere records that the
account's second factor is known to someone else. That is precisely today's
property with detectability removed. Making `begin` single-use is what converts
silent disclosure into a burnt invite and a failed registration the invitee
reports.

The cost is that a mid-registration page refresh must carry the handle. The page
holds it in `sessionStorage` (same tab, same origin, cleared on close), so a
refresh survives; a genuinely abandoned registration is re-minted by the admin,
which is cheap and is also the correct response to "something odd happened".

**`CompleteUserRegistration` requires a valid TOTP code** computed against the
invite's secret, plus the handle from `begin`. The code proves the authenticator
actually holds the secret before an account depends on it — the failure mode
`user add` has today, where a URI is printed and nobody checks it was ever
scanned.

Its effect is one atomic mutation (§3.4).

### 3.4 Atomicity, and the persistence change it requires

Completion must create the `UserRecord` **and** delete the `UserInvite` as one
durable act. Two writes leave a crash window with a burnt invite and no account.

`CaLog::mutate_users` (`persistence.rs`) cannot do this: it hands the closure
`&mut Vec<UserRecord>` and nothing else. The precedent that fits is
`CaLog::mutate_issued_and_held` (`persistence.rs`), which exists for exactly
this hazard and is pinned by two tests —
`mutate_issued_and_held_rolls_back_both_collections_together_on_persist_failure`
and `separate_mutate_issued_and_mutate_held_calls_can_durably_split`. This
design adds `mutate_users_and_invites` in its image.

**The new record also carries the account's TOTP replay guard.**
`UserRecord::new` (`users.rs`) hardcodes `totp_last_step: 0`, and
`verify_totp` refuses a step at or below it. If completion does not
carry the step it just accepted into the new record, the code the user typed at
registration stays valid at `AuthenticateUser` for the rest of its ±1-step window
— up to 90 seconds of replay against a brand-new administrative account. Since
`UserRecord::new` also mints its own secret at completion needs a second
constructor that takes both an existing secret and a starting `totp_last_step`.

### 3.5 The URL, and why the token goes in the fragment

```
https://dash.wayfndr.dev/register#<token>
```

**Fragment, not query string.** A fragment is never transmitted to the server,
which buys three things for a bearer credential:

1. It does not appear in the dashboard's HTTP access logs, or any reverse
   proxy's.
2. It is not sent in a `Referer` header if the page later links out.
3. **Link unfurlers never see it.** Paste a URL into Slack, Signal or iMessage
   and the platform fetches it server-side to build a preview. That fetch is a
   plain GET which runs no wasm, so with the token in the fragment the platform
   — and its logs — learn nothing. With it in the query string the token reaches
   the unfurler, and reaches the SSR render, where any implementation that
   redeemed on GET would burn the invite on a chat preview.

`bins/wayfinder-web` is Leptos in SSR mode, so the flow is: the server renders the
registration page knowing no token, the wasm bundle reads `window.location.hash`
after hydration, and calls a `#[server]` function (`api.rs` is where those
live) that opens the anonymous connection to the provider. That is the shape
`session.rs`'s `login` already uses — throwaway keypair, no certificate, the
enrollment tier — so this adds a caller, not a mechanism. The page clears the
fragment with `history.replaceState` immediately after reading it.

**What this does not fix:** the URL still lands in browser history, the
clipboard, and the messaging app that carried it. The mitigations for those are
the short TTL, the single use, and the visibility in §3.6 — not the fragment. The
fragment closes the paths where the token would leak *with nobody doing
anything*.

**The registration page cannot be a `<Route>`.** `Login` is not routed; it is a
conditional overlay rendered *outside* `<Routes>` and gated on
`Viewer::LoggedOut` (`bins/wayfinder-web/src/lib.rs`). A
`<Route path=StaticSegment("register")>` added at `:225-232` would render inside
the full dashboard shell — `<Header>`, `<TabBar>`, `<StatusStrip>` —
*and be covered by the sign-in overlay*, for exactly the signed-out visitor it
exists for. Either the overlay's condition gains a route-aware exclusion, or the
registration page is served by axum outside the dashboard shell entirely. The
second is cleaner: a registrant is not a viewer, and giving them a page with a
dashboard's tab bar on it is misleading.

### 3.6 What an admin can see, and what the design actually promises

`InviteStatus` is the audit trail. `ListUserInvites` shows, per invite: minted,
started-but-not-completed (with the timestamp the secret was revealed), or
expired. The state that matters is **started and not completed**: it means
someone took the second factor and did not finish, which is either an abandoned
registration or a disclosure, and either way the admin's response is the same —
revoke and re-mint.

This is what the goal in §2 buys, and it is worth being exact about its limit:
the admin holds the token between mint and delivery and can always start the
registration themselves. The design does not prevent that and does not claim to.
What it guarantees is that **doing so consumes the invite**, so the legitimate
registration fails, the invitee says so, and the admin's own listing shows the
start they did not expect. The exposure moves from silent and automatic to
deliberate and recorded. Compare today, where `CreateUserResponse` hands the
admin the secret with no action, no record and no way to ask afterwards whether
anyone else has it.

### 3.7 No second-factor-free invites

`no_totp` is not offered on this path, and `totp_secret` is therefore not an
`Option`. An invite with no second factor degenerates to "a bearer token in a
chat message buys an account that can mint a mesh-wide certificate", drops the
proof-of-enrolment goal entirely, and makes the URL single-factor for full mesh
administration. An automation account that cannot present a code has nobody to
send a URL to either; `CreateUser` with `no_totp` remains its path, as does
`wayfinderctl user add`. The invariant lives in the type so it cannot be
re-opened by accident.

## 4. Correctness and edge cases

1. **Username reservation, both directions.** `CertAuthority::add_user`
   (`authority.rs`) and `MeshAuthority::create_user` check only the user
   store. Both must also consult the invite store, or an admin creating a name
   that has a pending invite silently strands it until expiry and the invitee's
   registration fails with no explanation. `RemoveUser` should drop a matching
   invite too. Mint refuses a name that is taken *or* invited; completion
   re-checks, and a refusal there consumes nothing.
2. **Expired invite or handle.** Refused at both steps. Eviction is lazy and
   bounded, mirroring the held-CSR sweep (`authority.rs`), so a
   stale invite cannot accumulate.
3. **Capacity.** `MAX_PENDING_INVITES`, mirroring `MAX_HELD_CSRS`
   (`authority.rs`): a persisted store that grows without bound leaves the
   growth behind across a restart. Unlike held CSRs only a full grant can add
   one, so the cap guards against operator error, not a remote party.
4. **Invalid token must not cost Argon2id.** An unknown token is rejected
   *before* any hashing. This is the opposite of the `spend_absent_user_work`
   rule (`users.rs`) and deliberately so: that exists because usernames are
   low-entropy and guessable, so timing would enumerate accounts. A 256-bit
   `OsRng` token is not enumerable on any timescale, and `begin` already
   separates valid from invalid by response content on the same tier — so there
   is no oracle left for timing to leak, and spending 64 MiB of memory-hard work
   per bad token would hand any anonymous party a DoS amplifier against the CA.
5. **Replay.** The invite is deleted on success, so a replayed `complete` fails
   as unknown. The handle is single-use. The TOTP code cannot be replayed at
   login because completion carries its step forward (§3.4).
6. **Role and TTL are frozen at mint but applied up to a day later.** Completion
   re-clamps `session_ttl_secs` to the authority's certificate-lifetime cap, the
   way `CreateUserRequest`'s comment says that path does. The role is not
   re-validated — it is the admin's decision and there is no policy for it to
   drift against — but say so rather than leave it ambiguous.
7. **Concurrent starts / completions.** Decided by the atomic mutate-and-persist:
   one wins, the other sees a spent invite or an unknown handle.
8. **Revocation.** `RevokeUserInvite` deletes at any status. Revoking an already
   completed invite is a no-op — the account exists and `RemoveUser` is the tool.

## 5. Security considerations

### 5.1 What the fragment does not protect against, on this deployment

The CA's dashboard is served through a Cloudflare Tunnel, and
`nix/machines/wayfinder-ca/common.nix:63-67` states the consequence plainly:
"Cloudflare terminates TLS and therefore sees the dashboard's plaintext,
including a password at sign-in — a real trust decision, not a free lunch."

Every leg of this flow crosses that boundary: the token in the `#[server]` POST,
the raw `otpauth://` URI in the `begin` response, and the chosen password in
`complete`. So against `dash.wayfndr.dev` as deployed, "the first party to see
the secret" means *the first party other than the tunnel provider*. This is not a
new class of exposure — sign-in already crosses it, and the deployment
consciously accepts that — but a design whose entire point is secret custody must
not state the strong claim without the caveat.

If that trade is not acceptable for the TOTP secret specifically, the redemption
page can talk to the CA's own pinned management endpoint rather than through the
tunnel; the dashboard already pins `nodeKey` (`common.nix:52`) for exactly this
kind of connection. That is a deployment decision, not a redesign, and it belongs
in §7.

### 5.2 The rest

- The role travels in the invite and is never client-supplied. No field on either
  redemption request lets a redeemer ask for more than the admin granted.
- **Both redemption requests must be added to `PreAuthLimits`**
  (`transport.rs`) as per-source limiters, alongside the existing enrollment
  limiter for `SubmitCsr` (invoked at `:661-665`). Note while doing so that
  `AuthenticateUser` **has no limiter today at all**, despite already spending
  Argon2id on an unknown username — bounded only by the connection-rate limiter
  and `MAX_UNCREDENTIALED_CONNECTIONS`. Design 13 §3.5 closes that; do
  not close only the new hole and leave the older one open beside it.
- **`CompleteUserRegistration` and `CreateUserInvite` belong on the audit
  allowlist** in `service.rs`, which already carries `CreateUser` with the
  reasoning "Creating an account is creating something that can mint a
  certificate the whole mesh honours. If any request deserves a durable record of
  who asked, it is this one." Completion creates such an account *from an
  anonymous connection*, which is strictly more deserving.
- The token, the handle and the TOTP secret are never logged. Mint, start,
  completion and revocation are `info!` lifecycle events carrying the username
  and the role only.
- An invite grants nothing. It cannot authenticate, holds no certificate, and is
  invisible to anything iterating the user store.

## 6. Migration and versioning

**Wire.** Five request kinds (oneof tags **32-36**; 31 `get_alarms` is the
current highest) and their responses (tags **26-30**; 25 `Alarms` is the current
highest) — unless a request answers
with the shared `Empty`, which `RevokeUserInvite` reasonably could. Purely
additive: an older client never sends them, and an older node answers an unknown
kind as it does today. `buf lint`'s `COMMENTS` rule requires a comment on every
message, field and oneof.

**On disk.** A new persisted collection means a field on `CaLogState`
(`persistence.rs`, `#[derive(Clone)]` for rollback) and on `CaState`, which
requires **bumping `CURRENT_STATE_VERSION` from 5 to 6**, adding a `CaStateV5`
capture of the old shape, and wiring a `migrate_v5_to_v6` into `parse_state` —
mirroring `migrate_v4_to_v5`.
A v5 snapshot migrates forward with an empty invite store. `parse_state` already
refuses a newer-than-known snapshot with a clear message, so a
downgrade fails loudly rather than silently dropping invites.

## 7. Observability

- **`pending_invites` as current-vs-cap**, in the `TableOccupancy` shape. Note
  the cross-design wrinkle honestly: every existing `TableOccupancy` field
  (`wayfinder.proto`) is router-sourced, there is no held-CSR occupancy
  to sit beside, and design 13 is about to move the authority off the router
  loop. So this gauge is CA-sourced and the `add-metric` skill's reference path
  (`GetLinkQualityTable`) does not apply unmodified. Design 13 §7 already argues
  why a CA-sourced metric is legitimate despite the root `CLAUDE.md`'s
  router-owned rule; land that first and follow it.
- **Started-not-completed invites** surfaced in `ListUserInvites`. This is the
  security-relevant signal (§3.6), not the capacity one.
- An alarm when the invite store is at capacity. No new `AlarmKind` is needed —
  `TableSaturation` (`libs/wayfinder-alarm/src/lib.rs`) already means "a
  bounded table is at capacity".

## 8. Alternatives considered

- **Admin creates the account, user changes the password later.** Rejected: does
  not rotate the TOTP secret, so it does not fix the problem it is meant to fix,
  and needs more new machinery than this design (§1).
- **Non-consuming `BeginUserRegistration`.** Rejected — see §3.3. It buys a free
  page refresh and gives back the entire motivating property.
- **Public self-registration into an approval queue.** Rejected: the mint is
  already the approval, and a queue adds a remotely fillable store with the
  squatting and capacity problems `authz.rs` documents for held CSRs.
- **Token in the query string.** Rejected: access logs, `Referer`, and disclosure
  to link unfurlers (§3.5).
- **Let the browser generate the TOTP secret.** Rejected: the server must know it
  to verify codes, so it would be uploaded anyway, and the browser is the less
  trustworthy source of randomness.
- **Mint the TOTP secret at completion rather than at invite.** Rejected, but not
  for the reason it first appears: with a consuming `begin` the security
  properties are equivalent, so this is a simplicity call. Minting at invite
  keeps one record with one lifetime; minting at completion means `begin` has to
  create and persist a secret anyway (the QR must exist before the code can be
  typed), which is the same write in a less obvious place.

## 9. Open decisions for the implementing session

- **Invite TTL default**, and the much shorter **handle TTL**. Suggestion: 24 h
  and 15 min. Both admin-settable at mint; the handle's is what bounds how long a
  started-but-unfinished registration can be resumed.
- **Whether redemption goes through the tunnel or straight to the CA's pinned
  endpoint** (§5.1). This is a deployment trade with a real security difference
  and should be decided deliberately, not inherited from the login page.
- **How the registration page is served** — a route-aware exclusion on the
  `LoggedOut` overlay, or an axum-served page outside the dashboard shell (§3.5).
  Leaning to the latter.
> **Since superseded.** Design 15 made `wayfinderctl user` RPC-only, so
> `user invite` no longer edits the provider's state file and no longer needs
> the provider stopped.

- **`wayfinderctl user invite`** offline, mirroring `user add`. Note the real
  argument for it: `bins/wayfinder-ctl/src/user.rs` requires the provider
  to be **stopped**, so an offline invite must be minted before start-up and
  redeemed after — which is exactly what makes it the only way to create the
  *first admin account* without anyone but its owner ever seeing its TOTP secret.
  That is a stronger reason than parity with `user add`.

## 10. Where it landed

Written as an implementer's checklist and kept as a reader's map. Symbol names
rather than line numbers: this document is filed under `implemented/`, so it is
read long after the lines have moved, and a stale pin misdirects where a name
does not.

| File | What is there |
|---|---|
| `libs/wayfinder-protos/protos/.../wayfinder.proto` | Five request kinds, tags **32-36**. Only three response tags, **26-28**: `RevokeUserInvite` and `CompleteUserRegistration` answer with the shared `Empty` response. |
| `libs/wayfinder-protos/src/service.rs` | The five `WayfinderDataProvider` methods, the request dispatch, both request-name maps, and the **audit allowlist** in `audit_request` — see §5.2. |
| `libs/wayfinder-server/src/users.rs` | `UserInvite`, `InviteStatus`, `generate_invite_secret`, `invite_token_hash`, `registration_handle_hash`, and `UserRecord::from_registration` — the constructor taking an existing secret and a starting `totp_last_step` (§3.4). |
| `libs/wayfinder-server/src/persistence.rs` | The invite collection on `CaLogState` and `CaState`; `CURRENT_STATE_VERSION` 5→6; `CaStateV5` + `migrate_v5_to_v6` in `parse_state`; **`mutate_users_and_invites`**, in the image of `mutate_issued_and_held` and pinned by the same shape of rollback test. |
| `libs/wayfinder-server/src/authority.rs` | `create_user_invite`, `begin_user_registration`, `complete_user_registration`, `revoke_user_invite`, `list_user_invites`, `evict_expired_invites`, and the `invite_is_live` predicate the sweep and the listing share. `MAX_PENDING_INVITES`, `DEFAULT_INVITE_TTL_SECS`, `MAX_INVITE_TTL_SECS`, `REGISTRATION_HANDLE_TTL_SECS`. Invite-aware username checks live in `check_name_available`. |
| `libs/wayfinder-server/src/authz.rs` | **Two** redemption kinds join the enrollment tier in `permits` — `BeginUserRegistration` and `CompleteUserRegistration`; the three admin kinds need a full grant. `every_request_kind()` and its `all.len()` assertions moved 31→36. **Carries the SECURITY ALERT marker — change with care.** |
| `libs/wayfinder-server/src/transport.rs` | One shared per-source limiter covering both redemption kinds, beside `PreAuthLimits`; see §5.2 on `AuthenticateUser`. |
| `libs/wayfinder-server/src/adapter.rs`, `provider.rs` | Trait impls, following `create_user`. |
| `libs/wayfinder-client/src/lib.rs` | Five client methods, following `authenticate_user`. |
| `bins/wayfinder-web/src/api.rs` | The `#[server]` functions, including the two that reach the provider with no session. |
| `bins/wayfinder-web/src/invite.rs` | The view models — `InviteMinted`, `InviteRow`, `InviteListing`, `RegistrationStart`. |
| `bins/wayfinder-web/src/components/register.rs` | The registration page (§3.5). Routed but rendered with the shell's chrome suppressed; `decide_opening` holds the resume-versus-redeem precedence. |
| `bins/wayfinder-web/src/components/provider/accounts.rs` | The Invitations panel beside the create-user form, and `registration_url`. |
| `bins/wayfinder-web/src/mock.rs` | The `mock-node` stand-in the web tests build against. |
| `bins/wayfinder-ctl/src/user.rs` | `user invite`, `user invites`, `user revoke-invite`, beside `Add`. |


Tests come first per the root `CLAUDE.md` and the `tdd` skill. The specifying
cases: a started invite refuses a second `begin` (the §3.3 interlock); a
started-not-completed invite is visible to the admin (§3.6); a wrong TOTP code at
completion creates no account; completion is atomic under a simulated persist
failure (copy `persistence.rs`); the code accepted at completion is refused at
the next login (§3.4); a consumed token is unknown on replay; an expired invite
and an expired handle are each refused; an unknown token is rejected without
spending Argon2id (§4.4); creating an account by another path refuses a name
that is invited (§4.1); a v5 snapshot migrates forward with an empty invite store.

## 11. What landed, and what did not

Implemented: §3 whole, §4 with three stated departures, §5, §6, and the `user
invite` half of §9.

The five open decisions in §9 were closed as follows.

- **TTLs.** 24 h for an invitation, 15 min for a handle, as suggested. Only the
  invitation's is settable at mint (`invite_ttl_secs`, now bounded by
  `MAX_INVITE_TTL_SECS`); the handle's is not — see §11.
- **Redemption goes through the tunnel**, like sign-in. The caveat in §5.1
  therefore stands in full: against `dash.wayfndr.dev` as deployed, "the first
  party to see the secret" means the first party other than Cloudflare. This was
  a deliberate choice and not an inherited one — the alternative is a
  registration-only vhost on a DNS-only name with its own ACME certificate,
  which is real infrastructure work and remains available.
- **The registration page is routed but rendered outside the shell.** Not the
  axum-served page §9 leaned to, and the reason is this crate's own constraint
  rather than a change of mind: `generate_route_list` walks `App` once at
  startup, so `<Routes>` has to stay unconditional or every tab 404s. So
  `/register` is a `<Route>` whose *chrome* — header, tab bar, status strip, and
  the sign-in overlay — is excluded on that path. The property §3.5 asked for is
  the same one: a registrant does not get a dashboard's navigation, and is not
  covered by a sign-in form gated on the state they are in.
- **`wayfinderctl user invite` landed**, with `user invites` and
  `user revoke-invite` beside it so an invitation minted offline can also be
  seen and withdrawn offline.

Three departures from §4, each recorded in the test that covers it.

- **`RemoveUser` does not sweep a matching invitation** (§4.1's last sentence).
  The reservation is bidirectional — a name that is an account cannot be
  invited, and a name that is invited cannot become an account — so the state
  the sweep would reconcile is unreachable, and the code would be untestable
  insurance against it. `revoke_user_invite` is the tool for a pending
  invitation; `remove_user` frees the name for a fresh one.
- **Completion clamps an over-long session lifetime where mint refuses it**
  (§4.6 says "re-clamps" and does not say the two differ). Deliberate: the
  administrator can act on a refusal and is standing in front of it at mint,
  while the registrant can act on nothing, and refusing them would burn their
  invitation for a policy decision they had no part in. The reachable version of
  that drift is `allow_unbounded_cert_ttl` being given back between mint and
  redemption, which is what the test drives.
- **An invitation's own lifetime is capped, which §4 did not ask for.**
  `invite_ttl_secs` was taken verbatim however long the caller asked for, so
  `DEFAULT_INVITE_TTL_SECS`' description of itself as "the bound on how long a
  bearer token sitting in somebody's chat history is worth anything" held only
  while the administrator said nothing — `--invite-ttl 315360000` minted a
  ten-year token. `MAX_INVITE_TTL_SECS` (7 days) makes the bound real, refused
  at mint for the same reason the session lifetime is refused there.

Deferred, each with the reason:

- **§7's observability, in the shape §7 asked for.** There is no
  `pending_invites` gauge on `GetMetrics`. `TableOccupancy` is reported through
  the *router* facet, and design 13's own §6 observability was deferred, so
  there is still no precedent for a CA-sourced metric on that request and adding
  one would mean forking `GetMetrics` across both facets. What landed instead is
  the capacity beside the listing (`ListUserInvitesResponse::capacity`), which
  is the same current-vs-cap signal delivered where an operator is already
  looking — and on the facet that owns it. A real gauge should follow design
  13's observability, not precede it.
- **No `TableSaturation` alarm when the invitation store is full.** The cap
  guards operator error rather than a remote party, and a full store already
  refuses the next mint with a message naming the cap and the remedy. An alarm
  is worth adding alongside the held-CSR one, which does not exist either.
- **The handle TTL is not settable at mint.** §9 asked for both; only the
  invitation's is. Fifteen minutes is a page, a QR code and a six-digit code,
  and no deployment has yet wanted a different number — a request field nobody
  sets is a field that gets set wrong once.
- **No password reset and no TOTP re-enrolment**, as §2 already scoped out. Both
  are natural follow-ups on the same record, and the invitation machinery is
  most of what a re-enrolment would need.
- **The registration page does not render a QR code**, only the `otpauth://`
  URI with a copy button. Every authenticator app accepts a pasted setup link,
  and a QR encoder is a dependency (and a wasm size cost) for a convenience.
  Worth revisiting for phone-only users, who are the audience this whole flow is
  for.
