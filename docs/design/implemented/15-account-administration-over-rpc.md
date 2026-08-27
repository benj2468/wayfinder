# 15 — Account administration over RPC

**Status:** Implemented — `wayfinderctl user` is RPC-only; the offline
state-file path is deleted.

## Scope

`libs/wayfinder-protos` (three new requests), `libs/wayfinder-server`
(`authority.rs`, `authority_task.rs`, `provider.rs`, `authz.rs`),
`libs/wayfinder-client`, `bins/wayfinder-ctl` (`user.rs` rewritten),
`scripts/topology.py`.

Not touched: the user store's on-disk schema, `UserRecord`, the sign-in path,
`bins/wayfinder-web` (which already drove the account RPCs it had, and can adopt
the three new ones separately).

## Motivation

`wayfinderctl user` administered accounts by opening the provider's CA state
file directly. Three of its mutations — role change, password reset,
disable/enable — existed *only* there, with no RPC equivalent at all.

That is not a second way to do the same thing. It is a second writer to a file
with one owner, and the two do not merge:

- A provider loads the whole CA snapshot at startup (`CaLog::load`, called only
  from `CertAuthority::from_config`) and rewrites it **whole**, from memory, on
  every login, issuance and revocation (`Persisted::mutate`).
- The offline tool did exactly the same thing from the other side.

So whoever wrote last won the entire file, not the section they edited:

| order | outcome |
| --- | --- |
| CLI writes, then provider persists | the role change is silently discarded |
| provider persists, then CLI writes | the provider's **issued-certificate log** reverts to whatever it was when the CLI read the file — dropping records its impersonation guard and revocation checks depend on |

`DurableStore`'s guarantee does not cover this and never claimed to: it promises
a reader never observes a torn old/new mix, i.e. atomicity of *one* write. It
says nothing about two writers, or about staleness. Neither outcome is visible
to the operator who ran the command; the module's answer was a docstring telling
them to stop the provider first.

## Goals / non-goals

**Goals.** Every interaction with a provider's user store — read and write — is
a management-API request. No host-side tool reads or writes `ca-state.json`.
Nothing routine requires the provider to be stopped.

**Non-goals.** Self-service password change (needs the *old* password and a
different threat model). Replacing an account's second factor over the API —
see security considerations. Any change to the sign-in path or to what a session
certificate carries.

## Design

### The three missing requests

`SetUserRole`, `SetUserEnabled`, `SetUserPassword`, alongside the `ListUsers` /
`CreateUser` / `RemoveUser` / `RevokeUserSessions` / invite trio that already
existed. All three are `RequestFacet::Authority`, `Audited::Mutation`, admin
tier only, and refused for the viewer tier by the closed allowlist in
`authz.rs`.

**A demotion revokes the account's live sessions, in the same durable write as
the role change.** This is the whole reason the RPC is better than the file, not
merely safer: the capability is stamped on the certificate, not read from the
account per request, so a session minted while the account was an administrator
goes on administering until it is revoked or expires. The offline path could not
revoke — a revocation has to be *flooded*, and there is no router beside a CLI
process — so the best it could ever do was print the MACs it was leaving live.
Design 14 closed exactly this gap for `RemoveUser`; leaving it open for a role
change is the same bug one request along.

Disabling revokes for the same reason: an account that obtains no *new* session
while everything it already holds keeps working is disabled only in the future
tense.

Promoting and enabling revoke nothing — the certificates such an account holds
grant *less* than the account now does, which costs its holder one sign-in and
nobody any access.

`SetUserPassword` revokes nothing, deliberately. A forgotten password is the
common case, and ending every device its owner is signed in on is a larger act
than was asked for; when the reset answers a compromise,
`RevokeUserSessions` is the request that says so.

### Breaking the bootstrap loop without a file

The first account cannot be created *by an account*: creating one needs the
credential it creates. That loop is what justified an offline tool.

It is broken from the other side. Whoever runs this is on the provider host —
that was always the requirement — and the host holds the node's own identity
seed. A client presenting that seed authenticates at `MgmtAccess::GrantedSelfKey`,
which `permits` admits to **every** request:

```
wayfinderctl user add --identity /var/lib/wayfinder/identity.seed \
    --username rowan --admin
```

The same credential is the way back from a mesh whose last administrator was
removed: it depends on no account existing. An offline-issued admin certificate
(`cert issue --admin`) is a second route, and is the one `scripts/topology.py`
uses.

### The last-administrator guard covers three acts, not one

`MeshAuthority::remove_user` refused to remove the last enabled administrator.
Demoting or disabling that account strands the same mesh — one whose user store
no ordinary session can change in either direction, since every request that
could needs a full management grant. The check moved into
`CertAuthority::refuse_to_strand_the_mesh(username, act)` and all three call it,
each *before* signing anything, so a refusal has revoked nothing.

A guard on removal alone was a locked front door beside an open window.

### Layering

The split the existing code already drew is kept: `CertAuthority`'s inherent
`set_user_role_revoking_sessions` / `set_user_enabled_revoking_sessions` are the
raw acts with no policy, and the `MeshAuthority` trait methods are the guarded
ones. `AuthorityAdapter` names the trait method explicitly
(`MeshAuthority::set_user_role(ca, ..)`), because an inherent method wins method
resolution over a trait one and the two share a prefix — the mistake
`authority_task.rs` already documents having made once with `remove_user`.

`AuthorityAdapter::gated_session_revocation` gates on the router's ability to
flood, but it keys on whether the *account* holds live sessions — the right
question only when the act itself revokes. Promotion and enable therefore go
through a new `keep()` helper instead: gating them would refuse an act that
signs nothing, on a node that merely cannot announce nothing.

## Correctness argument / edge cases

- **The change and its revocations cannot durably split.** Both go through one
  `CaLog::mutate_users_and_issued` call, as `remove_user_revoking_sessions`
  does. The direction that matters is a demotion recorded whose admin sessions
  came back un-revoked.
- **Restating a role or status is a success that writes and revokes nothing.**
  The second call is what an operator makes when unsure the first landed; it
  must not cut off a session on the way through. Reported as `unchanged` so the
  operator is not shown a change that did not happen.
- **An unknown name is an error, not a silent success** — on all three, and the
  error has one author (the store), so the CLI's "already in that role" check
  falls through to the real call rather than inventing its own refusal.
- **A refused act signs nothing**, so the account it declined to touch keeps the
  sessions it holds. Asserted directly in
  `stranding_the_mesh_by_demoting_or_disabling_the_last_admin_is_refused`.

## Security considerations

- **The second factor is untouched by a password reset.** An operator able to
  replace both could take an account over in one request and leave its owner no
  signal. Whoever needs a fresh factor gets a fresh invite, which reveals the
  secret only to its redeemer.
- **The self-key tier is not a new grant.** It already admitted every request;
  this change relies on it rather than widening it. What it means in practice is
  that shell access to the provider host is administrative access to the mesh —
  which was equally true when that shell could edit `ca-state.json`, and is now
  auditable, because every act goes through `audit_request`.
- **The three new requests are audited as mutations**, and the record names the
  request kind and never its fields, so `SetUserPassword`'s password is never in
  a log.

## Alternatives considered

- **Keep the offline path and add an advisory `flock` on the state file**, held
  by the provider for its lifetime, so the CLI refuses while it is running.
  Fixes the corruption but not the split: three mutations would still be
  reachable only by stopping the provider, and a demotion still could not revoke.
  Rejected once the self-key tier made the offline path unnecessary outright —
  a lock is the right answer only if something must still write that file.
- **Keep the offline path for bootstrap and recovery alone.** The two cases that
  seemed to require it are precisely the two the self-key credential covers, so
  what remained would have been a dangerous path kept for no case at all.
- **Have a demotion report its live admin sessions instead of revoking them**,
  leaving `RevokeUserSessions` as a follow-up. Rejected: it is design 14's
  mistake restated, and the follow-up is the step that gets skipped.

## Key file map

- `libs/wayfinder-protos/protos/wayfinder/v1alpha/wayfinder.proto` — requests
  38–40, responses 30–31.
- `libs/wayfinder-protos/src/service.rs` — `AuthorityDataProvider` methods,
  dispatch arms, `set_user_role_reporting_change` /
  `set_user_enabled_reporting_change`, and the three classification matches.
- `libs/wayfinder-server/src/authority.rs` — the raw acts,
  `refuse_to_strand_the_mesh`, and the `MeshAuthority` methods.
- `libs/wayfinder-server/src/authority_task.rs` — `keep`, and the adapter
  bridge.
- `libs/wayfinder-server/src/authz.rs` — the sweep list (now 40) and the viewer
  refusal list.
- `bins/wayfinder-ctl/src/user.rs` — rewritten; no `--state` flag exists.
- `bins/wayfinder-ctl/tests/provider/mod.rs` — the in-process provider, shared
  with `enroll.rs`, whose mutations run through a real `AuthorityAdapter`.
- `scripts/topology.py` — `make_accounts` runs after `docker compose up`,
  against the provider's API.
