# libs/wayfinder-protos

The management-API wire protocol: `prost`-generated types for the
`wayfinder.v1alpha` package, plus the `WayfinderDataProvider` trait and request
dispatch built on them. `no_std` + `alloc`; the `serde` feature adds JSON
serialization for `wayfinderctl`.

## Layout

- `protos/wayfinder/v1alpha/wayfinder.proto` — the single source of truth.
- `build.rs` — compiles it with `prost` into `OUT_DIR`, included by
  `wayfinder::v1alpha`. Two non-default choices live here: `btree_map(["."])`
  (deterministic map iteration, so responses are stable across runs) and a
  feature-gated `#[cfg_attr(feature = "serde", derive(serde::Serialize))]` on
  every generated type.
- `src/service.rs` — the hand-written half: `*Data` structs, the
  `WayfinderDataProvider` trait, and `WayfinderService::handle`.

## The `Data` / proto type split

`service.rs` defines a parallel `…Data` struct for most wire messages
(`RoutingEntryData`, `NodeMetricsData`, `LogRecordData`, …). This is deliberate:
`WayfinderDataProvider` is implemented by `RouterAdapter` in `wayfinder-server`
against a `no_std` router, and the `Data` types are the allocation-light shape
that layer speaks. `handle` is what converts `Data` → generated proto message.

So a new metric touches **both**: a `Data` struct/trait method here, and the
`.proto` message. They are not redundant — but they must stay in step.

## Every field needs a comment

`buf lint` enforces the `COMMENTS` rule — every message, field, `oneof`, enum,
and enum value. Run it from this directory:

```bash
cd libs/wayfinder-protos && buf lint
```

`buf.yaml` excepts only `COMMENT_FIELD`, and only because a handful of empty
marker request messages have self-documenting names. Do not widen that list to
silence a lint; write the comment.

`breaking: FILE` is configured — this is a `v1alpha` package, but the intent is
that wire changes are noticed, not that they're free.

## Adding a request/response

Prefer the `add-metric` skill, which walks the whole path. The ordering that
matters: `.proto` first, then **the `rpc_table!` entry in [`rpc.rs`](src/rpc.rs)**,
then the `Data` struct + the `RouterReads`/`RouterWrites`/`AuthorityDataProvider`
method, then the dispatcher arm, then `RouterAdapter`/`RouterView` in
`wayfinder-server`, then the client and TUI. Skipping a layer compiles fine in
the crates below it and fails at the adapter.

The table entry is not optional and cannot be deferred: the five classifiers it
generates are exhaustive matches, so a proto variant with no entry does not
compile. Its five fields each force a decision — the owner that answers it
(`RouterRead`/`RouterWrite`/`Authority`/`Transport`), its audit class, the
access tiers admitted, and the anonymous rate-limit bucket it spends.

Two of those are worth extra care because getting them wrong is quiet rather
than loud. `owner:` decides whether a read is served off the driver's event
loop or forwarded to it — a read mis-declared `RouterWrite` still works, just
slowly, forever. And `limit:` is declared independently of `access:`, so a
request reachable with no credential can be left unmetered. Both are pinned by
sweeps in `wayfinder-server` (`the_read_facet_and_the_read_dispatcher_agree_on_every_kind`,
`every_request_spends_the_bucket_its_flow_was_sized_for`); if you are adding a
kind, expect to touch them.

## Audit classification is audit-only

`audited` tags a request kind as a write (`Mutation`), a read that hands out a
secret (`Disclosure`), or an ordinary read (`Query`), and its **only** consumer
is the `info!` audit line in `audit_request`. It is not an authorization gate.

It is declared in [`rpc.rs`](src/rpc.rs)'s `rpc_table!` alongside the request's
owner, access tiers and rate-limit bucket, rather than in a `match` of its own —
see the table's header for why all five live together.

`Disclosure` exists because `RevealEnrollmentToken` changes nothing and still
deserves a record: an operator asking "who learned the enrollment token, and
when?" has nowhere else to look. Do not fold it into `Mutation` — a log line
calling a read a mutation is a lie about what happened.

**Adding a request kind now requires an explicit authorization decision, and
there is no default.** This paragraph used to say the opposite — that a client
on either full grant could invoke everything, so a new mutating request needed
no authz change. That was true, and it was the bug: `authz::permits` classified
requests with `matches!` arms that had an implicit catch-all, so a new kind
silently became permitted for admin and self-key and refused for viewer and
enrollment. `SetUserRole`, `SetUserEnabled` and `SetUserPassword` all reached
the proto that way.

Every request's tiers are now declared in [`rpc.rs`](src/rpc.rs)'s `rpc_table!`,
and `access:` is a required field — an entry without one does not parse.
`authz::permits` is only the join between that declaration and the tier a
connection earned.

Admission is still per-connection (`decide_access` after the TLS handshake,
admitting or refusing the whole connection), and the enrollment tier is still
the one a client with no membership certificate lands in. What changed is that
"which tiers may invoke this request" is no longer answered by omission.
