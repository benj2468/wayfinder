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
matters: `.proto` first, then the `Data` struct + `WayfinderDataProvider`
method, then the `handle` arm, then `RouterAdapter` in `wayfinder-server`, then
the client and TUI. Skipping a layer compiles fine in the crates below it and
fails at the adapter.

## Mutation classification is audit-only

`request_is_mutation` tags a request kind as a write, and its **only** consumer
is the `info!` audit line in `handle`. It is not an authorization gate.

Authorization is **connection-level**, decided once: `wayfinder-server`'s
transport runs `decide_access` after the TLS handshake and either admits or
refuses the whole connection (`transport.rs`). An admitted client may invoke
every request kind. So adding a mutating request does not require an authz
change — but do add it to `request_is_mutation` (and to
`request_is_mutation_classifies_writes_vs_reads`) or the write lands with no
audit trail.

If per-request privilege ever becomes a requirement, this function is the
natural seam — but today, do not read it as one.
