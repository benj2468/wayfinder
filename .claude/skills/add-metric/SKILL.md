---
name: add-metric
description: Use when asked to add a new metric, stat, or gauge to wayfinder's management API — e.g. "expose X through the management API", "add a metric for Y", "surface Z on the TUI". Walks the full wire-to-TUI path so no layer gets skipped, using GetLinkQualityTable as the reference pair to copy the shape of.
---

# Adding a metric end to end

Per CLAUDE.md's Metrics and Observability section: treat "could an operator or
an app on top of the mesh want to observe this?" as a design question, and
wire new metrics through every layer below. Skipping a layer leaves the metric
inaccessible from part of the stack (e.g. queryable by `wayfinderctl` but
invisible in the TUI).

## 0. Decide where the state lives — before writing any code

State for the metric must live in `CentralRouter` (`libs/wayfinder`), the
`no_std` core — never only in `wayfinder-driver`. An embedded node drives the
router directly with no tokio driver loop, so a metric kept only in the driver
would not exist on hardware. The driver may *feed* the router (e.g. calling a
`record_*` method after a physical send/receive) but the counter/estimator and
its accessor belong on the router.

Prefer the existing patterns over a new one:
- A time-decayed EWMA rate (see `RateEstimator`) for anything throughput-like,
  instead of a monotonic total.
- A current-vs-capacity gauge (see `TableOccupancy`) for anything that fills a
  bounded structure.

## 1. Proto request/response

In `libs/wayfinder-protos/protos/wayfinder/v1alpha/wayfinder.proto`, add a
`Get<Thing>Request` / `Get<Thing>Response` pair, following the shape of
`GetLinkQualityTableRequest` (line ~38) / its response (~line 560) and wiring
it into the request/response `oneof`s (see `get_link_quality_table = 3` around
line 190). Every message, field, and enum value needs a `//` doc comment —
`buf lint`'s `COMMENTS` rule enforces this. Run `buf lint` from
`libs/wayfinder-protos/` to check.

## 2. WayfinderDataProvider + dispatch

In `libs/wayfinder-protos/src/service.rs`:
- Add a method to `pub trait WayfinderDataProvider` (starts at line 180),
  returning an intermediate `*Data` type (plain Rust struct, not the prost
  type) — follow the existing methods like `link_quality_table(&self) ->
  Vec<LinkQualityEntryData>`.
- Add the request-kind match arm in `WayfinderService::handle` (the impl
  starting ~line 282) that calls the new provider method and builds the
  response.

## 3. RouterAdapter projection

In `libs/wayfinder-server/src/adapter.rs`, implement the new
`WayfinderDataProvider` method on `RouterAdapter` by reading off the
`CentralRouter` state from step 0. `RouterAdapter::new` is handed the router's
monotonic `now`, so evaluate anything time-varying (a rate, an uptime) at that
instant rather than caching it — an idle interface should read as a decaying
rate, not a stale one.

## 4. Client method

Add a method to `libs/wayfinder-client/src/lib.rs` (alongside e.g.
`link_quality_table`) that sends the new request and unwraps the typed
response.

## 5. TUI panel

In `bins/wayfinder-tui/src/ui.rs`, add a row/panel under `render_metrics`
(alongside `render_throughput_chart` / `render_node_metrics`), reading the new
field off the `Snapshot`/`App` state defined in `bins/wayfinder-tui/src/app.rs`
— add the fetch to wherever that snapshot gets refreshed.

## 6. Extend the end-to-end smoke test

The real over-the-wire test lives in `bins/wayfinder-ctl/tests/query.rs`, not
in `wayfinder-tui` (CLAUDE.md's wording there is imprecise about which crate
owns it). It spins up a real authenticated `serve_tls_server` via the
`spawn_server()` helper against a `Mock: WayfinderDataProvider`, and
`spawn_server()` returns an `Endpoint` the client bootstraps against. To extend:
1. Add the new field/method to `Mock`'s impl with a distinctive test value.
2. Add a `#[tokio::test]` that calls `spawn_server()`, issues the new query via
   `run_query(cmd, &endpoint, output)`, and asserts on the rendered JSON and
   human output — mirroring
   `node_info_query_renders_json_from_server` /
   `node_info_query_renders_human_from_server`.

## 7. Unit tests on the router state itself

Per the TDD/unit-test conventions (see the `tdd` skill), the new estimator or
gauge on `CentralRouter` needs its own `#[cfg(test)]` unit tests — edge cases
(zero, empty, at-capacity) — independent of the end-to-end smoke test above.
