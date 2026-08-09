# libs/wayfinder-test

Test-only harness: a `Switch` fabric plus per-node routers for multi-node
integration tests, no hardware. **Synchronous** — the caller owns the clock.

## Two routers, deliberately

| | driver | used by |
|---|---|---|
| `TestRouter` (`test_router.rs`) | `wayfinder-tick-driver`, synchronous | `integration_tests.rs` (63 tests) via `TestHarness` |
| `LinkTestRouter` (`link_router.rs`) | `wayfinder-driver`, async | `link_error_tests.rs`, `rylr998_integration_tests.rs` |

The split is the point. Routing behaviour — convergence, split-horizon,
failover, auth, multicast — has nothing to do with links, so it is tested
synchronously against plain queues. **Link *plumbing*** — `send`/`recv` error
policy, a real `RylrClient` over a simulated LoRa medium — needs an actual
`LinkT`, which the tick driver does not have (its interfaces *are* queues). So
those two suites keep the async driver, and are consequently what keeps
`wayfinder-driver`'s link handling covered.

Put a new test in `integration_tests.rs` unless it is specifically about a
`LinkT` implementation or the driver's I/O error posture.

## How a step works

`TestRouter::step(now)` is three explicit moves, all synchronous:

1. **pump in** — everything the switch queued on each port → `Driver::push_rx`
2. **tick** — `Driver::tick_schedules(now, ..)`, the shared `driver-core` logic
3. **pump out** — `Driver::poll_egress` → the switch ports; `poll_local` →
   `local_deliveries()`

`TestHarness::tick()` then steps every node and lets every `Switch` forward what
landed on the wire, returning the frame count it moved — `0` means quiescent,
which is what `settle()` waits for.

## Driving the two schedules separately

`poll_due` runs **only** the OGM schedule and `poll_due_keepalive` **only** the
keep-alive one, mirroring the async driver's split. That is not cosmetic: it is
how a test injects "this node's keep-alives stopped while its OGMs keep
flowing", which is exactly what
`real_keepalive_tick_switches_route_when_it_stops` needs. Collapsing them into
one `step` makes that fault unrepresentable — and silently passes the test for
the wrong reason.

`TestHarness::tick()` uses neither (`step_schedules(now, false, false)`): a tick
only *moves* frames already in flight, so periodic rounds stay under the test's
explicit control.

## Clock

There is no wall clock and no executor. `TestHarness::clock` is a virtual
`Duration` the test advances; `converge`/`settle`/`advance_trickle` are bounded
by sweep counts (`MAX_SWEEPS`), not timeouts, so a forwarding loop fails with a
diagnostic instead of hanging — and fails identically on a fast or slow machine.

Tests are plain `#[test]`. If you find yourself reaching for `#[tokio::test]`,
you are probably in the wrong one of the two routers above.

## Writing a test

```rust
let mut config = TestConfig::default();
config.switches.push(TestSwitchConfig { name: "lan".into() });
// … machines, each with links naming a switch …
let mut harness = config.validate().unwrap();

harness.converge(Duration::from_secs(1));          // one OGM round, then settle
harness.get_machine_mut("a").send_local(dest, b"hi");
harness.settle();                                   // let it reach the far side
assert!(harness.get_machine("b").local_deliveries().contains(&expected));
```
