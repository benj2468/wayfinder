# libs/wayfinder-test

Test-only harness: a `Switch` simulator and `TestRouter` wrapper for multi-node
integration tests over `tokio` mpsc channels (no hardware).

## Testing with a simulated mesh

`TestRouter` pairs a `CentralRouter` with one mpsc egress channel per interface
and serialises outgoing frames automatically:

```rust
let (tx_a, mut rx_a) = mpsc::channel(64);
let mut router = TestRouter::new(Mac([0,0,0,0,0,1]), vec![tx_a]);
router.poll(now).await;            // drive periodic OGMs
router.receive(0, &raw).await;     // feed a received wire frame
router.send_local(Mac([0,0,0,0,0,2]), payload).await?; // inject local data toward node 2
```

For multi-node scenarios, connect several `TestRouter`s through a `Switch`.
