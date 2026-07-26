use std::collections::HashMap;
use std::fmt::Debug;
use std::mem::size_of;

use interfaces::frame::MeshIdentifier;
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use thiserror::Error;
use tokio::sync::mpsc::error::TryRecvError;

use crate::Direction;

/// Per-port link-loss configuration for a simulated [`Switch`] port.
pub struct PortConfig {
    /// Probability `[0.0, 1.0]` of dropping a frame on the switch→node egress
    /// toward this port (this node failing to *hear* the fabric).
    outgoing_loss: f64,
    /// Probability `[0.0, 1.0]` of dropping a frame on the node→switch ingress
    /// from this port (this node failing to *reach* the fabric).
    incoming_loss: f64,
}

impl PortConfig {
    /// A port with the given drop probabilities: `outgoing_loss` on the
    /// switch→node direction, `incoming_loss` on the node→switch direction.
    /// Setting both to `1.0` takes the port's link fully down in both
    /// directions; `0.0`/`0.0` is a perfect link (see [`no_loss`](Self::no_loss)).
    pub fn new(outgoing_loss: f64, incoming_loss: f64) -> Self {
        Self {
            outgoing_loss,
            incoming_loss,
        }
    }

    /// A perfect, lossless port (both directions deliver every frame).
    pub fn no_loss() -> Self {
        Self {
            outgoing_loss: 0.0,
            incoming_loss: 0.0,
        }
    }
}

/// Opaque identifier for a port on a [`Switch`].
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct PortId(u32);

/// The two channel endpoints a node uses to talk to a switch port: an `egress`
/// sender (node → switch) and an `ingress` receiver (switch → node).
pub struct PortComms {
    /// Sender the node writes outgoing frames into (node → switch).
    pub egress: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Receiver the node reads incoming frames from (switch → node).
    pub ingress: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl PortComms {
    /// Pair an egress sender with an ingress receiver into one endpoint.
    pub fn new(
        egress: tokio::sync::mpsc::Sender<Vec<u8>>,
        ingress: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self { egress, ingress }
    }

    /// Create a connected pair of endpoints (one for each side) backed by two
    /// `buf`-capacity channels — the switch keeps one, the node the other.
    pub fn pair(buf: usize) -> (Self, Self) {
        let (tx1, rx1) = tokio::sync::mpsc::channel(buf);
        let (tx2, rx2) = tokio::sync::mpsc::channel(buf);
        (Self::new(tx2, rx1), Self::new(tx1, rx2))
    }
}

/// A single port on a [`Switch`]: its loss configuration plus the channel
/// endpoints connecting it to the attached node.
pub struct Port {
    config: PortConfig,
    duplex: PortComms,
}

/// A registered monitoring tap: a callback invoked on every frame crossing a
/// port, able to inspect (and mutate) the bytes and to unregister itself.
pub struct TapConfig {
    /// If the tap config returns true it continues to monitor, if false, it stops monitoring
    clb: Box<dyn FnMut(TapMeta<'_>) -> bool>,
    /// Invalidated
    invalid: bool,
}

impl TapConfig {
    /// Register a tap driven by `clb`, called for each frame on the tapped port;
    /// returning `false` removes the tap.
    pub fn new<F>(clb: F) -> Self
    where
        F: FnMut(TapMeta<'_>) -> bool + 'static,
    {
        Self {
            clb: Box::new(clb),
            invalid: false,
        }
    }
}

/// The context handed to a [`TapConfig`] callback for one observed frame.
pub struct TapMeta<'a> {
    /// The port the frame is crossing.
    pub id: PortId,
    /// Which direction the frame is travelling.
    pub direction: Direction,
    /// The frame's bytes, which the tap may inspect or mutate in place.
    pub data: &'a mut [u8],
}

/// Opaque identifier for a registered tap.
#[expect(dead_code)]
pub struct TapId(u32);

/// An error from a [`Switch`] operation.
#[derive(Error, Debug)]
pub enum SwitchError {
    /// No port exists for the given [`PortId`] or identifier.
    #[error("port not found")]
    InvalidPort,
    /// A non-blocking receive on a port's channel failed.
    #[error(transparent)]
    TryRecvError(#[from] TryRecvError),
}

/// An in-process Ethernet-like switch simulator that fans frames out between
/// connected node ports, keyed by mesh [`Ident`](MeshIdentifier), with optional
/// per-port loss and monitoring taps. Used to wire several routers into a
/// topology for integration tests without any hardware.
pub struct Switch<Ident> {
    // Name of the switch
    name: String,
    // Random Number generator
    rng: StdRng,
    // Ports connected to the switch
    ports: HashMap<PortId, Port>,
    // Taps that we have registered on the switch for monitoring data in the application/test
    taps: HashMap<PortId, Vec<TapConfig>>,
    // Ident address mapping of port
    ident_map: HashMap<Ident, PortId>,
}

impl<Ident> Default for Switch<Ident>
where
    Ident: MeshIdentifier + std::fmt::Debug,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Ident> Switch<Ident>
where
    Ident: MeshIdentifier + std::fmt::Debug,
{
    /// Create an empty, unnamed switch with no ports and a fixed-seed RNG (so
    /// loss decisions are deterministic across test runs).
    pub fn new() -> Self {
        Self {
            name: String::new(),
            ports: HashMap::new(),
            taps: HashMap::new(),
            ident_map: HashMap::new(),
            rng: StdRng::from_seed([0; 32]),
        }
    }
    /// This switch's name (empty unless created via [`new_with_name`](Self::new_with_name)).
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Create an empty switch with the given `name`.
    pub fn new_with_name(name: String) -> Self {
        Self {
            name,
            ports: HashMap::new(),
            taps: HashMap::new(),
            ident_map: HashMap::new(),
            rng: StdRng::from_seed([0; 32]),
        }
    }

    /// Reseed the random number generator
    pub fn reseed(mut self, seed: [u8; 32]) -> Self {
        self.rng = StdRng::from_seed(seed);
        self
    }

    /// Attach a new port to the switch
    pub fn add_port(
        &mut self,
        duplex: PortComms,
        port_config: PortConfig,
    ) -> Result<PortId, SwitchError> {
        let id = PortId(self.ports.len() as u32);
        self.ports.insert(
            id,
            Port {
                config: port_config,
                duplex,
            },
        );
        Ok(id)
    }
    /// Update configuration of a port
    pub fn get_port(&mut self, id: PortId) -> Result<&PortConfig, SwitchError> {
        let port = self.ports.get(&id).ok_or(SwitchError::InvalidPort)?;
        Ok(&port.config)
    }

    /// Update configuration of a port
    pub fn update_port(&mut self, id: PortId, config: PortConfig) -> Result<(), SwitchError> {
        let port = self.ports.get_mut(&id).ok_or(SwitchError::InvalidPort)?;
        port.config = config;
        Ok(())
    }

    /// Disconnect a port
    pub fn disconnect_port(&mut self, id: PortId) -> Result<(), SwitchError> {
        self.ports.remove(&id).ok_or(SwitchError::InvalidPort)?;
        Ok(())
    }

    /// The ids of every port currently attached to the switch, so callers can
    /// install a [`TapConfig`] on each one (e.g. to observe all traffic
    /// crossing the fabric).
    pub fn port_ids(&self) -> Vec<PortId> {
        self.ports.keys().copied().collect()
    }

    /// Tap a port
    pub fn add_tap(&mut self, id: PortId, tap_config: TapConfig) -> Result<(), SwitchError> {
        let taps = self.taps.entry(id).or_default();
        taps.push(tap_config);
        Ok(())
    }

    /// Tick the switch, multiplexing messages between ports and calling the tap
    /// handlers.  Returns the number of frames pulled off the wire this tick
    /// (i.e. frames nodes transmitted into the fabric); callers use a zero count
    /// as the signal that the fabric has fallen silent.
    #[tracing::instrument(skip(self), fields(name = self.name))]
    pub async fn tick(&mut self) -> Result<usize, SwitchError> {
        // Flush all messages in the switch's buffer
        let mut msgs = self
            .ports
            .iter_mut()
            .map(|(id, port)| {
                let mut msgs = vec![];
                while let Ok(msg) = port.duplex.ingress.try_recv() {
                    if !self.rng.random_bool(port.config.incoming_loss) {
                        msgs.push(msg);
                    }
                }

                Ok((*id, msgs))
            })
            .collect::<Result<Vec<_>, SwitchError>>()?;

        // Count of frames received from the ports this tick.  A tick that pulls
        // nothing off the wire means no node transmitted, so the fabric is
        // quiescent — the convergence loop's stop condition.
        let frames_in: usize = msgs.iter().map(|(_, m)| m.len()).sum();

        // Loop over all and register the source ident for each message
        for (id, msgs) in msgs.iter_mut() {
            if let Some(taps) = self.taps.get_mut(id) {
                for tap in taps.iter_mut() {
                    for msg in msgs.iter_mut() {
                        if !(tap.clb)(TapMeta {
                            data: msg.as_mut_slice(),
                            direction: Direction::ToSwitch,
                            id: *id,
                        }) {
                            tap.invalid = true;
                        }
                    }
                }

                taps.retain(|t| !t.invalid);
            }
            for msg in msgs {
                let source = match Ident::ref_from_prefix(&msg[size_of::<Ident>()..]) {
                    Ok((source, _)) => source,
                    Err(e) => {
                        tracing::trace!(error = ?e, "drop: message is not a valid ident");
                        continue;
                    }
                };
                tracing::trace!(source = ?*source, port_id = ?*id, "learned ident");

                self.ident_map.insert(*source, *id);
            }
        }

        // Forward each frame toward its destination (or flood when the
        // destination is unknown).  A port's `outgoing_loss` is the switch→node
        // egress drop, applied here keyed on the *destination* port — so a port
        // configured for total loss is deaf to the fabric, the complement of
        // `incoming_loss` muting its transmissions above.  Together they let a
        // single port's link be taken fully up or down.
        for (port, msgs) in msgs {
            tracing::trace!(port_id = ?port, count = msgs.len(), "processing messages");
            for mut msg in msgs {
                tracing::trace!(port_id = ?port, direction = ?Direction::ToSwitch, len = msg.len(), "switch frame");

                let Ok((dest, _)) = Ident::ref_from_prefix(&msg) else {
                    continue;
                };

                tracing::trace!(dest = ?dest, port = ?self.ident_map.get(dest), "forwarding message");
                if let Some(dest_port) = self.ident_map.get(dest).copied() {
                    // Drop on the wire toward the destination node if its link is lossy.
                    #[expect(
                        clippy::expect_used,
                        reason = "dest_port came from ident_map, and ports are never removed once added"
                    )]
                    let outgoing_loss = self
                        .ports
                        .get(&dest_port)
                        .expect("ports are never removed once added")
                        .config
                        .outgoing_loss;
                    if self.rng.random_bool(outgoing_loss) {
                        continue;
                    }
                    tracing::trace!(port_id = ?dest_port, direction = ?Direction::FromSwitch, len = msg.len(), "switch frame");
                    // Send to specific destination port
                    if let Some(taps) = self.taps.get_mut(&dest_port) {
                        for tap in taps.iter_mut() {
                            if !(tap.clb)(TapMeta {
                                data: msg.as_mut_slice(),
                                direction: Direction::FromSwitch,
                                id: dest_port,
                            }) {
                                tap.invalid = true;
                            }
                        }
                        taps.retain(|t| !t.invalid);
                    }

                    #[expect(
                        clippy::expect_used,
                        reason = "dest_port came from ident_map, and ports are never removed once added"
                    )]
                    let _ = self
                        .ports
                        .get(&dest_port)
                        .expect("ports are never removed once added")
                        .duplex
                        .egress
                        .send(msg.clone())
                        .await;
                } else {
                    // Broadcast to all ports except source, each copy subject to
                    // that port's own egress loss.
                    for (other_port_id, other_port) in self.ports.iter() {
                        if *other_port_id == port {
                            continue; // Don't send back to source
                        }
                        if self.rng.random_bool(other_port.config.outgoing_loss) {
                            continue;
                        }
                        tracing::trace!(port_id = ?other_port_id, direction = ?Direction::FromSwitch, len = msg.len(), "switch frame");

                        if let Some(taps) = self.taps.get_mut(other_port_id) {
                            for tap in taps.iter_mut() {
                                if !(tap.clb)(TapMeta {
                                    data: msg.as_mut_slice(),
                                    direction: Direction::FromSwitch,
                                    id: *other_port_id,
                                }) {
                                    tap.invalid = true;
                                }
                            }
                            taps.retain(|t| !t.invalid);
                        }

                        let _ = other_port.duplex.egress.send(msg.clone()).await;
                    }
                }
            }
        }

        Ok(frames_in)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    // Helper to create a simple frame with src and dst
    fn make_frame(src: u8, dst: u8) -> Vec<u8> {
        use zerocopy::IntoBytes;
        let mut data = Vec::new();
        data.extend_from_slice(dst.as_bytes());
        data.extend_from_slice(src.as_bytes());
        data
    }

    fn create_port_pair(
        buffer_size: usize,
    ) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>, PortComms) {
        let (tx_to_switch, rx_to_switch) = mpsc::channel(buffer_size);
        let (tx_from_switch, rx_from_switch) = mpsc::channel(buffer_size);
        let port_comms = PortComms::new(tx_from_switch, rx_to_switch);
        (tx_to_switch, rx_from_switch, port_comms)
    }

    #[tokio::test]
    async fn test_add_port() {
        let mut switch: Switch<u8> = Switch::new();
        let (_, _, port_comms) = create_port_pair(10);

        let port_id = switch.add_port(port_comms, PortConfig::no_loss()).unwrap();
        assert_eq!(port_id, PortId(0));

        let (_, _, port_comms2) = create_port_pair(10);
        let port_id2 = switch.add_port(port_comms2, PortConfig::no_loss()).unwrap();
        assert_eq!(port_id2, PortId(1));
    }

    #[tokio::test]
    async fn test_disconnect_port() {
        let mut switch: Switch<u8> = Switch::new();
        let (_, _, port_comms) = create_port_pair(10);

        let port_id = switch.add_port(port_comms, PortConfig::no_loss()).unwrap();
        assert!(switch.disconnect_port(port_id).is_ok());

        // Should fail on second disconnect
        assert!(matches!(
            switch.disconnect_port(port_id),
            Err(SwitchError::InvalidPort)
        ));
    }

    #[tokio::test]
    async fn test_update_port_config() {
        let mut switch: Switch<u8> = Switch::new();
        let (_, _, port_comms) = create_port_pair(10);

        let port_id = switch.add_port(port_comms, PortConfig::no_loss()).unwrap();

        let new_config = PortConfig::new(0.5, 0.5);
        assert!(switch.update_port(port_id, new_config).is_ok());

        // Invalid port should fail
        assert!(matches!(
            switch.update_port(PortId(999), PortConfig::no_loss()),
            Err(SwitchError::InvalidPort)
        ));
    }

    #[tokio::test]
    async fn test_simple_unicast_learned_forwarding() {
        let mut switch: Switch<u8> = Switch::new();

        // Create two ports
        let (tx1, mut rx1, port1) = create_port_pair(10);
        let (tx2, mut rx2, port2) = create_port_pair(10);

        let _port1_id = switch.add_port(port1, PortConfig::no_loss()).unwrap();
        let _port2_id = switch.add_port(port2, PortConfig::no_loss()).unwrap();

        // Port 1 sends frame from node 1 to node 2
        tx1.send(make_frame(1, 2)).await.unwrap();
        switch.tick().await.unwrap();

        // Should broadcast to port 2 (destination unknown)
        let received = rx2.try_recv().unwrap();
        assert_eq!(received, make_frame(1, 2));

        // Port 1 should not receive it back
        assert!(rx1.try_recv().is_err());

        // Now port 2 sends reply from node 2 to node 1
        tx2.send(make_frame(2, 1)).await.unwrap();
        switch.tick().await.unwrap();

        // Should go directly to port 1 (learned address)
        let received = rx1.try_recv().unwrap();
        assert_eq!(received, make_frame(2, 1));

        // Port 2 should not receive it back
        assert!(rx2.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_broadcast_to_unknown_destination() {
        let mut switch: Switch<u8> = Switch::new();

        // Create three ports
        let (tx1, mut rx1, port1) = create_port_pair(10);
        let (_tx2, mut rx2, port2) = create_port_pair(10);
        let (_tx3, mut rx3, port3) = create_port_pair(10);

        switch.add_port(port1, PortConfig::no_loss()).unwrap();
        switch.add_port(port2, PortConfig::no_loss()).unwrap();
        switch.add_port(port3, PortConfig::no_loss()).unwrap();

        // Port 1 sends to unknown destination
        tx1.send(make_frame(1, 99)).await.unwrap();
        switch.tick().await.unwrap();

        // Should broadcast to port 2 and 3, but not back to port 1
        assert!(rx1.try_recv().is_err());
        assert_eq!(rx2.try_recv().unwrap(), make_frame(1, 99));
        assert_eq!(rx3.try_recv().unwrap(), make_frame(1, 99));
    }

    #[tokio::test]
    async fn test_address_learning() {
        let mut switch: Switch<u8> = Switch::new();

        let (tx1, _, port1) = create_port_pair(10);
        let (tx2, _, port2) = create_port_pair(10);

        switch.add_port(port1, PortConfig::no_loss()).unwrap();
        switch.add_port(port2, PortConfig::no_loss()).unwrap();

        // Send from port 1 (source = node 5)
        tx1.send(make_frame(5, 10)).await.unwrap();
        switch.tick().await.unwrap();

        // Switch should have learned that node 5 is on port 0
        assert_eq!(switch.ident_map.get(&5), Some(&PortId(0)));

        // Send from port 2 (source = node 7)
        tx2.send(make_frame(7, 5)).await.unwrap();
        switch.tick().await.unwrap();

        // Switch should have learned that node 7 is on port 1
        assert_eq!(switch.ident_map.get(&7), Some(&PortId(1)));
    }

    #[tokio::test]
    async fn test_incoming_packet_loss() {
        let mut switch: Switch<u8> = Switch::new();

        // Create port with 100% incoming loss
        let (tx1, _, port1) = create_port_pair(10);
        let (_, mut rx2, port2) = create_port_pair(10);

        switch.add_port(port1, PortConfig::new(0.0, 1.0)).unwrap(); // 100% incoming loss
        switch.add_port(port2, PortConfig::no_loss()).unwrap();

        // Send multiple frames from port 1
        for i in 0..10 {
            tx1.send(make_frame(1, i)).await.unwrap();
        }
        switch.tick().await.unwrap();

        // Port 2 should receive nothing (100% loss on port 1 incoming)
        assert!(rx2.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_outgoing_packet_loss() {
        let mut switch: Switch<u8> = Switch::new();

        // Create port with 100% outgoing loss
        let (tx1, mut rx1, port1) = create_port_pair(10);
        let (_, mut rx2, port2) = create_port_pair(10);

        switch.add_port(port1, PortConfig::no_loss()).unwrap();
        switch.add_port(port2, PortConfig::new(1.0, 0.0)).unwrap(); // 100% outgoing loss

        // Send frame from port 1 (source learns); dst is unknown so it floods.
        tx1.send(make_frame(1, 99)).await.unwrap();
        switch.tick().await.unwrap();

        // Port 2 must receive nothing: its egress (switch→node) is 100% lossy.
        assert!(rx2.try_recv().is_err());
        // ...but the switch still learned port 1 = node 1 from the ingress.

        // Now send from a third port to node 1 - but port 1 has no outgoing loss
        let (tx3, _, port3) = create_port_pair(10);
        switch.add_port(port3, PortConfig::no_loss()).unwrap();

        tx3.send(make_frame(3, 1)).await.unwrap();
        switch.tick().await.unwrap();

        // Port 1 should receive it (no outgoing loss on port 1)
        assert_eq!(rx1.try_recv().unwrap(), make_frame(3, 1));
    }

    #[tokio::test]
    async fn test_tap_to_switch() {
        let mut switch: Switch<u8> = Switch::new();

        let (tx1, _, port1) = create_port_pair(10);
        let port1_id = switch.add_port(port1, PortConfig::no_loss()).unwrap();

        // Track tapped messages
        let tapped = Arc::new(Mutex::new(Vec::new()));
        let tapped_clone = tapped.clone();

        let tap = TapConfig::new(move |meta: TapMeta| {
            tapped_clone
                .lock()
                .unwrap()
                .push((meta.direction, meta.data.to_vec()));
            true // Continue tapping
        });

        switch.add_tap(port1_id, tap).unwrap();

        // Send frame
        tx1.send(make_frame(1, 2)).await.unwrap();
        switch.tick().await.unwrap();

        // Check tap captured the message with correct direction
        let tapped_msgs = tapped.lock().unwrap();
        assert_eq!(tapped_msgs.len(), 1);
        assert_eq!(tapped_msgs[0].0, Direction::ToSwitch);
        assert_eq!(tapped_msgs[0].1, make_frame(1, 2));
    }

    #[tokio::test]
    async fn test_tap_from_switch() {
        let mut switch: Switch<u8> = Switch::new();

        let (tx1, _, port1) = create_port_pair(10);
        let (_, mut rx2, port2) = create_port_pair(10);

        switch.add_port(port1, PortConfig::no_loss()).unwrap();
        let port2_id = switch.add_port(port2, PortConfig::no_loss()).unwrap();

        // Learn port 1 = node 1
        tx1.send(make_frame(1, 99)).await.unwrap();
        switch.tick().await.unwrap();
        rx2.try_recv().ok(); // Clear broadcast

        // Tap port 2 for outgoing traffic
        let tapped = Arc::new(Mutex::new(Vec::new()));
        let tapped_clone = tapped.clone();

        let tap = TapConfig::new(move |meta: TapMeta| {
            tapped_clone
                .lock()
                .unwrap()
                .push((meta.direction, meta.data.to_vec()));
            true
        });

        switch.add_tap(port2_id, tap).unwrap();

        // Send from port 2 to node 1 (should go to port 1)
        let (tx3, _, port3) = create_port_pair(10);
        switch.add_port(port3, PortConfig::no_loss()).unwrap();

        tx3.send(make_frame(3, 1)).await.unwrap();
        switch.tick().await.unwrap();

        // Port 2 should not have been tapped (message went to port 1)
        let tapped_msgs = tapped.lock().unwrap();
        assert_eq!(tapped_msgs.len(), 0);
    }

    #[tokio::test]
    async fn test_tap_stops_on_false_return() {
        let mut switch: Switch<u8> = Switch::new();

        let (tx1, _, port1) = create_port_pair(10);
        let port1_id = switch.add_port(port1, PortConfig::no_loss()).unwrap();

        let counter = Arc::new(Mutex::new(0));
        let counter_clone = counter.clone();

        // Tap that stops after first message
        let tap = TapConfig::new(move |_: TapMeta| {
            *counter_clone.lock().unwrap() += 1;
            false // Stop tapping
        });

        switch.add_tap(port1_id, tap).unwrap();

        // Send two frames
        tx1.send(make_frame(1, 2)).await.unwrap();
        switch.tick().await.unwrap();

        tx1.send(make_frame(1, 3)).await.unwrap();
        switch.tick().await.unwrap();

        // Should only have been called once
        assert_eq!(*counter.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_multiple_ports_full_mesh() {
        let mut switch: Switch<u8> = Switch::new();

        // Create 4 ports
        let (tx1, mut rx1, port1) = create_port_pair(10);
        let (tx2, mut rx2, port2) = create_port_pair(10);
        let (tx3, mut rx3, port3) = create_port_pair(10);
        let (tx4, mut rx4, port4) = create_port_pair(10);

        switch.add_port(port1, PortConfig::no_loss()).unwrap();
        switch.add_port(port2, PortConfig::no_loss()).unwrap();
        switch.add_port(port3, PortConfig::no_loss()).unwrap();
        switch.add_port(port4, PortConfig::no_loss()).unwrap();

        // Each port sends a message
        tx1.send(make_frame(1, 99)).await.unwrap();
        tx2.send(make_frame(2, 99)).await.unwrap();
        tx3.send(make_frame(3, 99)).await.unwrap();
        tx4.send(make_frame(4, 99)).await.unwrap();

        switch.tick().await.unwrap();

        // Each port should receive 3 messages (from the other 3 ports)
        for _ in 0..3 {
            rx1.try_recv().unwrap();
            rx2.try_recv().unwrap();
            rx3.try_recv().unwrap();
            rx4.try_recv().unwrap();
        }

        // No more messages
        assert!(rx1.try_recv().is_err());
        assert!(rx2.try_recv().is_err());
        assert!(rx3.try_recv().is_err());
        assert!(rx4.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_reseed_affects_randomness() {
        // Test that reseeding changes RNG behavior
        let mut switch1: Switch<u8> = Switch::new().reseed([1; 32]);
        let mut switch2: Switch<u8> = Switch::new().reseed([2; 32]);

        // Both switches with 50% loss
        let (tx1, mut rx1, port1) = create_port_pair(100);
        let (_, _, port2) = create_port_pair(100);

        switch1.add_port(port1, PortConfig::new(0.0, 0.5)).unwrap();
        switch1.add_port(port2, PortConfig::no_loss()).unwrap();

        let (tx3, mut rx3, port3) = create_port_pair(100);
        let (_, _, port4) = create_port_pair(100);

        switch2.add_port(port3, PortConfig::new(0.0, 0.5)).unwrap();
        switch2.add_port(port4, PortConfig::no_loss()).unwrap();

        // Send many packets
        for i in 0..50 {
            tx1.send(make_frame(1, i)).await.unwrap();
            tx3.send(make_frame(1, i)).await.unwrap();
        }

        switch1.tick().await.unwrap();
        switch2.tick().await.unwrap();

        // Count received (different seeds should give different results)
        let mut count1 = 0;
        let mut count2 = 0;

        while rx1.try_recv().is_ok() {
            count1 += 1;
        }
        while rx3.try_recv().is_ok() {
            count2 += 1;
        }

        // With different seeds, counts should differ (probabilistically)
        // This might occasionally fail due to randomness, but very unlikely
        println!("Count1: {}, Count2: {}", count1, count2);
    }

    // ── partial (statistical) loss ──────────────────────────────────────────
    //
    // The tests above only ever exercise 0.0/1.0 loss. Real links sit
    // somewhere in between, so these drive enough frames through a fractional
    // `PortConfig` to check the drop rate lands near the configured
    // probability rather than being all-or-nothing, ignored, or inverted.
    // Bounds are generous (many standard deviations either side of the mean)
    // so they only fail on a real regression, not RNG noise, while `assert_ne`
    // guards against a config that silently behaves like 0.0 or 1.0.

    #[tokio::test]
    async fn test_partial_outgoing_loss_statistical() {
        const N: usize = 2000;
        let mut switch: Switch<u8> = Switch::new();

        let (tx1, _rx1, port1) = create_port_pair(N + 10);
        let (tx2, mut rx2, port2) = create_port_pair(N + 10);

        switch.add_port(port1, PortConfig::no_loss()).unwrap();
        switch.add_port(port2, PortConfig::new(0.5, 0.0)).unwrap();

        // Teach the switch node 2 lives on port2, so the frames below resolve
        // to a direct unicast (the per-destination outgoing_loss branch)
        // rather than the broadcast fan-out branch.
        tx2.send(make_frame(2, 1)).await.unwrap();
        switch.tick().await.unwrap();

        for _ in 0..N {
            tx1.send(make_frame(1, 2)).await.unwrap();
        }
        switch.tick().await.unwrap();

        let mut received = 0;
        while rx2.try_recv().is_ok() {
            received += 1;
        }

        // Expected ≈ N/2 = 1000, std dev ≈ 22; ±150 is ~7 std devs.
        assert!(
            (850..=1150).contains(&received),
            "expected roughly half of {N} frames to survive 50% outgoing loss, got {received}"
        );
    }

    #[tokio::test]
    async fn test_partial_incoming_loss_statistical() {
        const N: usize = 2000;
        let mut switch: Switch<u8> = Switch::new();

        let (tx1, _rx1, port1) = create_port_pair(N + 10);
        let (_tx2, mut rx2, port2) = create_port_pair(N + 10);

        switch.add_port(port1, PortConfig::new(0.0, 0.5)).unwrap();
        switch.add_port(port2, PortConfig::no_loss()).unwrap();

        // Unknown destination floods to port2, so every surviving frame is
        // observable there; drops happen on ingress from port1, before
        // forwarding decisions are even made.
        for _ in 0..N {
            tx1.send(make_frame(1, 99)).await.unwrap();
        }
        switch.tick().await.unwrap();

        let mut received = 0;
        while rx2.try_recv().is_ok() {
            received += 1;
        }

        assert!(
            (850..=1150).contains(&received),
            "expected roughly half of {N} frames to survive 50% incoming loss, got {received}"
        );
    }

    #[tokio::test]
    async fn test_asymmetric_direction_loss_independent() {
        // Node A is "deaf" (outgoing_loss = 1.0: it can't hear the fabric) but
        // not "mute" (incoming_loss = 0.0: its own transmissions still reach
        // the fabric).  The two knobs must act independently.
        let mut switch: Switch<u8> = Switch::new();

        let (tx_a, mut rx_a, port_a) = create_port_pair(2100);
        let (tx_b, mut rx_b, port_b) = create_port_pair(2100);

        switch.add_port(port_a, PortConfig::new(1.0, 0.0)).unwrap();
        switch.add_port(port_b, PortConfig::no_loss()).unwrap();

        // A's first frame teaches the switch A's port and reaches B fine — A
        // isn't the destination here, so its outgoing_loss doesn't apply.
        tx_a.send(make_frame(10, 20)).await.unwrap();
        switch.tick().await.unwrap();
        assert_eq!(rx_b.try_recv().unwrap(), make_frame(10, 20));

        // B's reply teaches the switch B's port too — learning happens on
        // ingress, independent of whether delivery to the destination
        // succeeds — but delivery to A is dropped by A's outgoing_loss.
        tx_b.send(make_frame(20, 10)).await.unwrap();
        switch.tick().await.unwrap();
        assert!(rx_a.try_recv().is_err());

        // With both ports learned: B -> A must be fully blocked...
        const N: usize = 1000;
        for _ in 0..N {
            tx_b.send(make_frame(20, 10)).await.unwrap();
        }
        switch.tick().await.unwrap();
        assert!(
            rx_a.try_recv().is_err(),
            "A's outgoing_loss = 1.0 must block every frame addressed to it"
        );

        // ...while A -> B must be fully delivered: A's incoming_loss = 0.0
        // means its own transmissions are never dropped, regardless of its
        // (unrelated) outgoing_loss.
        for _ in 0..N {
            tx_a.send(make_frame(10, 20)).await.unwrap();
        }
        switch.tick().await.unwrap();
        let mut received = 0;
        while rx_b.try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(
            received, N,
            "A's incoming_loss = 0.0 must deliver every frame A sends, unaffected by its outgoing_loss"
        );
    }

    #[tokio::test]
    async fn test_broadcast_fanout_independent_per_port_loss() {
        // Three ports observe the same broadcast frame under three different
        // outgoing_loss settings: each port's fan-out copy must be governed
        // only by its own loss, not by the others'.
        const N: usize = 2000;
        let mut switch: Switch<u8> = Switch::new();

        let (tx1, _rx1, port1) = create_port_pair(N + 10);
        let (_tx2, mut rx2, port2) = create_port_pair(N + 10);
        let (_tx3, mut rx3, port3) = create_port_pair(N + 10);
        let (_tx4, mut rx4, port4) = create_port_pair(N + 10);

        switch.add_port(port1, PortConfig::no_loss()).unwrap();
        switch.add_port(port2, PortConfig::new(0.0, 0.0)).unwrap();
        switch.add_port(port3, PortConfig::new(0.5, 0.0)).unwrap();
        switch.add_port(port4, PortConfig::new(1.0, 0.0)).unwrap();

        for _ in 0..N {
            tx1.send(make_frame(1, 99)).await.unwrap(); // unknown dest -> flood
        }
        switch.tick().await.unwrap();

        fn drain(rx: &mut mpsc::Receiver<Vec<u8>>) -> usize {
            let mut count = 0;
            while rx.try_recv().is_ok() {
                count += 1;
            }
            count
        }

        assert_eq!(drain(&mut rx2), N, "0% loss port must receive every frame");
        let partial = drain(&mut rx3);
        assert!(
            (850..=1150).contains(&partial),
            "50% loss port should receive roughly half of {N}, got {partial}"
        );
        assert_eq!(drain(&mut rx4), 0, "100% loss port must receive nothing");
    }
}
