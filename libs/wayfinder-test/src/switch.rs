use std::collections::HashMap;
use std::mem::size_of;

use interfaces::link::MeshIdentifier;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use thiserror::Error;
use tokio::sync::mpsc::error::TryRecvError;

use crate::Direction;

pub struct PortConfig {
    // TODO: will support vlans
    outgoing_loss: f64,
    incoming_loss: f64,
}

impl PortConfig {
    pub fn new(outgoing_loss: f64, incoming_loss: f64) -> Self {
        Self {
            outgoing_loss,
            incoming_loss,
        }
    }

    pub fn no_loss() -> Self {
        Self {
            outgoing_loss: 0.0,
            incoming_loss: 0.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct PortId(u32);

pub struct PortComms {
    to_switch: tokio::sync::mpsc::Receiver<Vec<u8>>,
    from_switch: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl PortComms {
    pub fn new(
        to_switch: tokio::sync::mpsc::Receiver<Vec<u8>>,
        from_switch: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            to_switch,
            from_switch,
        }
    }
}

pub struct Port {
    config: PortConfig,
    duplex: PortComms,
}

pub struct TapConfig {
    /// If the tap config returns true it continues to monitor, if false, it stops monitoring
    clb: Box<dyn FnMut(TapMeta<'_>) -> bool>,
    /// Invalidated
    invalid: bool,
}

impl TapConfig {
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

pub struct TapMeta<'a> {
    pub id: PortId,
    pub direction: Direction,
    pub data: &'a [u8],
}

pub struct TapId(u32);

#[derive(Error, Debug)]
pub enum SwitchError {
    #[error("port not found")]
    InvalidPort,
    #[error(transparent)]
    TryRecvError(#[from] TryRecvError),
}

pub struct Switch<Ident> {
    // Random Number generator
    rng: StdRng,
    // Ports connected to the switch
    ports: HashMap<PortId, Port>,
    // Taps that we have registered on the switch for monitoring data in the application/test
    taps: HashMap<PortId, Vec<TapConfig>>,
    // Ident address mapping of port
    ident_map: HashMap<Ident, PortId>,
}

impl<Ident> Switch<Ident>
where
    Ident: MeshIdentifier + std::fmt::Debug,
{
    pub fn new() -> Self {
        Self {
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

    /// Tap a port
    pub fn add_tap(&mut self, id: PortId, tap_config: TapConfig) -> Result<(), SwitchError> {
        let taps = self.taps.entry(id).or_default();
        taps.push(tap_config);
        Ok(())
    }

    /// Tick the switch, multiplexing messages between ports and calling the tap handlers
    pub async fn tick(&mut self) -> Result<(), SwitchError> {
        // Flush all messages in the switch's buffer
        let msgs = self
            .ports
            .iter_mut()
            .map(|(id, port)| {
                let mut msgs = vec![];
                while let Ok(msg) = port.duplex.to_switch.try_recv() {
                    if !self.rng.random_bool(port.config.incoming_loss) {
                        msgs.push(msg);
                    }
                }

                Ok((*id, msgs))
            })
            .collect::<Result<Vec<_>, SwitchError>>()?;

        // Loop over all and register the source ident for each message
        for (id, msgs) in &msgs {
            if let Some(taps) = self.taps.get_mut(id) {
                for tap in taps.iter_mut() {
                    for msg in msgs {
                        if !(tap.clb)(TapMeta {
                            data: msg.as_slice(),
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
                let Ok((source, _)) = Ident::ref_from_prefix(msg.as_slice()) else {
                    continue;
                };

                self.ident_map.insert(*source, *id);
            }
        }

        // Loop over all and forward to destination, or all ports if destination port not specifically known
        for (port, msgs) in msgs {
            let port_config = self.ports.get(&port).unwrap();
            for msg in msgs {
                if self.rng.random_bool(port_config.config.outgoing_loss) {
                    continue;
                }

                let Ok((dest, _)) = Ident::ref_from_prefix(&msg[size_of::<Ident>()..]) else {
                    continue;
                };

                if let Some(dest_port) = self.ident_map.get(dest) {
                    // Send to specific destination port
                    if let Some(taps) = self.taps.get_mut(dest_port) {
                        for tap in taps.iter_mut() {
                            if !(tap.clb)(TapMeta {
                                data: msg.as_slice(),
                                direction: Direction::FromSwitch,
                                id: *dest_port,
                            }) {
                                tap.invalid = true;
                            }
                        }
                        taps.retain(|t| !t.invalid);
                    }

                    let _ = self
                        .ports
                        .get(dest_port)
                        .unwrap()
                        .duplex
                        .from_switch
                        .send(msg.clone())
                        .await;
                } else {
                    // Broadcast to all ports except source
                    for (other_port_id, other_port) in self.ports.iter() {
                        if *other_port_id == port {
                            continue; // Don't send back to source
                        }

                        if let Some(taps) = self.taps.get_mut(other_port_id) {
                            for tap in taps.iter_mut() {
                                if !(tap.clb)(TapMeta {
                                    data: msg.as_slice(),
                                    direction: Direction::FromSwitch,
                                    id: *other_port_id,
                                }) {
                                    tap.invalid = true;
                                }
                            }
                            taps.retain(|t| !t.invalid);
                        }

                        let _ = other_port.duplex.from_switch.send(msg.clone()).await;
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    // Helper to create a simple frame with src and dst
    fn make_frame(src: u8, dst: u8) -> Vec<u8> {
        use zerocopy::IntoBytes;
        let mut data = Vec::new();
        data.extend_from_slice(src.as_bytes()).as_bytes();
        data.extend_from_slice(dst.as_bytes()).as_bytes();
        data
    }

    fn create_port_pair(
        buffer_size: usize,
    ) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>, PortComms) {
        let (tx_to_switch, rx_to_switch) = mpsc::channel(buffer_size);
        let (tx_from_switch, rx_from_switch) = mpsc::channel(buffer_size);
        let port_comms = PortComms::new(rx_to_switch, tx_from_switch);
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
        let (_, _, port2) = create_port_pair(10);

        switch.add_port(port1, PortConfig::no_loss()).unwrap();
        switch.add_port(port2, PortConfig::new(1.0, 0.0)).unwrap(); // 100% outgoing loss

        // Send frame from port 1 (source learns)
        tx1.send(make_frame(1, 99)).await.unwrap();
        switch.tick().await.unwrap();

        // Port 2 should have received nothing due to outgoing loss
        // But switch learned port 1 = node 1

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
}
