#![no_std]

use core::mem::size_of;
use interfaces::frame::MeshIdentifier;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use thiserror::Error;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use heapless::{Vec, IndexMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    ToSwitch,
    FromSwitch,
}

pub struct PortConfig {
    pub outgoing_loss: f64,
    pub incoming_loss: f64,
}

impl PortConfig {
    pub const fn new(outgoing_loss: f64, incoming_loss: f64) -> Self {
        Self {
            outgoing_loss,
            incoming_loss,
        }
    }

    pub const fn no_loss() -> Self {
        Self {
            outgoing_loss: 0.0,
            incoming_loss: 0.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct PortId(pub u32);

pub struct PortComms<'a> {
    pub to_switch: &'a Channel<NoopRawMutex, Vec<u8, 1500>, 16>,
    pub from_switch: &'a Channel<NoopRawMutex, Vec<u8, 1500>, 16>,
}

pub struct Port<'a> {
    pub config: PortConfig,
    pub duplex: PortComms<'a>,
}

pub trait TapHandler {
    fn handle(&mut self, meta: TapMeta<'_>) -> bool;
}

pub struct TapMeta<'a> {
    pub id: PortId,
    pub direction: Direction,
    pub data: &'a [u8],
}

#[derive(Error, Debug)]
pub enum SwitchError {
    #[error("port not found")]
    InvalidPort,
    #[error("table full")]
    TableFull,
}

pub struct Switch<'a, Ident, const MAX_PORTS: usize, const MAX_TAPS_PER_PORT: usize> {
    rng: StdRng,
    ports: IndexMap<PortId, Port<'a>, MAX_PORTS>,
    // For no_alloc taps, we might need a different approach.
    // For now, let's skip taps or use function pointers.
    ident_map: IndexMap<Ident, PortId, 100>,
}

impl<'a, Ident, const MAX_PORTS: usize, const MAX_TAPS_PER_PORT: usize> Switch<'a, Ident, MAX_PORTS, MAX_TAPS_PER_PORT>
where
    Ident: MeshIdentifier + core::fmt::Debug,
{
    pub fn new() -> Self {
        Self {
            ports: IndexMap::new(),
            ident_map: IndexMap::new(),
            rng: StdRng::from_seed([0; 32]),
        }
    }

    pub fn reseed(&mut self, seed: [u8; 32]) {
        self.rng = StdRng::from_seed(seed);
    }

    pub fn add_port(
        &mut self,
        duplex: PortComms<'a>,
        port_config: PortConfig,
    ) -> Result<PortId, SwitchError> {
        let id = PortId(self.ports.len() as u32);
        self.ports.insert(
            id,
            Port {
                config: port_config,
                duplex,
            },
        ).map_err(|_| SwitchError::TableFull)?;
        Ok(id)
    }

    pub async fn tick(&mut self) -> Result<(), SwitchError> {
        // In no_std with embassy-sync, we can't easily collect all messages into a Vec of Vecs without alloc.
        // We'll process them one by one.
        
        let mut port_ids: Vec<PortId, MAX_PORTS> = Vec::new();
        for id in self.ports.keys() {
            let _ = port_ids.push(*id);
        }

        for id in port_ids {
            let port = self.ports.get_mut(&id).unwrap();
            while let Ok(msg) = port.duplex.to_switch.try_receive() {
                if self.rng.gen_bool(port.config.incoming_loss) {
                    continue;
                }

                // Learn source
                if let Ok((source, _)) = Ident::ref_from_prefix(&msg) {
                    let _ = self.ident_map.insert(*source, id);
                }

                // Forwarding logic
                if let Ok((dest, _)) = Ident::ref_from_prefix(&msg[size_of::<Ident>()..]) {
                    if let Some(dest_port_id) = self.ident_map.get(dest) {
                        let dp_id = *dest_port_id;
                        if let Some(dest_port) = self.ports.get_mut(&dp_id) {
                            if !self.rng.gen_bool(dest_port.config.outgoing_loss) {
                                let _ = dest_port.duplex.from_switch.try_send(msg.clone());
                            }
                        }
                    } else {
                        // Broadcast
                        for (other_id, other_port) in self.ports.iter_mut() {
                            if *other_id == id { continue; }
                            if !self.rng.gen_bool(other_port.config.outgoing_loss) {
                                let _ = other_port.duplex.from_switch.try_send(msg.clone());
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
