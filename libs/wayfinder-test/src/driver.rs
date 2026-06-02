use futures::future::FutureExt;
use std::{collections::HashMap, time::Duration};

use interfaces::frame::Mac;
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, interval, interval_at};

use crate::{
    switch::{PortComms, PortConfig, Switch},
    test_router::TestRouter,
};

#[derive(Serialize, Deserialize, Default)]
pub struct TestConfig {
    pub switches: Vec<TestSwitchConfig>,
    pub machines: Vec<TestMachineConfig>,
}

#[derive(Serialize, Deserialize)]
pub struct TestSwitchConfig {
    pub name: String,
}

#[derive(Serialize, Deserialize)]
pub struct TestMachineConfig {
    pub name: String,
    pub wayfinder: wayfinder::config::Config,
}

#[derive(Default)]
pub struct TestHarness {
    pub switches: HashMap<String, Switch<Mac>>,
    pub machines: HashMap<String, TestRouter>,
}

impl TestHarness {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn poll(&mut self, now: Duration) {
        let mut int = interval(Duration::from_hours(1));
        // Tick it once so that we don't block waiting for the interval to elapse
        int.tick().await;

        for (_, router) in self.machines.iter_mut() {
            router.poll(now).await;
        }
    }

    pub async fn tick(&mut self) {
        let mut int = interval(Duration::from_hours(1));
        int.tick().await;

        for (_, router) in self.machines.iter_mut() {
            let _ = router
                .driver()
                .run_once(&mut int, false, true, false)
                .now_or_never();
        }

        for (_, router) in self.machines.iter_mut() {
            let _ = router
                .driver()
                .run_once(&mut int, true, false, false)
                .now_or_never();
        }
        for (_, switch) in self.switches.iter_mut() {
            switch.tick().await.unwrap();
        }
    }

    pub fn get_machine(&self, name: &str) -> &TestRouter {
        self.machines.get(name).unwrap()
    }

    pub fn get_machine_mut(&mut self, name: &str) -> &mut TestRouter {
        self.machines.get_mut(name).unwrap()
    }

    pub fn add_switch_port(&mut self, switch_name: &str) -> PortComms {
        let switch = self
            .switches
            .get_mut(switch_name)
            .expect("switch not found");

        let (router_comms, switch_comms) = PortComms::pair(10);

        switch
            .add_port(switch_comms, PortConfig::no_loss())
            .unwrap();

        router_comms
    }
}

pub fn mac(n: u8) -> Mac {
    Mac([0, 0, 0, 0, 0, n])
}

impl TestConfig {
    pub fn validate(&self) -> Result<TestHarness, String> {
        let mut h = TestHarness::default();
        for switch in &self.switches {
            if h.switches
                .insert(
                    switch.name.clone(),
                    Switch::new_with_name(switch.name.clone()),
                )
                .is_some()
            {
                return Err(format!(
                    "Switch '{}' is defined multiple times",
                    switch.name
                ));
            }
        }
        for (i, machine) in self.machines.iter().enumerate() {
            let router = TestRouter::new_from_config(&mut h, mac(i as u8), &machine.wayfinder);
            if h.machines.insert(machine.name.clone(), router).is_some() {
                return Err(format!(
                    "Machine '{}' is defined multiple times",
                    machine.name
                ));
            }
        }

        Ok(h)
    }
}
