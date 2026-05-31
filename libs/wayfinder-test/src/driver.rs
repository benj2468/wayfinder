use std::{collections::HashMap, time::Duration};

use interfaces::frame::Mac;
use serde::{Deserialize, Serialize};

use crate::{
    switch::{PortComms, PortConfig, Switch},
    test_router::TestRouter,
};

#[derive(Serialize, Deserialize, Default)]
struct TestConfig {
    switches: Vec<TestSwitchConfig>,
    machines: Vec<TestMachineConfig>,
}

#[derive(Serialize, Deserialize)]
struct TestSwitchConfig {
    name: String,
}

#[derive(Serialize, Deserialize)]
struct TestMachineConfig {
    name: String,
    switches: Vec<String>,
    wayfinder: wayfinder::config::Config,
}

#[derive(Default)]
pub struct TestHarness {
    switches: HashMap<String, Switch<Mac>>,
    machines: HashMap<String, TestRouter>,
}

impl TestHarness {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn tick(&mut self, now: Duration) {
        for (_, router) in self.machines.iter_mut() {
            router.drain_all().await;
        }

        for (_, switch) in self.switches.iter_mut() {
            switch.tick().await.unwrap();
        }

        for (_, router) in self.machines.iter_mut() {
            router.poll(now).await;
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

fn mac(n: u8) -> Mac {
    Mac([0, 0, 0, 0, 0, n + 1])
}

impl TestConfig {
    fn validate(&self) -> Result<TestHarness, String> {
        let mut h = TestHarness::default();
        for switch in &self.switches {
            if !self
                .machines
                .iter()
                .any(|m| m.switches.iter().any(|s| *s == switch.name))
            {
                return Err(format!(
                    "Switch '{}' is not used by any machine",
                    switch.name
                ));
            }

            if h.switches
                .insert(switch.name.clone(), Switch::new())
                .is_some()
            {
                return Err(format!(
                    "Switch '{}' is defined multiple times",
                    switch.name
                ));
            }
        }
        for (i, machine) in self.machines.iter().enumerate() {
            for switch in &machine.switches {
                if !self.switches.iter().any(|s| s.name == *switch) {
                    return Err(format!("Switch '{}' is not defined", switch));
                }
            }
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

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use tracing_subscriber::EnvFilter;
    use wayfinder::config::{Config, LinkConfig};

    use super::*;

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_test_writer() // Captures logs correctly within the test runner
                .init();
        });
    }

    #[tokio::test]
    async fn test_validate() {
        let config = TestConfig::default();
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_multi_same_switch() {
        let mut config = TestConfig::default();
        config.switches.push(TestSwitchConfig {
            name: "test1".into(),
        });
        config.switches.push(TestSwitchConfig {
            name: "test1".into(),
        });
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_invalid_switch() {
        let mut config = TestConfig::default();
        config.machines.push(TestMachineConfig {
            name: "foo".into(),
            switches: vec!["invalid".into()],
            wayfinder: Config::default(),
        });
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_simple_pair() {
        let mut config = TestConfig::default();
        config.switches.push(TestSwitchConfig {
            name: "test1".into(),
        });
        config.machines.push(TestMachineConfig {
            name: "foo".into(),
            switches: vec!["test1".into()],
            wayfinder: Config::default(),
        });
        config.machines.push(TestMachineConfig {
            name: "foo1".into(),
            switches: vec!["test1".into()],
            wayfinder: Config::default(),
        });
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_simple_pair_send_data() {
        setup();

        let mut config = TestConfig::default();
        config.switches.push(TestSwitchConfig {
            name: "switch1".into(),
        });
        config.machines.push(TestMachineConfig {
            name: "machine1".into(),
            switches: vec!["switch1".into()],
            wayfinder: Config {
                links: vec![LinkConfig::Test {
                    switch_name: "switch1".into(),
                }],
                ..Default::default()
            },
        });
        config.machines.push(TestMachineConfig {
            name: "machine2".into(),
            switches: vec!["switch1".into()],
            wayfinder: Config {
                links: vec![LinkConfig::Test {
                    switch_name: "switch1".into(),
                }],
                ..Default::default()
            },
        });
        let mut harness = config.validate().unwrap();
        harness.tick(Duration::from_secs(1)).await;
        harness.tick(Duration::from_secs(2)).await;

        let ident = harness.get_machine_mut("machine2").ident;
        harness
            .get_machine_mut("machine1")
            .send_local(ident, b"Hello World")
            .await
            .unwrap();

        harness.tick(Duration::from_secs(3)).await;
        harness.tick(Duration::from_secs(4)).await;

        assert_eq!(
            harness.get_machine("machine2").local_deliveries,
            vec![b"Hello World"]
        );
    }
}
