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

    fn simple_pair() -> TestHarness {
        let mut config = TestConfig::default();
        config.switches.push(TestSwitchConfig {
            name: "switch1".into(),
        });
        config.machines.push(TestMachineConfig {
            name: "machine1".into(),
            wayfinder: Config {
                links: vec![LinkConfig::Test {
                    switch_name: "switch1".into(),
                }],
                ..Default::default()
            },
        });
        config.machines.push(TestMachineConfig {
            name: "machine2".into(),
            wayfinder: Config {
                links: vec![LinkConfig::Test {
                    switch_name: "switch1".into(),
                }],
                ..Default::default()
            },
        });
        config.validate().unwrap()
    }

    fn line_of_three() -> TestHarness {
        let mut config = TestConfig::default();
        config.switches.push(TestSwitchConfig {
            name: "switch1".into(),
        });
        config.switches.push(TestSwitchConfig {
            name: "switch2".into(),
        });
        config.machines.push(TestMachineConfig {
            name: "machine1".into(),
            wayfinder: Config {
                links: vec![LinkConfig::Test {
                    switch_name: "switch1".into(),
                }],
                ..Default::default()
            },
        });
        config.machines.push(TestMachineConfig {
            name: "machine2".into(),
            wayfinder: Config {
                links: vec![
                    LinkConfig::Test {
                        switch_name: "switch1".into(),
                    },
                    LinkConfig::Test {
                        switch_name: "switch2".into(),
                    },
                ],
                ..Default::default()
            },
        });
        config.machines.push(TestMachineConfig {
            name: "machine3".into(),
            wayfinder: Config {
                links: vec![LinkConfig::Test {
                    switch_name: "switch2".into(),
                }],
                ..Default::default()
            },
        });
        config.validate().unwrap()
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
    #[should_panic]
    async fn test_invalid_switch() {
        let mut config = TestConfig::default();
        config.machines.push(TestMachineConfig {
            name: "foo".into(),
            wayfinder: Config {
                links: vec![LinkConfig::Test {
                    switch_name: "invalid".into(),
                }],
                ..Default::default()
            },
        });
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_simple_pair() {
        simple_pair();
    }

    #[tokio::test]
    async fn test_simple_pair_send_data() {
        setup();
        let mut harness = simple_pair();

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

    #[tokio::test]
    async fn test_line_of_three() {
        line_of_three();
    }

    #[tokio::test]
    async fn test_line_of_three_send_data() {
        setup();
        let mut harness = line_of_three();

        harness.tick(Duration::from_secs(1)).await;
        harness.tick(Duration::from_secs(2)).await;
        harness.tick(Duration::from_secs(3)).await;
        harness.tick(Duration::from_secs(4)).await;

        let ident = harness.get_machine_mut("machine3").ident;
        harness
            .get_machine_mut("machine1")
            .send_local(ident, b"Hello World")
            .await
            .unwrap();

        harness.tick(Duration::from_secs(5)).await;
        harness.tick(Duration::from_secs(6)).await;
        harness.tick(Duration::from_secs(7)).await;

        assert_eq!(
            harness.get_machine("machine3").local_deliveries,
            vec![b"Hello World"]
        );
    }
}
