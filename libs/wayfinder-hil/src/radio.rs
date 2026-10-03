//! A radio module on the rig: a REYAX RYLR998, driven over its AT-command UART.
//!
//! Not a [`Board`](crate::Board) — it runs its vendor's firmware, has no probe
//! and no management API — so it is reached through
//! [`rylr998::RylrClient`] rather than `wayfinder-client`. It exists on the rig
//! to talk over the air to a board whose own firmware a test controls.

use std::path::PathBuf;
use std::time::Duration;

use embedded_io_adapters::tokio_1::FromTokio;
use rylr998::Bandwidth;
use rylr998::CodingRate;
use rylr998::ReceivedPacket;
use rylr998::RylrClient;
use rylr998::SpreadingFactory;
use tokio_serial::SerialPortBuilderExt;
use tokio_serial::SerialStream;

use crate::inventory::RadioSpec;
use crate::usb;

/// The module's UART rate, its factory default.
const BAUD: u32 = 115_200;

/// How long one AT command may take to answer. Generous: `AT+BAND` writes
/// flash on some firmware revisions.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);

/// The PHY every radio test on this rig uses, which the WL55 images match:
/// SF7, 125 kHz, CR 4/8 and an 8-symbol preamble
/// (`bins/wayfinder-wl55jc/src/main.rs`'s `RADIO`, and the HIL echo example).
/// Any one disagreeing and the two radios do not hear each other at all.
const SPREADING_FACTOR: SpreadingFactory = SpreadingFactory::Sf7;
/// See [`SPREADING_FACTOR`].
const BANDWIDTH: Bandwidth = Bandwidth::Khz125;
/// See [`SPREADING_FACTOR`].
const CODING_RATE: CodingRate = CodingRate::Cr48;
/// See [`SPREADING_FACTOR`].
const PREAMBLE_SYMBOLS: u8 = 8;

/// The module's factory network id, measured to hear the LoRa private sync
/// word the WL55 images use (`rylr998::air`'s module docs).
const NETWORK_ID: u8 = 18;

/// One attached radio module, addressed the way the inventory describes it.
#[derive(Debug, Clone)]
pub struct Radio {
    spec: RadioSpec,
}

impl Radio {
    /// Wrap an inventory entry.
    pub fn new(spec: RadioSpec) -> Radio {
        Radio { spec }
    }

    /// The inventory entry this radio was built from.
    pub fn spec(&self) -> &RadioSpec {
        &self.spec
    }

    /// The device node of the adapter the module sits behind, resolved through
    /// its USB serial every time, as a board's management port is.
    pub fn port(&self) -> anyhow::Result<PathBuf> {
        let devices = usb::enumerate()?;
        Ok(usb::match_device(&devices, &self.spec.usb)?.to_path_buf())
    }

    /// Open the module and configure it for this rig: the inventory's
    /// frequency, the rig's PHY, the factory network id, and `address` as its
    /// own `AT+ADDRESS`.
    ///
    /// Nothing is persisted on the module (`AT+BAND` without its remember
    /// flag), so a test leaves it as a power cycle would find it.
    pub async fn connect(&self, address: u16) -> anyhow::Result<RadioLink> {
        let port = self.port()?;
        let stream = tokio_serial::new(port.to_string_lossy(), BAUD)
            .open_native_async()
            .map_err(|e| {
                anyhow::anyhow!(
                    "opening radio {:?} at {}: {e}",
                    self.spec.role,
                    port.display()
                )
            })?;
        let mut client = RylrClient::new(FromTokio::new(stream))
            .map_err(|e| anyhow::anyhow!("radio {:?}: {e:?}", self.spec.role))?;
        client.set_timeout(COMMAND_TIMEOUT);

        let role = &self.spec.role;
        let context = |step: &'static str| {
            move |e: rylr998::LoraError| anyhow::anyhow!("radio {role:?}: {step}: {e:?}")
        };
        client.ping().await.map_err(context("AT"))?;
        client
            .set_rf_frequency(self.spec.frequency_hz, false)
            .await
            .map_err(context("AT+BAND"))?;
        client
            .set_parameters(SPREADING_FACTOR, BANDWIDTH, CODING_RATE, PREAMBLE_SYMBOLS)
            .await
            .map_err(context("AT+PARAMETER"))?;
        client
            .set_network_id(NETWORK_ID)
            .await
            .map_err(context("AT+NETWORKID"))?;
        client
            .set_address(address)
            .await
            .map_err(context("AT+ADDRESS"))?;
        Ok(RadioLink { client })
    }
}

/// A configured, open radio module.
pub struct RadioLink {
    client: RylrClient<FromTokio<SerialStream>>,
}

impl RadioLink {
    /// `AT+SEND` `payload` to `address` (`0` broadcasts).
    pub async fn send(&mut self, address: u16, payload: &str) -> anyhow::Result<()> {
        self.client
            .send_data(address, payload)
            .await
            .map_err(|e| anyhow::anyhow!("AT+SEND to {address:#06x}: {e:?}"))
    }

    /// The next packet the module delivers within `window`, or `None` if it
    /// delivers none.
    ///
    /// `None` is a result, not an error: "nothing arrived" is exactly what a
    /// test of the module's filtering asserts.
    pub async fn receive_within(
        &mut self,
        window: Duration,
    ) -> anyhow::Result<Option<ReceivedPacket>> {
        match tokio::time::timeout(window, self.client.listen_for_packet()).await {
            Err(_elapsed) => Ok(None),
            Ok(Ok(packet)) => Ok(Some(packet)),
            Ok(Err(e)) => Err(anyhow::anyhow!("listening for a packet: {e:?}")),
        }
    }
}
