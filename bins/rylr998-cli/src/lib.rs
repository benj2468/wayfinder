//! CLI for driving a physical RYLR998/RYLR498 module over its AT-command
//! serial interface — a flexible replacement for a fixed example script,
//! used to debug the `rylr998` driver against real hardware.
//!
//! Each subcommand maps 1:1 onto one `RylrClient` method, so a failure here
//! isolates whether a bug is in the driver's AT-command framing/parsing
//! itself, as opposed to something higher up the stack (fragmentation, the
//! mesh `LinkT` adapter, routing).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use embedded_io_async::Read;
use embedded_io_async::Write;
use rylr998::Bandwidth;
use rylr998::CodingRate;
use rylr998::LoraError;
use rylr998::ReceivedPacket;
use rylr998::RylrClient;
use rylr998::SpreadingFactory;
use rylr998::WirelessMode;

/// Command-line interface for `rylr998-cli`.
#[derive(Parser, Debug)]
#[command(
    name = "rylr998-cli",
    version,
    about = "Debug a RYLR998/RYLR498 LoRa module over its AT-command serial interface"
)]
pub struct Cli {
    /// Serial device path the module is attached to.
    #[arg(long, short = 'p', global = true, default_value = "/dev/ttyUSB0")]
    pub port: String,
    /// UART baud rate to open the port at.
    #[arg(long, short = 'b', global = true, default_value_t = 115_200)]
    pub baud: u32,
    /// Per-command response timeout, in seconds.
    #[arg(long, global = true, default_value_t = 2)]
    pub timeout_secs: u64,
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// One RYLR998 AT command, exposed 1:1 with a [`RylrClient`] method.
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Confirm the module responds to commands (`AT`).
    Ping,
    /// Software-reset the module and wait for it to report ready (`AT+RESET`).
    Reset,
    /// Query the module's UID (`AT+UID?`).
    ModuleId,
    /// Set the wireless work mode (`AT+MODE`).
    SetMode {
        /// New wireless work mode.
        #[arg(value_enum)]
        mode: WirelessModeArg,
    },
    /// Set the UART baud rate the module itself expects (`AT+IPR`). This does
    /// not change the rate this CLI opens the port at — reconnect with
    /// `--baud` set to the new value afterward.
    SetBaudRate {
        /// New baud rate.
        baud_rate: u32,
    },
    /// Set the RF frequency, in Hz (`AT+BAND`).
    SetRfFrequency {
        /// New frequency, in Hz.
        frequency_hz: u32,
        /// Persist the new frequency across power cycles.
        #[arg(long)]
        remember: bool,
    },
    /// Set spreading factor, bandwidth, coding rate, and preamble length
    /// (`AT+PARAMETER`).
    SetParameters {
        /// New spreading factor.
        #[arg(value_enum)]
        spreading_factor: SpreadingFactorArg,
        /// New RF bandwidth.
        #[arg(value_enum)]
        bandwidth: BandwidthArg,
        /// New coding rate.
        #[arg(value_enum)]
        coding_rate: CodingRateArg,
        /// Programming preamble length.
        preamble: u8,
    },
    /// Set this module's own address (`AT+ADDRESS`).
    SetAddress {
        /// New address.
        address: u16,
    },
    /// Set the network-id group filter (`AT+NETWORKID`).
    SetNetworkId {
        /// New network id.
        network_id: u8,
    },
    /// Set RF output power, in dBm (`AT+CRFOP`).
    SetRfOutputPower {
        /// New output power, in dBm.
        dbm: u8,
    },
    /// Send a text payload to a target address (`AT+SEND`); address 0 broadcasts.
    Send {
        /// Destination module address (0 = broadcast).
        target_address: u16,
        /// Payload text.
        data: String,
    },
    /// Listen for incoming packets and print each as it arrives.
    Listen {
        /// Stop after receiving this many packets instead of running until
        /// interrupted (Ctrl-C).
        #[arg(long)]
        count: Option<usize>,
    },
}

/// [`WirelessMode`], mirrored so `clap` can derive [`ValueEnum`] for it —
/// `rylr998` is `no_std`-first and doesn't depend on `clap`.
#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum WirelessModeArg {
    /// Normal transmit/receive operation.
    Transceiver,
    /// Low-power sleep; the module wakes on serial activity.
    Sleep,
    /// Smart receiving power-saving mode.
    SmartReceiving,
}

impl From<WirelessModeArg> for WirelessMode {
    fn from(value: WirelessModeArg) -> Self {
        match value {
            WirelessModeArg::Transceiver => WirelessMode::Transceiver,
            WirelessModeArg::Sleep => WirelessMode::Sleep,
            WirelessModeArg::SmartReceiving => WirelessMode::SmartReceiving,
        }
    }
}

/// [`SpreadingFactory`], mirrored for [`ValueEnum`] (see [`WirelessModeArg`]).
#[derive(ValueEnum, Debug, Clone, Copy)]
#[allow(missing_docs, reason = "self-explanatory numeric spreading factors")]
pub enum SpreadingFactorArg {
    Sf5,
    Sf6,
    Sf7,
    Sf8,
    Sf9,
    Sf10,
    Sf11,
}

impl From<SpreadingFactorArg> for SpreadingFactory {
    fn from(value: SpreadingFactorArg) -> Self {
        match value {
            SpreadingFactorArg::Sf5 => SpreadingFactory::Sf5,
            SpreadingFactorArg::Sf6 => SpreadingFactory::Sf6,
            SpreadingFactorArg::Sf7 => SpreadingFactory::Sf7,
            SpreadingFactorArg::Sf8 => SpreadingFactory::Sf8,
            SpreadingFactorArg::Sf9 => SpreadingFactory::Sf9,
            SpreadingFactorArg::Sf10 => SpreadingFactory::Sf10,
            SpreadingFactorArg::Sf11 => SpreadingFactory::Sf11,
        }
    }
}

/// [`Bandwidth`], mirrored for [`ValueEnum`] (see [`WirelessModeArg`]).
#[derive(ValueEnum, Debug, Clone, Copy)]
#[allow(missing_docs, reason = "self-explanatory numeric bandwidths")]
pub enum BandwidthArg {
    Khz125,
    Khz250,
    Khz500,
}

impl From<BandwidthArg> for Bandwidth {
    fn from(value: BandwidthArg) -> Self {
        match value {
            BandwidthArg::Khz125 => Bandwidth::Khz125,
            BandwidthArg::Khz250 => Bandwidth::Khz250,
            BandwidthArg::Khz500 => Bandwidth::Khz500,
        }
    }
}

/// [`CodingRate`], mirrored for [`ValueEnum`] (see [`WirelessModeArg`]).
#[derive(ValueEnum, Debug, Clone, Copy)]
#[allow(missing_docs, reason = "self-explanatory numeric coding rates")]
pub enum CodingRateArg {
    Cr45,
    Cr46,
    Cr47,
    Cr48,
}

impl From<CodingRateArg> for CodingRate {
    fn from(value: CodingRateArg) -> Self {
        match value {
            CodingRateArg::Cr45 => CodingRate::Cr45,
            CodingRateArg::Cr46 => CodingRate::Cr46,
            CodingRateArg::Cr47 => CodingRate::Cr47,
            CodingRateArg::Cr48 => CodingRate::Cr48,
        }
    }
}

/// Render one received packet the way [`run_command`]'s `Listen` prints it.
pub fn format_packet(packet: &ReceivedPacket) -> String {
    format!(
        "from {}: {:?} (rssi {} dBm, snr {} dB)",
        packet.address, packet.data, packet.rssi, packet.snr
    )
}

/// Run `command` against `client`, printing a human-readable result. Generic
/// over the transport so tests can drive it against `rylr998-sim`'s in-process
/// simulator instead of a real serial port.
pub async fn run_command<S>(client: &mut RylrClient<S>, command: &Command) -> Result<(), LoraError>
where
    S: Read + Write + Send,
{
    match command {
        Command::Ping => {
            client.ping().await?;
            println!("OK: module responded to AT");
        }
        Command::Reset => {
            client.reset().await?;
            println!("OK: module reset and ready");
        }
        Command::ModuleId => {
            let uid = client.query_module_id().await?;
            println!("UID: {uid}");
        }
        Command::SetMode { mode } => {
            client.set_mode((*mode).into()).await?;
            println!("OK: mode set");
        }
        Command::SetBaudRate { baud_rate } => {
            client.set_baud_rate(*baud_rate).await?;
            println!("OK: module baud rate set to {baud_rate}");
        }
        Command::SetRfFrequency {
            frequency_hz,
            remember,
        } => {
            client.set_rf_frequency(*frequency_hz, *remember).await?;
            println!("OK: RF frequency set to {frequency_hz} Hz");
        }
        Command::SetParameters {
            spreading_factor,
            bandwidth,
            coding_rate,
            preamble,
        } => {
            client
                .set_parameters(
                    (*spreading_factor).into(),
                    (*bandwidth).into(),
                    (*coding_rate).into(),
                    *preamble,
                )
                .await?;
            println!("OK: RF parameters set");
        }
        Command::SetAddress { address } => {
            client.set_address(*address).await?;
            println!("OK: address set to {address}");
        }
        Command::SetNetworkId { network_id } => {
            client.set_network_id(*network_id).await?;
            println!("OK: network id set to {network_id}");
        }
        Command::SetRfOutputPower { dbm } => {
            client.set_rf_output_power(*dbm).await?;
            println!("OK: RF output power set to {dbm} dBm");
        }
        Command::Send {
            target_address,
            data,
        } => {
            client.send_data(*target_address, data).await?;
            println!("OK: sent {} byte(s) to {target_address}", data.len());
        }
        Command::Listen { count } => {
            let mut received = 0usize;
            loop {
                match client.listen_for_packet().await {
                    Ok(packet) => {
                        println!("{}", format_packet(&packet));
                        received += 1;
                        if count.is_some_and(|limit| received >= limit) {
                            break;
                        }
                    }
                    Err(err) => eprintln!("error receiving packet: {err}"),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_packet_includes_address_data_and_signal_quality() {
        let packet = ReceivedPacket {
            address: 51,
            length: 5,
            data: heapless::String::try_from("hello").unwrap(),
            rssi: -42,
            snr: 9,
        };
        let rendered = format_packet(&packet);
        assert!(rendered.contains("51"));
        assert!(rendered.contains("hello"));
        assert!(rendered.contains("-42"));
        assert!(rendered.contains('9'));
    }
}
