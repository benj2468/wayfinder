//! A `no_std` async driver for the REYAX RYLR998/RYLR498 LoRa modules.
//!
//! [`RylrClient`] wraps the module's AT-command interface over any
//! [`embedded_io_async`] serial port — configuring the radio, sending data, and
//! receiving packets with RSSI/SNR. With the `link` feature it also exposes a
//! `LinkT` mesh-interface adapter that treats LoRa as a shared broadcast medium
//! (the mesh filters on the embedded [`Mac`](interfaces::frame::Mac)).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use core::time::Duration;
use embedded_io_async::{Read, Write};
use heapless::{Deque, String};
use thiserror::Error;
use tracing::{trace, warn};

/// An error from the RYLR module driver.
#[derive(Error, Debug)]
pub enum LoraError {
    /// A read or write on the underlying serial port failed.
    #[error("IO error")]
    Io,
    /// The module replied with a `+ERR=<code>` response; carries the code.
    #[error("Module returned error code: {0}")]
    ModuleError(i32),
    /// A module response could not be parsed into the expected form.
    #[error("Response format was invalid or unparseable")]
    InvalidResponse,
    /// The payload exceeds the module's maximum transmit size.
    #[error("Request too large")]
    RequestTooLarge,
    /// No response arrived within the command's timeout.
    #[error("Operation timed out waiting for module response")]
    Timeout,
}

/// Supported Spreading Factor configurations.
#[derive(Debug, Clone, Copy)]
pub enum SpreadingFactory {
    /// Spreading factor 5 (fastest, shortest range).
    Sf5 = 5,
    /// Spreading factor 6.
    Sf6 = 6,
    /// Spreading factor 7.
    Sf7 = 7,
    /// Spreading factor 8.
    Sf8 = 8,
    /// Spreading factor 9.
    Sf9 = 9,
    /// Spreading factor 10.
    Sf10 = 10,
    /// Spreading factor 11 (slowest, longest range).
    Sf11 = 11,
}

/// Supported RF bandwidth configurations.
#[derive(Debug, Clone, Copy)]
pub enum Bandwidth {
    /// 125 kHz channel bandwidth.
    Khz125 = 7,
    /// 250 kHz channel bandwidth.
    Khz250 = 8,
    /// 500 kHz channel bandwidth.
    Khz500 = 9,
}

/// Supported Coding Rate configurations.
#[derive(Debug, Clone, Copy)]
pub enum CodingRate {
    /// Coding rate 4/5.
    Cr45 = 1,
    /// Coding rate 4/6.
    Cr46 = 2,
    /// Coding rate 4/7.
    Cr47 = 3,
    /// Coding rate 4/8.
    Cr48 = 4,
}

/// Supported wireless working modes.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum WirelessMode {
    /// Normal transmit/receive operation.
    Transceiver = 0,
    /// Low-power sleep; the module wakes on serial activity.
    Sleep = 1,
    /// Smart receiving power-saving mode.
    SmartReceiving = 2,
}

/// Supported emc certification modes.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum EmcCertificationMode {
    /// EMC test mode disabled (normal operation).
    Off = 0,
    /// Emit an unmodulated carrier for EMC certification testing.
    UnModulated = 1,
    /// Emit a modulated carrier for EMC certification testing.
    Modulated = 2,
}

/// Data structure representing asynchronously received packet data via +RCV.
#[derive(Debug, Clone)]
pub struct ReceivedPacket {
    /// Source module address the packet was sent from.
    pub address: u16,
    /// Length of the payload in bytes.
    pub length: usize,
    /// Payload bytes as received (module delivers ASCII/UTF-8 text).
    pub data: String<240>,
    /// Received signal strength indicator, in dBm.
    pub rssi: i32,
    /// Signal-to-noise ratio, in dB.
    pub snr: i32,
}

#[cfg(feature = "link")]
mod link;

#[cfg(feature = "link")]
mod frag;

/// Parse a `+RCV=<Address>,<Length>,<Data>,<RSSI>,<SNR>` line (the `+RCV=`
/// prefix must already be present) into a [`ReceivedPacket`].
fn parse_rcv(line: &str) -> Result<ReceivedPacket, LoraError> {
    // Format payload: +RCV=<Address>,<Length>,<Data>,<RSSI>,<SNR>
    // Manual parsing to avoid Vec
    let clean_target = line
        .strip_prefix("+RCV=")
        .ok_or(LoraError::InvalidResponse)?;
    let mut parts = clean_target.split(',');

    let address_str = parts.next().ok_or(LoraError::InvalidResponse)?;
    let length_str = parts.next().ok_or(LoraError::InvalidResponse)?;
    let data_str = parts.next().ok_or(LoraError::InvalidResponse)?;
    let rssi_str = parts.next().ok_or(LoraError::InvalidResponse)?;
    let snr_str = parts.next().ok_or(LoraError::InvalidResponse)?;

    let address = address_str
        .parse::<u16>()
        .map_err(|_| LoraError::InvalidResponse)?;
    let length = length_str
        .parse::<usize>()
        .map_err(|_| LoraError::InvalidResponse)?;
    let mut data = String::<240>::new();
    data.push_str(data_str)
        .map_err(|_| LoraError::InvalidResponse)?;
    let rssi = rssi_str
        .parse::<i32>()
        .map_err(|_| LoraError::InvalidResponse)?;
    let snr = snr_str
        .parse::<i32>()
        .map_err(|_| LoraError::InvalidResponse)?;

    Ok(ReceivedPacket {
        address,
        length,
        data,
        rssi,
        snr,
    })
}

/// Depth of [`RylrClient::rx_queue`]: how many unsolicited `+RCV` packets can
/// sit buffered while a command response is awaited before the oldest is
/// evicted to make room. Not derived from a hard protocol limit — chosen as a
/// small multiple of a fragmented message's typical fragment count (a few) so
/// one busy command wait can absorb an interleaved multi-fragment OGM without
/// evicting; each queued `ReceivedPacket` costs ~250 bytes (dominated by its
/// `String<240>`), so this is a deliberately modest bound, not an attempt at
/// an exact worst case.
const RX_QUEUE_DEPTH: usize = 8;

/// Longest single line (a command response or an unsolicited `+RCV=...`) the
/// module can send us. Sized for the worst case: the module's own 240-char
/// maximum `<Data>` field, plus the largest `<Address>`/`<RSSI>`/`<SNR>`
/// fields the AT protocol allows (`+RCV=65535,240,<240 chars>,-130,-20` is
/// ~264 chars) — comfortably covers a maximal on-air fragment once the
/// `link` feature is base64-encoding one into a `+RCV` line.
const LINE_BUF_LEN: usize = 300;

/// The core RYLR998/RYLR498 Client driver structure.
pub struct RylrClient<S> {
    stream: S,
    timeout: Duration,

    // The network ID for the client.
    network_id: u8,

    // Unsolicited `+RCV` packets read by `next_line` while some other reader
    // (`expect`) was waiting for a command response, buffered here so
    // `listen_for_packet` still observes them instead of them being silently
    // dropped. Bounded: the oldest is evicted once full.
    rx_queue: Deque<ReceivedPacket, RX_QUEUE_DEPTH>,

    // Scratch buffer holding the most recently reassembled mesh frame,
    // borrowed by `LinkT::recv`.  Only present when the `link` feature wires
    // this client onto a mesh; sized for the largest frame `frag::Reassembler`
    // will reassemble.
    #[cfg(feature = "link")]
    rx_frame: [u8; frag::MAX_REASSEMBLED_LEN],

    // Fragmentation message-id counter, incremented once per `LinkT::send`
    // call; see `link::RylrClient::next_msg_id`.
    #[cfg(feature = "link")]
    msg_id_ctr: u8,

    // Bounded table of in-flight fragment reassemblies fed by `LinkT::recv`.
    #[cfg(feature = "link")]
    reassembler: frag::Reassembler,
}

impl<S> RylrClient<S>
where
    S: Read + Write,
{
    /// Instantiate a new client connection over the designated serial port path.
    pub fn new(stream: S) -> Result<Self, LoraError> {
        Ok(Self {
            stream,
            timeout: Duration::from_secs(3),
            network_id: 18,
            rx_queue: Deque::new(),
            #[cfg(feature = "link")]
            rx_frame: [0u8; frag::MAX_REASSEMBLED_LEN],
            #[cfg(feature = "link")]
            msg_id_ctr: 0,
            #[cfg(feature = "link")]
            reassembler: frag::Reassembler::new(),
        })
    }

    /// Set an internal command-response interaction timeout modifier.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Helper function to internally dispatch an explicit string sequence and read its immediate raw response.
    async fn send_raw(&mut self, cmd: &str) -> Result<(), LoraError> {
        trace!("send_raw: cmd={cmd}");

        self.stream
            .write_all(cmd.as_bytes())
            .await
            .map_err(|_| LoraError::Io)?;
        if !cmd.ends_with("\r\n") {
            self.stream
                .write_all(b"\r\n")
                .await
                .map_err(|_| LoraError::Io)?;
        }
        self.stream.flush().await.map_err(|_| LoraError::Io)?;

        Ok(())
    }

    /// Helper function to internally dispatch an explicit string sequence and read its immediate raw response.
    /// And expect a series of specific responses
    async fn send_cmd_expect(
        &mut self,
        cmd: &str,
        expected: &str,
    ) -> Result<String<LINE_BUF_LEN>, LoraError> {
        self.send_raw(cmd).await?;

        self.expect(expected).await
    }

    async fn read_line(&mut self, line: &mut String<LINE_BUF_LEN>) -> Result<(), LoraError> {
        let mut buf = [0u8; 1];
        loop {
            self.stream
                .read_exact(&mut buf)
                .await
                .map_err(|_| LoraError::Io)?;
            let c = buf[0] as char;
            if c == '\n' {
                break;
            }
            if c != '\r' {
                line.push(c).map_err(|_| LoraError::InvalidResponse)?;
            }
        }
        Ok(())
    }

    /// Read and classify one line off the serial port, skipping blank lines
    /// transparently (never meaningful to either caller below).
    ///
    /// An unsolicited `+RCV=` line is parsed and pushed onto [`Self::rx_queue`]
    /// (evicting the oldest queued packet if full) rather than returned
    /// directly — this is what lets `listen_for_packet` still observe a
    /// packet that arrived while [`Self::expect`] was awaiting a command
    /// response, instead of it being silently dropped. Returns `None` in that
    /// case; `Some(line)` for any other (non-blank) line.
    async fn next_line(&mut self) -> Result<Option<String<LINE_BUF_LEN>>, LoraError> {
        loop {
            let mut line = String::<LINE_BUF_LEN>::new();
            self.read_line(&mut line).await?;
            trace!(len = line.len(), "read_line");

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed.starts_with("+RCV=") {
                let packet = parse_rcv(trimmed)?;
                if self.rx_queue.is_full()
                    && let Some(evicted) = self.rx_queue.pop_front()
                {
                    warn!(
                        evicted_addr = evicted.address,
                        evicted_len = evicted.length,
                        queue_depth = RX_QUEUE_DEPTH,
                        "capacity eviction: rx_queue full, dropping oldest unsolicited packet"
                    );
                }
                self.rx_queue
                    .push_back(packet)
                    .unwrap_or_else(|_| unreachable!("just ensured room above"));
                return Ok(None);
            }

            return Ok(Some(line));
        }
    }

    /// Helper function to internally dispatch an explicit string sequence and read its immediate raw response.
    /// And expect a series of specific responses
    async fn expect(&mut self, expected: &str) -> Result<String<LINE_BUF_LEN>, LoraError> {
        loop {
            // `None` means the line was an unsolicited `+RCV=`, already
            // queued onto `rx_queue`; keep waiting for our own response.
            let Some(line) = self.next_line().await? else {
                continue;
            };
            let trimmed = line.trim();
            if trimmed.starts_with(expected) {
                return Ok(line.clone());
            }
            if trimmed.starts_with("+ERR=") {
                return Err(LoraError::ModuleError(0)); // Simplify for now
            }
            // Any other unrecognized line is noise; keep waiting.
        }
    }

    async fn send_cmd_expect_ok(&mut self, cmd: &str) -> Result<String<LINE_BUF_LEN>, LoraError> {
        self.send_cmd_expect(cmd, "+OK").await
    }

    /// 1. Test if the module can respond to Commands.
    pub async fn ping(&mut self) -> Result<(), LoraError> {
        self.send_cmd_expect_ok("AT").await?;
        Ok(())
    }

    /// 2. Software Reset (AT+RESET)
    pub async fn reset(&mut self) -> Result<(), LoraError> {
        self.send_cmd_expect("AT+RESET", "+RESET").await?;
        self.expect("+READY").await?;
        Ok(())
    }

    /// 3. Set the wireless work mode
    pub async fn set_mode(&mut self, mode: WirelessMode) -> Result<(), LoraError> {
        let mut cmd = String::<32>::new();
        let _ = core::fmt::write(&mut cmd, format_args!("AT+MODE={}", mode as u8));
        self.send_cmd_expect_ok(&cmd).await?;
        Ok(())
    }

    /// 4. Set the UART baud rate.
    pub async fn set_baud_rate(&mut self, baud_rate: u32) -> Result<(), LoraError> {
        let mut cmd = String::<32>::new();
        let _ = core::fmt::write(&mut cmd, format_args!("AT+IPR={}", baud_rate));
        let mut expected = String::<32>::new();
        let _ = core::fmt::write(&mut expected, format_args!("+IPR={}", baud_rate));
        self.send_cmd_expect(&cmd, &expected).await?;
        Ok(())
    }

    /// 5. Set RF Frequency.
    pub async fn set_rf_frequency(
        &mut self,
        frequency: u32,
        remember_in_flash: bool,
    ) -> Result<(), LoraError> {
        let mut cmd = String::<32>::new();
        if remember_in_flash {
            let _ = core::fmt::write(&mut cmd, format_args!("AT+BAND={},M", frequency));
        } else {
            let _ = core::fmt::write(&mut cmd, format_args!("AT+BAND={}", frequency));
        };
        self.send_cmd_expect_ok(&cmd).await?;
        Ok(())
    }

    /// 6. Set the RF parameters.
    pub async fn set_parameters(
        &mut self,
        spreading_factor: SpreadingFactory,
        bandwidth: Bandwidth,
        coding_rate: CodingRate,
        programming_preamble: u8,
    ) -> Result<(), LoraError> {
        let mut cmd = String::<64>::new();
        let _ = core::fmt::write(
            &mut cmd,
            format_args!(
                "AT+PARAMETER={},{},{},{}",
                spreading_factor as u8, bandwidth as u8, coding_rate as u8, programming_preamble
            ),
        );
        self.send_cmd_expect_ok(&cmd).await?;
        Ok(())
    }

    /// 7. Set the address of the RYLR998/RYLR498 module.
    pub async fn set_address(&mut self, address: u16) -> Result<(), LoraError> {
        let mut cmd = String::<32>::new();
        let _ = core::fmt::write(&mut cmd, format_args!("AT+ADDRESS={}", address));
        self.send_cmd_expect_ok(&cmd).await?;
        Ok(())
    }

    /// 8. Set the network ID group function (AT+NETWORKID)
    pub async fn set_network_id(&mut self, network_id: u8) -> Result<(), LoraError> {
        let mut cmd = String::<32>::new();
        let _ = core::fmt::write(&mut cmd, format_args!("AT+NETWORKID={}", network_id));
        self.send_cmd_expect_ok(&cmd).await?;
        self.network_id = network_id;
        Ok(())
    }

    /// 10. Set the RF output power (AT+CRFOP).
    pub async fn set_rf_output_power(&mut self, dbm: u8) -> Result<(), LoraError> {
        let mut cmd = String::<32>::new();
        let _ = core::fmt::write(&mut cmd, format_args!("AT+CRFOP={}", dbm));
        self.send_cmd_expect_ok(&cmd).await?;
        Ok(())
    }

    /// 11. Send data to the appointed address explicitly (AT+SEND).
    ///     Payload length is parsed automatically. Address 0 broadcasts.
    pub async fn send_data(&mut self, target_address: u16, data: &str) -> Result<(), LoraError> {
        let payload_length = data.len();
        if payload_length > 240 {
            return Err(LoraError::RequestTooLarge);
        }
        let mut cmd = String::<512>::new();
        let _ = core::fmt::write(
            &mut cmd,
            format_args!("AT+SEND={},{},{}", target_address, payload_length, data),
        );
        self.send_cmd_expect_ok(&cmd).await?;
        Ok(())
    }

    /// 13. To inquire module ID.
    pub async fn query_module_id(&mut self) -> Result<String<64>, LoraError> {
        let resp = self.send_cmd_expect("AT+UID?", "+UID=").await?;
        let mut uid = String::<64>::new();
        if let Some(clean) = resp.strip_prefix("+UID=") {
            uid.push_str(clean)
                .map_err(|_| LoraError::InvalidResponse)?;
        }
        Ok(uid)
    }

    /// Asynchronously read a line looking specifically for passive downstream incoming radio signals (`+RCV`).
    /// Use this loop setup when waiting passively for unexpected telemetry items.
    ///
    /// Checks [`Self::rx_queue`] first: a packet that arrived while a command
    /// response was being awaited (see [`Self::next_line`]) is delivered from
    /// there rather than being lost.
    pub async fn listen_for_packet(&mut self) -> Result<ReceivedPacket, LoraError> {
        if let Some(packet) = self.rx_queue.pop_front() {
            return Ok(packet);
        }
        loop {
            if self.next_line().await?.is_none() {
                return Ok(self
                    .rx_queue
                    .pop_front()
                    .unwrap_or_else(|| unreachable!("next_line just queued a packet")));
            }
        }
    }
}
