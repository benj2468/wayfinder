#![cfg_attr(not(test), no_std)]

use core::time::Duration;
use embedded_io_async::{Read, Write};
use heapless::String;
use thiserror::Error;
use tracing::trace;

#[derive(Error, Debug)]
pub enum LoraError {
    #[error("IO error")]
    Io,
    #[error("Module returned error code: {0}")]
    ModuleError(i32),
    #[error("Response format was invalid or unparseable")]
    InvalidResponse,
    #[error("Operation timed out waiting for module response")]
    Timeout,
}

/// Supported Spreading Factor configurations.
#[derive(Debug, Clone, Copy)]
pub enum SpreadingFactory {
    Sf5 = 5,
    Sf6 = 6,
    Sf7 = 7,
    Sf8 = 8,
    Sf9 = 9,
    Sf10 = 10,
    Sf11 = 11,
}

/// Supported RF bandwidth configurations.
#[derive(Debug, Clone, Copy)]
pub enum Bandwidth {
    Khz125 = 7,
    Khz250 = 8,
    Khz500 = 9,
}

/// Supported Coding Rate configurations.
#[derive(Debug, Clone, Copy)]
pub enum CodingRate {
    Cr45 = 45,
    Cr46 = 46,
    Cr47 = 47,
    Cr48 = 48,
}

/// Supported wireless working modes.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum WirelessMode {
    Transceiver = 0,
    Sleep = 1,
    SmartReceiving = 2,
}

/// Supported emc certification modes.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum EmcCertificationMode {
    Off = 0,
    UnModulated = 1,
    Modulated = 2,
}

/// Data structure representing asynchronously received packet data via +RCV.
#[derive(Debug, Clone)]
pub struct ReceivedPacket {
    pub address: u16,
    pub length: usize,
    pub data: String<240>,
    pub rssi: i32,
    pub snr: i32,
}

/// The core RYLR998/RYLR498 Client driver structure.
pub struct RylrClient<S> {
    stream: S,
    timeout: Duration,

    // The network ID for the client.
    network_id: u8,
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
    ) -> Result<String<256>, LoraError> {
        self.send_raw(cmd).await?;

        self.expect(expected).await
    }

    async fn read_line(&mut self, line: &mut String<256>) -> Result<(), LoraError> {
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

    /// Helper function to internally dispatch an explicit string sequence and read its immediate raw response.
    /// And expect a series of specific responses
    async fn expect(&mut self, expected: &str) -> Result<String<256>, LoraError> {
        let mut line = String::<256>::new();

        // TODO(bjc) Change this client into a big state machine...

        loop {
            line.clear();
            self.read_line(&mut line).await?;
            trace!("read_line: line={line:?}");

            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            if trimmed.starts_with(expected) {
                return Ok(line.clone());
            }

            if trimmed.starts_with("+ERR=") {
                return Err(LoraError::ModuleError(0)); // Simplify for now
            }
        }
    }

    async fn send_cmd_expect_ok(&mut self, cmd: &str) -> Result<String<256>, LoraError> {
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
    /// Payload length is parsed automatically. Address 0 broadcasts.
    pub async fn send_data(&mut self, target_address: u16, data: &str) -> Result<(), LoraError> {
        let payload_length = data.len();
        if payload_length > 240 {
            return Err(LoraError::InvalidResponse);
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
    pub async fn listen_for_packet(&mut self) -> Result<ReceivedPacket, LoraError> {
        let mut line = String::<256>::new();

        loop {
            line.clear();
            self.read_line(&mut line).await?;
            let trimmed = line.trim();

            if let Some(clean_target) = trimmed.strip_prefix("+RCV=") {
                // Format payload: +RCV=<Address>,<Length>,<Data>,<RSSI>,<SNR>
                // Manual parsing to avoid Vec
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

                return Ok(ReceivedPacket {
                    address,
                    length,
                    data,
                    rssi,
                    snr,
                });
            }
        }
    }
}
