use std::io;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_serial::{SerialPortBuilderExt, SerialStream};

#[derive(Error, Debug)]
pub enum LoraError {
    #[error("IO or Serial Error: {0}")]
    Io(#[from] io::Error),
    #[error("Serial configuration error: {0}")]
    Serial(#[from] tokio_serial::Error),
    #[error("Module returned error code: {0}")]
    ModuleError(i32),
    #[error("Response format was invalid or unparseable: {0}")]
    InvalidResponse(String),
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
    pub data: String,
    pub rssi: i32,
    pub snr: i32,
}

/// The core RYLR998/RYLR498 Client driver structure.
pub struct RylrClient {
    stream: SerialStream,
    timeout: Duration,

    // The network ID for the client.
    network_id: u8,
}

impl RylrClient {
    /// Instantiate a new client connection over the designated serial port path.
    pub fn new(port_path: &str, baud_rate: u32) -> Result<Self, LoraError> {
        let stream = tokio_serial::new(port_path, baud_rate).open_native_async()?;

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
        let mut raw_cmd = cmd.to_string();
        if !raw_cmd.ends_with("\r\n") {
            raw_cmd.push_str("\r\n");
        }

        // Split the stream to read and write concurrently if needed, using buffered readers
        let (_, mut writer) = tokio::io::split(&mut self.stream);

        // Write command out over UART
        writer.write_all(raw_cmd.as_bytes()).await?;
        writer.flush().await?;

        Ok(())
    }

    /// Helper function to internally dispatch an explicit string sequence and read its immediate raw response.
    /// And expect a series of specific responses
    async fn send_cmd_expect(&mut self, cmd: &str, expected: &str) -> Result<String, LoraError> {
        self.send_raw(cmd).await?;

        let (reader, _) = tokio::io::split(&mut self.stream);

        let mut buf_reader = BufReader::new(reader);

        let mut line = String::new();

        // Wrap reading loop inside a timeout block to prevent endless waiting
        tokio::time::timeout(self.timeout, async {
            loop {
                line.clear();
                buf_reader.read_line(&mut line).await?;
                let trimmed = line.trim();

                if trimmed.is_empty() {
                    continue;
                }

                if trimmed.starts_with(expected) {
                    return Ok(trimmed.to_string());
                }

                if trimmed.starts_with("+ERR=") {
                    if let Some(err_code_str) = trimmed.strip_prefix("+ERR=") {
                        if let Ok(code) = err_code_str.parse::<i32>() {
                            return Err(LoraError::ModuleError(code));
                        }
                    }
                    return Err(LoraError::InvalidResponse(trimmed.to_string()));
                }
            }
        })
        .await
        .map_err(|_| LoraError::Timeout)?
    }

    async fn send_cmd_expect_ok(&mut self, cmd: &str) -> Result<String, LoraError> {
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
        self.send_cmd_expect("AT+RESET", "+READY").await?;
        Ok(())
    }

    /// 3. Set the wireless work mode
    pub async fn set_mode(&mut self, mode: WirelessMode) -> Result<(), LoraError> {
        self.send_cmd_expect_ok(&format!("AT+MODE={}", mode as u8))
            .await?;
        Ok(())
    }

    /// 4. Set the UART baud rate.
    pub async fn set_baud_rate(&mut self, baud_rate: u32) -> Result<(), LoraError> {
        self.send_cmd_expect(
            &format!("AT+IPR={}", baud_rate),
            &format!("+IPR={}", baud_rate),
        )
        .await?;
        Ok(())
    }

    /// 5. Set RF Frequency.
    pub async fn set_rf_frequency(
        &mut self,
        frequency: u32,
        remember_in_flash: bool,
    ) -> Result<(), LoraError> {
        let cmd = if remember_in_flash {
            format!("AT+BAND={},M", frequency)
        } else {
            format!("AT+BAND={}", frequency)
        };
        self.send_cmd_expect_ok(&cmd).await?;
        Ok(())
    }

    /// 5.1. Set RF Frequency.
    pub async fn set_rf_frequency_memorized(&mut self, frequency: u32) -> Result<(), LoraError> {
        self.send_cmd_expect_ok(&format!("AT+BAND={},M", frequency))
            .await?;
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
        if self.network_id != 18 {
            if programming_preamble != 12 {
                return Err(LoraError::InvalidResponse(
                    "programming_preamble must be 12 for non-network_id 18".to_string(),
                ));
            }
        }
        self.send_cmd_expect_ok(&format!(
            "AT+PARAMETER={},{},{},{}",
            spreading_factor as u8, bandwidth as u8, coding_rate as u8, programming_preamble
        ))
        .await?;
        Ok(())
    }

    /// 7. Set the address of the RYLR998/RYLR498 module.
    pub async fn set_address(&mut self, address: u16) -> Result<(), LoraError> {
        self.send_cmd_expect_ok(&format!("AT+ADDRESS={}", address))
            .await?;
        Ok(())
    }

    /// 8. Set the network ID group function (AT+NETWORKID)
    pub async fn set_network_id(&mut self, network_id: u8) -> Result<(), LoraError> {
        if network_id < 3 || network_id > 15 || network_id != 18 {
            return Err(LoraError::InvalidResponse(
                "Network ID must be 3-15, or 18".to_string(),
            ));
        }
        self.send_cmd_expect_ok(&format!("AT+NETWORKID={}", network_id))
            .await?;
        self.network_id = network_id;
        Ok(())
    }

    /// 9. Set the domain password (AT+CPIN).
    pub async fn set_password(
        &mut self,
        hex_password: &str,
        remember_in_flash: bool,
    ) -> Result<(), LoraError> {
        let cmd = if remember_in_flash {
            format!("AT+CPIN={},M", hex_password)
        } else {
            format!("AT+CPIN={}", hex_password)
        };
        self.send_cmd_expect_ok(&cmd).await?;
        Ok(())
    }

    /// 10. Set the RF output power (AT+CRFOP).
    pub async fn set_rf_output_power(&mut self, dbm: u8) -> Result<(), LoraError> {
        self.send_cmd_expect_ok(&format!("AT+CRFOP={}", dbm))
            .await?;
        Ok(())
    }

    /// 11. Send data to the appointed address explicitly (AT+SEND).
    /// Payload length is parsed automatically. Address 0 broadcasts.
    pub async fn send_data(&mut self, target_address: u16, data: &str) -> Result<(), LoraError> {
        let payload_length = data.len();
        if payload_length > 240 {
            return Err(LoraError::InvalidResponse(
                "Payload length exceeds 240 bytes".to_string(),
            ));
        }
        let cmd = format!("AT+SEND={},{},{}", target_address, payload_length, data);
        self.send_cmd_expect_ok(&cmd).await?;
        Ok(())
    }

    /// 13. To inquire module ID.
    pub async fn query_module_id(&mut self) -> Result<String, LoraError> {
        let resp = self.send_cmd_expect("AT+UID?", "+UID=").await?;
        let uid = resp
            .strip_prefix("+UID=")
            .ok_or_else(|| LoraError::InvalidResponse("Unable to remove UID prefix".into()))?;
        Ok(uid.into())
    }

    /// 14. Internal Query commands wrapping checking syntax `AT+COMMAND?`
    pub async fn query_firmware_version(&mut self) -> Result<String, LoraError> {
        let resp = self.send_cmd_expect("AT+VER?", "+VER=").await?;
        let ver = resp
            .strip_prefix("+VER=")
            .ok_or_else(|| LoraError::InvalidResponse("Unable to remove VER prefix".into()))?;
        Ok(ver.into())
    }

    /// 15. Set all current parameters to manufacturer defaults (AT+FACTORY).
    pub async fn factory_reset(&mut self) -> Result<(), LoraError> {
        self.send_cmd_expect("AT+FACTORY", "+FACTORY").await?;
        Ok(())
    }

    /// 18. Set the EMC certification mode
    pub async fn set_emc_certification_mode(
        &mut self,
        mode: EmcCertificationMode,
    ) -> Result<(), LoraError> {
        self.send_cmd_expect_ok(&format!("AT+FCC={}", mode as u8))
            .await?;
        Ok(())
    }

    /// Asynchronously read a line looking specifically for passive downstream incoming radio signals (`+RCV`).
    /// Use this loop setup when waiting passively for unexpected telemetry items.
    pub async fn listen_for_packet(&mut self) -> Result<ReceivedPacket, LoraError> {
        let (reader, _) = tokio::io::split(&mut self.stream);
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();
            buf_reader.read_line(&mut line).await?;
            let trimmed = line.trim();

            if let Some(clean_target) = trimmed.strip_prefix("+RCV=") {
                // Format payload: +RCV=<Address>,<Length>,<Data>,<RSSI>,<SNR>
                let parts: Vec<&str> = clean_target.split(',').map(|s| s.trim()).collect();

                if parts.len() >= 5 {
                    let address = parts[0]
                        .parse::<u16>()
                        .map_err(|_| LoraError::InvalidResponse(trimmed.to_string()))?;
                    let length = parts[1]
                        .parse::<usize>()
                        .map_err(|_| LoraError::InvalidResponse(trimmed.to_string()))?;
                    let data = parts[2].to_string();
                    let rssi = parts[3]
                        .parse::<i32>()
                        .map_err(|_| LoraError::InvalidResponse(trimmed.to_string()))?;
                    let snr = parts[4]
                        .parse::<i32>()
                        .map_err(|_| LoraError::InvalidResponse(trimmed.to_string()))?;

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
}
