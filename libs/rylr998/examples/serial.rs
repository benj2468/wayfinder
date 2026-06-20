use embedded_io_adapters::tokio_1::FromTokio;
use rylr998::{Bandwidth, RylrClient};
use std::time::Duration;
use tokio_serial::SerialPortBuilderExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Establish standard connection to your platform's mapped USB interface
    let stream = tokio_serial::new("/dev/ttyUSB0", 115200).open_native_async()?;
    let mut client = RylrClient::new(FromTokio::new(stream))?;
    client.set_timeout(Duration::from_secs(2));

    println!("Pinging RYLR transceiver module...");
    client.ping().await?;
    println!("Module responded to commands successfully.");

    // 2. Set Device Addresses and Parameters
    println!("Configuring LoRa Network Settings...");
    client.set_address(50).await?;
    client.set_network_id(18).await?;
    client
        .set_parameters(
            rylr998::SpreadingFactory::Sf7,
            Bandwidth::Khz125,
            rylr998::CodingRate::Cr48,
            15,
        )
        .await?;

    // 3. Dispatch a Test Broadcast Packet
    println!("Sending message to target node...");
    client.send_data(51, "HELLO").await?;
    println!("Message sent!");

    // 4. Fall backward into a dedicated receiver monitoring thread block
    println!("Entering active receiver telemetry monitoring track loop...");
    loop {
        match client.listen_for_packet().await {
            Ok(packet) => {
                println!(
                    "Received Packet From Node ID [{}]: '{}' (RSSI: {} dBm, SNR: {})",
                    packet.address, packet.data, packet.rssi, packet.snr
                );
            }
            Err(e) => eprintln!("Telemetry reception tracking slip error: {:?}", e),
        }
    }
}
