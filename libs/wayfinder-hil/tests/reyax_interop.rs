//! A NUCLEO-WL55JC and a REYAX RYLR998 talking over real RF, and the one rule
//! that decides whether they can.
//!
//! # What this pins
//!
//! The WL55 drives its LoRa radio raw, so it can put any bytes on the air; the
//! RYLR998 hides its radio behind AT commands. Measured on the bench
//! (2026-10-03), with the PHY settings matched:
//!
//! - every `AT+SEND` goes on air behind a five-byte header,
//!   `[dst_lo, dst_hi, src_lo, src_hi, len]` (`rylr998::air`);
//! - the module's firmware **silently drops any packet without that header** —
//!   no `+RCV`, no `+ERR`. A WL55 node's ordinary mesh frames were sent within
//!   half a second of framed ones, on the same settings, and never surfaced.
//!
//! The second fact is the one worth a hardware test: it lives in REYAX's
//! firmware, nothing in this repository can observe it except a real module,
//! and a module firmware update could change it without a word.
//!
//! # How a board with no management API is driven
//!
//! It is not driven: it is *replaced*. The WL55 has no management port (it
//! does not fit in flash; design 25 §9), so this test builds and flashes
//! `hil_reyax_echo`, a test-only firmware that answers every framed packet with
//! a framed copy of its payload, and — when the payload begins with
//! [`RAW_PREFIX`] — answers with the remainder *unframed* instead. The RYLR998
//! is then the only thing the test talks to.
//!
//! That leaves the board running the echo firmware afterwards, not a mesh
//! node. Reflash it (`cargo run --release` in `bins/wayfinder-wl55jc`) before
//! using it as one.

use std::time::Duration;

use wayfinder_hil::BoardKind;
use wayfinder_hil::Rig;
use wayfinder_hil::firmware;
use wayfinder_hil::radio::RadioLink;

/// The address the echo firmware transmits from, and so the source every echo
/// must carry. Duplicated in `bins/wayfinder-wl55jc/examples/hil_reyax_echo.rs`
/// — that crate is its own workspace, so the two cannot share a constant.
const ECHO_ADDRESS: u16 = 0x0A55;

/// The address the test sets on the RYLR998, so an echo addressed back to it
/// is distinguishable from a broadcast.
const MODULE_ADDRESS: u16 = 0x0101;

/// A payload starting with this asks the echo firmware to answer *without* the
/// header. Duplicated in the example, as [`ECHO_ADDRESS`] is.
const RAW_PREFIX: &str = "raw:";

/// How long one echo is given to come back.
///
/// A short SF7/125 kHz packet is ~50 ms on air each way; the rest is the
/// module's UART and the firmware's turnaround. Generous on purpose — a radio
/// test that flakes on timing teaches people to ignore it.
const ECHO_TIMEOUT: Duration = Duration::from_secs(3);

/// How long "nothing arrives" is watched for before it counts as silence.
///
/// Several times [`ECHO_TIMEOUT`], since this is the assertion a slow echo
/// would falsely pass.
const SILENCE_WINDOW: Duration = Duration::from_secs(8);

/// How many framed pings each run sends. More than one, and each is retried
/// once, so a single lost packet is not a failed test: the claim is "framed
/// traffic flows", not "no packet is ever lost".
const PINGS: usize = 3;

/// Skip unless both the WL55 and the radio are attached, otherwise flash the
/// echo firmware at the radio's frequency and connect to the module.
async fn echo_rig() -> anyhow::Result<Option<RadioLink>> {
    let rig = Rig::load()?;
    let (Some(board), Some(radio)) = (rig.board("wl55"), rig.radio("lora")) else {
        return Ok(None);
    };
    anyhow::ensure!(
        board.spec().kind == BoardKind::Stm32wl55Nucleo,
        "role \"wl55\" is a {:?}; the echo firmware only exists for the NUCLEO-WL55JC",
        board.spec().kind
    );

    // Built here rather than by a recipe, because the frequency is the
    // inventory's to choose: the band that is licence-free depends on where
    // the rig is (`Inventory` refuses a radio without one).
    let elf = firmware::build_example(
        "bins/wayfinder-wl55jc",
        "hil_reyax_echo",
        &[(
            "WAYFINDER_LORA_FREQUENCY_HZ",
            &radio.spec().frequency_hz.to_string(),
        )],
    )?;
    board.flash(&elf)?;

    Ok(Some(radio.connect(MODULE_ADDRESS).await?))
}

/// Send `payload` to the echo firmware and wait for one packet back.
async fn round_trip(
    link: &mut RadioLink,
    payload: &str,
) -> anyhow::Result<Option<rylr998::ReceivedPacket>> {
    link.send(ECHO_ADDRESS, payload).await?;
    link.receive_within(ECHO_TIMEOUT).await
}

/// **Framed traffic crosses in both directions.** The module hears the WL55
/// when, and because, it frames its packets the module's way; and the WL55
/// parses the module's header well enough to answer the right address.
#[tokio::test]
#[ignore = "needs hardware: a NUCLEO-WL55JC (\"wl55\") and a RYLR998 (\"lora\")"]
async fn a_rylr998_and_the_wl55_exchange_framed_packets() -> anyhow::Result<()> {
    let Some(mut link) = echo_rig().await? else {
        return Ok(());
    };

    for n in 0..PINGS {
        let payload = format!("ping-{n}");
        let echo = match round_trip(&mut link, &payload).await? {
            Some(echo) => echo,
            None => round_trip(&mut link, &payload).await?.ok_or_else(|| {
                anyhow::anyhow!(
                    "no echo of {payload:?} after a retry -- if nothing echoes at all, check the \
                     radio's frequency_hz matches what was flashed, and that the board did not \
                     boot its ROM bootloader (power-cycle it once after a mass erase)"
                )
            })?,
        };
        assert_eq!(
            echo.address, ECHO_ADDRESS,
            "echo of {payload:?} from the wrong address"
        );
        assert_eq!(echo.data.as_str(), payload, "echo payload");
    }
    Ok(())
}

/// **The module drops a packet with no header, and says nothing.** Then a
/// framed packet still crosses, so the silence was the module's filter and not
/// a dead link.
///
/// If this starts failing because an unframed echo *arrives*, REYAX changed
/// their firmware: `rylr998::air`'s module docs and design 25 §4.4's
/// interoperability argument both need revisiting.
#[tokio::test]
#[ignore = "needs hardware: a NUCLEO-WL55JC (\"wl55\") and a RYLR998 (\"lora\")"]
async fn a_rylr998_silently_drops_a_packet_without_its_header() -> anyhow::Result<()> {
    let Some(mut link) = echo_rig().await? else {
        return Ok(());
    };

    // Ten bytes that cannot pass for a header: read as one, the length byte
    // is `A` (65) against five remaining bytes.
    link.send(ECHO_ADDRESS, &format!("{RAW_PREFIX}NOHEADER-1"))
        .await?;
    if let Some(heard) = link.receive_within(SILENCE_WINDOW).await? {
        anyhow::bail!(
            "the module delivered a reply that should have gone out unframed ({heard:?}). Either \
             REYAX's firmware no longer drops headerless packets, or `hil_reyax_echo` framed its \
             reply -- a payload still carrying {RAW_PREFIX:?} points at the latter"
        );
    }

    // The control: the same link, framed, still works.
    let control = "control-after-raw";
    let echo = match round_trip(&mut link, control).await? {
        Some(echo) => echo,
        None => round_trip(&mut link, control).await?.ok_or_else(|| {
            anyhow::anyhow!("no framed echo after the raw request; the silence proves nothing")
        })?,
    };
    assert_eq!(echo.address, ECHO_ADDRESS);
    assert_eq!(echo.data.as_str(), control);
    Ok(())
}
