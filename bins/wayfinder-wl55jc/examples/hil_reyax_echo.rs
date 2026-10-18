//! Test-only firmware: answer a REYAX RYLR998 module in its own framing.
//!
//! Flashed by `libs/wayfinder-hil/tests/reyax_interop.rs`, never by hand and
//! never as a node — it routes nothing. It receives raw LoRa, and for every
//! packet that parses as a RYLR998 frame (`rylr998::air`):
//!
//! - payload beginning [`RAW_PREFIX`]: transmit the rest of the payload
//!   **without** a header, so the test can watch the module drop it;
//! - anything else: transmit the payload back, framed, from [`ECHO_ADDRESS`]
//!   to the sender's address.
//!
//! A packet that does not parse is dropped, so the board's own mesh traffic
//! from another WL55 never provokes an answer.
//!
//! # The frequency comes from the build, and has no default
//!
//! `WAYFINDER_LORA_FREQUENCY_HZ` at build time — the HIL test sets it from its
//! inventory, because which band is licence-free depends on where the rig is.
//! Built without it (as `just clippy-wl55jc` does), the image boots, logs an
//! error and never transmits, rather than picking some region's band.
//!
//! The PHY settings otherwise match the mesh node (`src/main.rs`): SF7,
//! 125 kHz, CR 4/8, an 8-symbol preamble and the LoRa private sync word — the
//! one a RYLR998 at its default `AT+NETWORKID=18` was measured to hear.

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_stm32::bind_interrupts;
use embassy_stm32::spi::Spi;
use embassy_time::Delay;
use embedded_alloc::LlffHeap as Heap;
use lora_phy::LoRa;
use lora_phy::RxMode;
use lora_phy::mod_params::Bandwidth;
use lora_phy::mod_params::CodingRate;
use lora_phy::mod_params::SpreadingFactor;
use lora_phy::sx126x::Sx126x;
use panic_halt as _;
use rylr998::air;
use rylr998::air::AirFrame;
use tracing::error;
use tracing::info;
use tracing::trace;
use wayfinder_wl55jc::PREAMBLE_SYMBOLS;
use wayfinder_wl55jc::RadioParts;

/// The address every echo is sent from. Duplicated in
/// `libs/wayfinder-hil/tests/reyax_interop.rs`, which asserts it — this crate
/// is its own workspace, so the two cannot share a constant.
const ECHO_ADDRESS: u16 = 0x0A55;

/// A payload starting with this is answered *unframed*. Duplicated in the HIL
/// test, as [`ECHO_ADDRESS`] is.
const RAW_PREFIX: &[u8] = b"raw:";

/// Transmit power in dBm: the mesh node's figure. A bench test wants the two
/// radios a hand-width apart, not range.
const OUTPUT_POWER_DBM: i32 = 14;

/// The carrier frequency the test built this image for, or `None` if it was
/// built without one.
const FREQUENCY_HZ: Option<u32> = parse_hz(option_env!("WAYFINDER_LORA_FREQUENCY_HZ"));

/// `str::parse` is not `const`; this is, so a malformed value is a build-time
/// `None` rather than a runtime surprise.
const fn parse_hz(text: Option<&str>) -> Option<u32> {
    let Some(text) = text else { return None };
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let digit = bytes[i];
        if !digit.is_ascii_digit() {
            return None;
        }
        value = match value.checked_mul(10) {
            Some(v) => match v.checked_add((digit - b'0') as u32) {
                Some(v) => v,
                None => return None,
            },
            None => return None,
        };
        i += 1;
    }
    Some(value)
}

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// `tracing-core`'s bookkeeping is the only user, as on the node.
const HEAP_SIZE_BYTES: usize = 2 * 1024;

bind_interrupts!(struct Irqs {
    SUBGHZ_RADIO => wayfinder_wl55jc::SubghzIrqHandler;
    DMA1_CHANNEL1 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::DMA1_CH1>;
    DMA1_CHANNEL2 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::DMA1_CH2>;
});

/// Wait forever without transmitting: the outcome for any bring-up failure.
async fn park() -> ! {
    core::future::pending().await
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    // SAFETY: called once, before anything can allocate, over a `static mut`
    // region nothing else references.
    unsafe {
        static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE_BYTES] =
            [core::mem::MaybeUninit::uninit(); HEAP_SIZE_BYTES];
        #[allow(static_mut_refs)]
        HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE_BYTES);
    }
    wayfinder_log::init();

    let Some(frequency_hz) = FREQUENCY_HZ else {
        error!(
            "built without a valid WAYFINDER_LORA_FREQUENCY_HZ; not transmitting -- \
             the HIL test builds this image itself"
        );
        park().await
    };

    let p = embassy_stm32::init_primary(
        wayfinder_wl55jc::clock_config(),
        &wayfinder_wl55jc::SHARED_DATA,
    );
    let RadioParts {
        spi,
        interface,
        sx_config,
    } = wayfinder_wl55jc::radio_parts(
        Spi::new_subghz(p.SUBGHZSPI, p.DMA1_CH1, p.DMA1_CH2, Irqs),
        p.PC3,
        p.PC4,
        p.PC5,
    );

    let mut lora = match LoRa::new(Sx126x::new(spi, interface, sx_config), false, Delay).await {
        Ok(lora) => lora,
        Err(e) => {
            error!(?e, "echo: radio bring-up failed");
            park().await
        }
    };
    let Ok(modulation) = lora.create_modulation_params(
        SpreadingFactor::_7,
        Bandwidth::_125KHz,
        CodingRate::_4_8,
        frequency_hz,
    ) else {
        error!(frequency_hz, "echo: modulation parameters refused");
        park().await
    };
    let Ok(rx_params) =
        lora.create_rx_packet_params(PREAMBLE_SYMBOLS, false, u8::MAX, true, false, &modulation)
    else {
        error!("echo: rx packet parameters refused");
        park().await
    };
    let Ok(mut tx_params) =
        lora.create_tx_packet_params(PREAMBLE_SYMBOLS, false, true, false, &modulation)
    else {
        error!("echo: tx packet parameters refused");
        park().await
    };
    if let Err(e) = lora.init().await {
        error!(?e, "echo: radio init failed");
        park().await
    }

    info!(frequency_hz, address = ECHO_ADDRESS, "echo: listening");

    let mut rx = [0u8; u8::MAX as usize];
    let mut tx = [0u8; u8::MAX as usize];
    loop {
        if let Err(e) = lora
            .prepare_for_rx(RxMode::Continuous, &modulation, &rx_params)
            .await
        {
            error!(?e, "echo: entering rx failed");
            park().await
        }
        let len = match lora.rx(&rx_params, &mut rx).await {
            Ok((len, _status)) => len as usize,
            Err(e) => {
                trace!(?e, "drop: radio receive error");
                continue;
            }
        };
        let Ok(frame) = air::parse(&rx[..len]) else {
            trace!(len, "drop: not a rylr998 frame");
            continue;
        };

        let reply_len = match frame.payload.strip_prefix(RAW_PREFIX) {
            Some(raw) => {
                tx[..raw.len()].copy_from_slice(raw);
                raw.len()
            }
            None => {
                let reply = AirFrame {
                    dst: frame.src,
                    src: ECHO_ADDRESS,
                    payload: frame.payload,
                };
                match air::encode(&reply, &mut tx) {
                    Ok(n) => n,
                    Err(e) => {
                        trace!(?e, "drop: echo does not fit a frame");
                        continue;
                    }
                }
            }
        };
        let raw = frame.payload.starts_with(RAW_PREFIX);

        if let Err(e) = lora
            .prepare_for_tx(
                &modulation,
                &mut tx_params,
                OUTPUT_POWER_DBM,
                &tx[..reply_len],
            )
            .await
        {
            trace!(?e, "drop: preparing transmit failed");
            continue;
        }
        match lora.tx().await {
            Ok(()) => trace!(src = frame.src, len = reply_len, raw, "echo: sent"),
            Err(e) => trace!(?e, "drop: transmit failed"),
        }
    }
}
