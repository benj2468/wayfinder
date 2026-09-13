//! ESP32 (Xtensa LX6) firmware: the bring-up "hello world" for a third board
//! family, printing over the UART a dev board's USB-serial bridge already
//! exposes.
//!
//! Deliberately not a mesh node yet — no [`wayfinder_embedded_driver::Driver`],
//! no link, no management port. What it establishes is the half of bringing up
//! a board family that nothing in the host workspace can: that the toolchain
//! fork, the sysroot built from source, `linkall.x` and the ESP-IDF image
//! header line up well enough for the ROM bootloader to start what we flash.
//! Printing `wayfinder-version`'s build identity is what makes that visible —
//! a banner naming the commit distinguishes "this image booted" from "some
//! older image is still on the part", which is the failure a silent hello world
//! cannot tell apart.
//!
//! The next step is what `bins/wayfinder-stm32f411` already does: give the
//! shared embedded driver a `LinkT` and a `Clock` and let the same routing core
//! run here.
//!
//! [`wayfinder_embedded_driver::Driver`]: https://docs.rs/wayfinder-embedded-driver

#![no_std]
#![no_main]

// The panic handler, linked for its side effect.
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::main;
use esp_hal::time::Duration;
use esp_hal::time::Instant;
use esp_println::println;

// The descriptor the ESP-IDF second-stage bootloader reads out of the image
// before starting it; see this crate's `Cargo.toml`.
esp_bootloader_esp_idf::esp_app_desc!();

/// Gap between heartbeat lines.
///
/// A heartbeat rather than a single greeting because the two failure modes this
/// image exists to separate look identical at boot: a line printed once could
/// come from an image that greeted and then faulted, while a line that keeps
/// arriving says the part is still executing.
const HEARTBEAT_MS: u64 = 1_000;

#[main]
fn main() -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    // Nothing is wired up yet; naming it keeps the bring-up sequence's shape
    // (`init` hands over every peripheral) visible for the driver that follows.
    let _ = peripherals;

    println!("wayfinder-esp32: hello world");
    println!(
        "build {} commit {}{}",
        wayfinder_version::VERSION,
        wayfinder_version::COMMIT,
        if wayfinder_version::DIRTY {
            " (dirty)"
        } else {
            ""
        }
    );

    let mut beats: u32 = 0;
    loop {
        // A busy wait, not a timer: this image links no executor and no time
        // driver, and adding either before there is anything to schedule would
        // be the wrong order to bring a board up in.
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(HEARTBEAT_MS) {}

        beats = beats.wrapping_add(1);
        println!("wayfinder-esp32: alive, {beats} beats");
    }
}
