//! The management port: `wayfinder-server`'s embedded framing over UART0.
//!
//! This is how the board is observed and enrolled at all. `wayfinder-tui`,
//! `wayfinderctl --serial <port>` and `wayfinder-web` all speak the same
//! length-delimited prost envelope, and [`wayfinder_server::serve`] is already
//! transport-agnostic over any `embedded_io_async` byte stream — so this file
//! is the transport and nothing else. No new protocol.
//!
//! # Why a UART and not USB
//!
//! **The original ESP32 has no USB peripheral at all** — no USB-OTG (that is
//! the S2/S3), no USB-Serial-JTAG (C3/C6/H2/S3). What a dev board exposes at
//! its USB socket is an external CP2102 or CH340 bridge wired to UART0. So
//! there is no CDC-ACM function to imitate `libs/wayfinder-nrf`'s `usb_mgmt`
//! with, and no way to get one on this silicon. The host-visible outcome is
//! the same either way — a serial port — but the board side is a raw byte
//! stream with no notion of a connection.
//!
//! That difference shows up in exactly one place: the nRF waits for the host to
//! enumerate the device before serving, and treats a disconnect as the normal
//! state of a deployed node. A UART has neither event. There is no
//! `wait_connection` here and no session boundary; the port is simply always
//! open, and whether anything is listening is unknowable from this end.
//!
//! On an ESP32-C6 or S3 this becomes a real CDC-ACM device through esp-hal's
//! `UsbSerialJtag` with no bridge and no UART spent, which is the strongest
//! argument for a second ESP32 variant later.
//!
//! # UART0 carries the management API, and nothing else
//!
//! It is also where `esp-println` writes, and the two cannot share it: a boot
//! banner interleaved with a length-delimited frame desynchronises the
//! framing. The management API wins, and this board's `wayfinder-log` selects
//! **no text sink at all** — records go to the `GetLogs` ring and are read back
//! over this same port with `wayfinderctl logs`.
//!
//! That is the nRF dongle's posture rather than a compromise: a board with no
//! debug probe has its logs read over its management port regardless, and
//! spending a second UART and a second cable on a console would buy a
//! duplicate of what `GetLogs` already serves. What it costs is the window
//! before this port is up — a panic during bring-up prints nowhere, where the
//! nRF has a retained fault record in `.uninit` to re-emit on the next boot.
//! Building the equivalent here is worth doing and is not this ticket.
//!
//! # Authentication
//!
//! Unauthenticated, **by decision rather than by omission** — the same posture
//! `libs/wayfinder-hil` records for the nRF's mgmt port (#57). Physical access
//! to the cable is the boundary. Do not add a network-reachable transport on
//! top of this without revisiting that.

use embassy_time::Duration;
use embassy_time::Timer;
use esp_hal::Async;
use esp_hal::uart::Uart;
use tracing::debug;
use tracing::trace;
use tracing::warn;
use wayfinder_server::EmbeddedQueryTx;
use wayfinder_server::FrameError;
use wayfinder_server::serve;

/// How long to wait after a reset before reading again.
///
/// **This is not politeness, it is the only suspend point on the error path.**
/// `esp-hal`'s `read_exact_async` drains its receive buffer synchronously and
/// returns a pending RX error *before its first await*, so a line with a
/// standing error — a floating U0RXD, or a host that opened the port at the
/// wrong baud — resolves `Ready(Err)` every time. Without a yield here this
/// loop never returns `Pending`, and since [`run`] `join`s it with the router
/// on one task, the executor never gets to poll the router again: the node
/// keeps power, keeps its UART configured, and silently stops routing and
/// answering. The nRF's equivalent loop has the same backstop for the same
/// reason.
///
/// Long enough that a stuck line costs a handful of wake-ups a second rather
/// than thousands, short enough that a real client arriving right after a reset
/// is not kept waiting.
///
/// [`run`]: crate::main
const RESET_BACKOFF: Duration = Duration::from_millis(100);

/// Serve management requests off UART0 forever.
///
/// [`serve`] only returns by error, and every error it can return is about the
/// stream rather than about this node: a host that closed its end mid-frame, or
/// a length prefix that desynchronised the framing. Both are recoverable by
/// starting the next frame afresh, which is what looping does — the alternative
/// is a board that answers once and then goes quiet until it is power-cycled.
pub async fn serve_forever(uart: &mut Uart<'static, Async>, query_tx: &EmbeddedQueryTx<'_>) -> ! {
    loop {
        match serve(uart, query_tx).await {
            // The host closed the port, or the cable came out mid-frame. On a
            // UART this is indistinguishable from an idle line and is the
            // normal state of a deployed node, so it stays at `debug!`.
            Err(FrameError::UnexpectedEof | FrameError::Io(_)) => {
                debug!("management port stream reset");
            }
            // A peer-supplied length prefix desynchronised the stream —
            // reachable by whatever is on the other end of the cable, not a
            // node-local fault, so it stays below `error!`.
            Err(e @ FrameError::Oversized(_)) => {
                warn!(?e, "management link reset: oversized frame");
            }
            // A zero-length prefix: the stream is carrying something that is
            // not framing (a break, or an idle line read as zero bytes), and
            // there is no marker to resynchronise on. Reset rather than answer
            // it — see `read_frame`.
            //
            // **`trace!` and a backoff, not `debug!` and a retry.** This arm is
            // reached by whatever is on the other end of the cable, and the
            // failure mode that motivated the check delivers zero bytes
            // *continuously* — so re-entering immediately spins at line rate,
            // ~2,800 times a second at 115200 baud. Refusing the frame already
            // stops the flood on the wire; without the backoff the flood just
            // moves into the `GetLogs` ring, which on this board is the only
            // log sink there is, filling it with this line exactly when an
            // operator is reading it to find out what is wrong. CLAUDE.md's
            // logging rules put remote-reachable hot paths at `trace!` for
            // this reason.
            Err(FrameError::Empty) => {
                trace!("management link reset: zero-length frame");
            }
            Ok(()) => unreachable!("serve only returns via an error"),
        }
        // Every arm, not just the noisy one: see [`RESET_BACKOFF`]. A UART has
        // no `wait_connection` to block on the way the nRF's CDC-ACM port does,
        // so if this loop does not suspend, nothing in it ever will.
        Timer::after(RESET_BACKOFF).await;
    }
}
