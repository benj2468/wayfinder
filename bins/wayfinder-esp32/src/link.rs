//! This board's mesh interfaces, behind one concrete [`LinkT`].
//!
//! The same shape `libs/wayfinder-nrf`'s `link.rs` has, and for the same
//! reason: [`Driver`](wayfinder_embedded_driver::Driver) takes a fixed
//! `[L; N]` of one concrete link type, so a board carrying mixed media
//! dispatches across them with an `enum`.
//!
//! **There is only one variant today, and that is the point of this file
//! existing anyway.** The ESP32's mesh medium is ESP-NOW, which is its own
//! ticket; until that lands the board routes over nothing, and the router still
//! has to have somewhere to send. Declaring the seam now means adding the radio
//! is one variant here plus one array slot in `main`, rather than a change to
//! the shape of the bring-up.

use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::link::LinkT;
use wayfinder::link::Received;

/// Dispatches [`LinkT`] across this board's mesh interfaces.
pub enum MeshLink {
    /// This slot's medium is not attached.
    ///
    /// [`LinkError::NotPresent`] rather than an error or an `Ok(0)`: the driver
    /// logs it at `trace!` and keeps it out of the transmit-rate estimator, so
    /// a board with no radio wired neither `warn!`s once per OGM nor publishes
    /// a non-zero `tx_fps` for hardware that isn't there. `recv` never
    /// resolves, since nothing will arrive on a medium with nothing attached.
    ///
    /// A router over nothing but this still does observable work — it paces its
    /// Trickle timers, ages its tables and emits the records that show the
    /// engine running, which is exactly what this board's first milestone is.
    Absent,
}

impl LinkT for MeshLink {
    async fn send(&mut self, _origin: Mac, _data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        match self {
            MeshLink::Absent => Err(LinkError::NotPresent),
        }
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        match self {
            MeshLink::Absent => core::future::pending().await,
        }
    }
}
