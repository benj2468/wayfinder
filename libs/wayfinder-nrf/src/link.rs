//! The board's mesh interfaces, behind one concrete [`LinkT`].

use embedded_io_async::Read;
use embedded_io_async::Write;
use rylr998::RylrClient;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::link::LinkT;
use wayfinder::link::Received;

pub use blue::NrfBleLink;

pub use crate::usb_link::UsbNcmLink;

/// Dispatches [`LinkT`] across this board's mesh interfaces.
/// `wayfinder_embedded_driver::Driver` takes a fixed `[L; N]` of one concrete
/// link type; this is the "board-defined `enum` dispatching across mixed media"
/// its docs anticipate.
#[expect(clippy::large_enum_variant, reason = "typed instead of boxed")]
pub enum MeshLink<S> {
    /// A RYLR998 LoRa module, over the UART carrying its AT-command protocol.
    Rylr(RylrClient<S>),
    /// Connectionless BLE advertising broadcast over the chip's built-in radio.
    Ble(NrfBleLink),
    /// The USB host, reached as Ethernet over a CDC-NCM function. Point-to-point
    /// and wired, so unlike the two radios it is neither lossy nor rate-limited
    /// — see [`crate::usb_link`].
    Usb(UsbNcmLink),
    /// No RYLR998 module was detected at boot on this slot's UART. An absent
    /// external module is an expected shape (a BLE-only deployment), not a
    /// fault, so this keeps the link array's size fixed at compile time while
    /// contributing nothing.
    ///
    /// [`LinkError::NotPresent`] rather than an error or an `Ok(0)`: the driver
    /// logs it at `trace!` and keeps it out of the transmit-rate estimator, so a
    /// BLE-only board neither `warn!`s once per OGM nor publishes a non-zero
    /// `tx_fps` for hardware that isn't attached. `recv` never resolves, since
    /// nothing will arrive on a medium with nothing attached.
    Absent,
}

impl<S> LinkT for MeshLink<S>
where
    S: Read + Write + Send,
{
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        match self {
            MeshLink::Rylr(link) => link.send(origin, data).await,
            MeshLink::Ble(link) => link.send(origin, data).await,
            MeshLink::Usb(link) => link.send(origin, data).await,
            MeshLink::Absent => Err(LinkError::NotPresent),
        }
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        match self {
            MeshLink::Rylr(link) => link.recv().await,
            MeshLink::Ble(link) => link.recv().await,
            MeshLink::Usb(link) => link.recv().await,
            MeshLink::Absent => core::future::pending().await,
        }
    }
}
