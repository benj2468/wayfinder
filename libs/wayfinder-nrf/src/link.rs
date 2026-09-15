//! The board's mesh interfaces, behind one concrete [`LinkT`].

use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::link::LinkT;
use wayfinder::link::Received;

pub use nrf_ieee802154::Ieee802154Link;

pub use crate::usb_link::UsbNcmLink;

/// Dispatches [`LinkT`] across this board's mesh interfaces.
/// `wayfinder_embedded_driver::Driver` takes a fixed `[L; N]` of one concrete
/// link type; this is the "board-defined `enum` dispatching across mixed media"
/// its docs anticipate.
pub enum MeshLink {
    /// IEEE 802.15.4 over the chip's built-in radio.
    Dot15d4(Ieee802154Link),
    /// The USB host, reached as Ethernet over a CDC-NCM function. Point-to-point
    /// and wired, so unlike the radio it is neither lossy nor rate-limited
    /// — see [`crate::usb_link`].
    Usb(UsbNcmLink),
    /// This slot's medium is not attached. Today that is only the USB link on a
    /// board whose device stack failed to come up, which is a degraded node
    /// rather than a dead one (it still routes over the radio).
    ///
    /// [`LinkError::NotPresent`] rather than an error or an `Ok(0)`: the driver
    /// logs it at `trace!` and keeps it out of the transmit-rate estimator, so a
    /// board with no host attached neither `warn!`s once per OGM nor publishes a
    /// non-zero `tx_fps` for hardware that isn't there. `recv` never resolves,
    /// since nothing will arrive on a medium with nothing attached.
    Absent,
}

impl LinkT for MeshLink {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        match self {
            MeshLink::Dot15d4(link) => link.send(origin, data).await,
            MeshLink::Usb(link) => link.send(origin, data).await,
            MeshLink::Absent => Err(LinkError::NotPresent),
        }
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        match self {
            MeshLink::Dot15d4(link) => link.recv().await,
            MeshLink::Usb(link) => link.recv().await,
            MeshLink::Absent => core::future::pending().await,
        }
    }
}
