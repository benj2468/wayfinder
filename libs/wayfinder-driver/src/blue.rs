//! Helper for building a mesh link over a Linux host's Bluetooth controller,
//! carrying frames as BLE connectionless advertisements through BlueZ.
//!
//! Thin by design: unlike the serial-attached RYLR998 (see [`crate::rylr998`],
//! which owns reconnect/reconfigure logic), the BlueZ backend is a D-Bus
//! client, so a controller disappearing and coming back is `bluetoothd`'s
//! problem to absorb — the link's own scan loop already retries its discovery
//! session, and each `send` registers a fresh advertisement rather than
//! holding long-lived state that could go stale. All this adds is the
//! type erasure the driver's link array needs.

use blue::BleLinkParams;
use blue::StdBleLink;
use wayfinder::link::DynLinkT;

/// Build a mesh link over the host's BLE controller, type-erased as a
/// [`LinkT`](wayfinder::link::LinkT).
///
/// Fails at startup if BlueZ is unreachable (no `bluetoothd`, no permission
/// on the system bus) or the named adapter doesn't exist — a misconfigured
/// adapter is a startup error, not something to discover on the first frame.
pub async fn build_ble_link(params: BleLinkParams) -> anyhow::Result<Box<DynLinkT<'static>>> {
    Ok(DynLinkT::new_box(StdBleLink::new(params).await?))
}
