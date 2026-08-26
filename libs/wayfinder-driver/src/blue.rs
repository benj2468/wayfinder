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
//!
//! BlueZ is Linux's Bluetooth stack and has no counterpart elsewhere, so on
//! any other host this module is just the error-returning stub that keeps the
//! rest of the driver — and every node that builds links from a config —
//! compiling and testable there.

use blue::BleLinkParams;
use wayfinder::link::DynLinkT;

/// Build a mesh link over the host's BLE controller, type-erased as a
/// [`LinkT`](wayfinder::link::LinkT).
///
/// Fails at startup if BlueZ is unreachable (no `bluetoothd`, no permission
/// on the system bus) or the named adapter doesn't exist — a misconfigured
/// adapter is a startup error, not something to discover on the first frame.
///
/// On a non-Linux host it always fails: BLE here is BlueZ, which no other
/// operating system has. The signature is kept identical on every platform so
/// a node's config parsing and link-building code stays `cfg`-free — a
/// configured BLE link is then a startup error with a clear reason rather
/// than a compile error in the caller.
#[cfg(target_os = "linux")]
pub async fn build_ble_link(params: BleLinkParams) -> anyhow::Result<Box<DynLinkT<'static>>> {
    Ok(DynLinkT::new_box(blue::StdBleLink::new(params).await?))
}

/// The non-Linux counterpart of [`build_ble_link`]; see its documentation.
#[cfg(not(target_os = "linux"))]
pub async fn build_ble_link(_params: BleLinkParams) -> anyhow::Result<Box<DynLinkT<'static>>> {
    anyhow::bail!(
        "BLE mesh links are supported on Linux only (they are carried by BlueZ, \
         which this host does not have); remove the `ble` link from the config \
         or run this node on Linux"
    )
}
