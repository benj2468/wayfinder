//! The kernel TAP device as a driver [`FrameIo`] carrier.
//!
//! `tun_rs::AsyncDevice` is a foreign type and [`FrameIo`] is a foreign trait,
//! so the orphan rule forces a local newtype to bridge the two.

use async_trait::async_trait;
use wayfinder_driver::FrameIo;

/// A kernel TUN/TAP device presented to the driver as a host-frame transport.
pub struct TapDevice(pub tun_rs::AsyncDevice);

#[async_trait]
impl FrameIo for TapDevice {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(buf).await
    }
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.send(buf).await
    }
}
