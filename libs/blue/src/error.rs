/// An error bringing up the SoftDevice's background tasks. Node-local and
/// only encountered at construction; `LinkT`'s own `send`/`recv` errors are
/// `LinkError`, not this type. (`Softdevice::enable` itself panics rather
/// than returning a `Result` on misuse, and it happens outside this crate —
/// the caller enables the SoftDevice and hands `NrfBleLink::new` an
/// already-`&'static` reference — so the only fallible step left here is the
/// scan task spawn.)
#[derive(Debug)]
pub enum BleError {
    /// Spawning the background BLE scan loop failed.
    ScanTaskSpawn,
}
