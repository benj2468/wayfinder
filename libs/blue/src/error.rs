/// An error bringing up the SoftDevice's background tasks — construction only;
/// `send`/`recv` fail with `LinkError` instead. The caller enables the
/// SoftDevice (which panics rather than returning a `Result`) before handing
/// `NrfBleLink::new` a reference, so the scan-task spawn is all that is left
/// to fail here.
#[derive(Debug)]
pub enum BleError {
    /// Spawning the background BLE scan loop failed.
    ScanTaskSpawn,
}
