/// An error bringing up the SoftDevice's background tasks. Node-local and
/// only encountered at construction; `LinkT`'s own `send`/`recv` errors are
/// `LinkError`, not this type. (`Softdevice::enable` itself panics rather
/// than returning a `Result` on misuse, so the only fallible steps here are
/// the two task spawns — distinguished so a bring-up failure log names which
/// one failed, rather than an uninformative unit value.)
#[derive(Debug)]
pub enum BleError {
    /// Spawning the SoftDevice's background event-pump task failed.
    SoftdeviceTaskSpawn,
    /// Spawning the background BLE scan loop failed.
    ScanTaskSpawn,
}
