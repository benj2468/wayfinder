//! List the CDC-ACM devices this machine has, as the harness sees them.
//!
//! The first thing to run when a board is plugged in and a test still skips:
//! it separates "the kernel did not enumerate it" from "the inventory names
//! the wrong serial", which look the same from a test result.

fn main() -> anyhow::Result<()> {
    let devices = wayfinder_hil::usb::enumerate()?;
    if devices.is_empty() {
        println!("no CDC-ACM devices with a USB serial");
        return Ok(());
    }
    for d in &devices {
        println!("{:<16} usb = {}", d.node.display(), d.usb_serial);
    }
    Ok(())
}
