//! Print the QR code `src/qr.rs` produces for a URI, as SVG on stdout.
//!
//! A development aid, not part of the dashboard: it exists so the encoder's
//! output can be handed to an *independent* scanner (`zbarimg`) and checked to
//! decode back to the string it was given. The unit tests assert the markup's
//! shape; only a real decoder proves the modules are right.
#[allow(
    clippy::expect_used,
    reason = "a dev-tool example: a bad argument should abort with its own message"
)]
fn main() {
    let uri = std::env::args().nth(1).expect("usage: emit_qr <text>");
    print!(
        "{}",
        wayfinder_web::qr::svg(&uri, "Authenticator setup code").expect("the text fits a QR code")
    );
}
