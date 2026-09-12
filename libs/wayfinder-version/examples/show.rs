//! Print the build identity this crate resolved.
//!
//! A convenience for bring-up and for verifying the build-environment injection
//! by hand: `cargo run -p wayfinder-version --example show`, optionally with
//! `WAYFINDER_BUILD_VERSION=… ` set to check the injected tier.

fn main() {
    println!(
        "version={} commit={} dirty={} source={:?}",
        wayfinder_version::VERSION,
        wayfinder_version::COMMIT,
        wayfinder_version::DIRTY,
        wayfinder_version::SOURCE,
    );
}
