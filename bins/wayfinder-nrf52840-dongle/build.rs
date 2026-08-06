//! Standard `cortex-m-rt` linker-script plumbing: copies `memory.x` into
//! `OUT_DIR` and puts it on the linker's search path so `link.x` (pulled in via
//! `.cargo/config.toml`'s `-C link-arg=-Tlink.x`) can find it.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out = &PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is always set by cargo"));
    File::create(out.join("memory.x"))
        .expect("OUT_DIR is always writable")
        .write_all(include_bytes!("memory.x"))
        .expect("OUT_DIR is always writable");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
}
