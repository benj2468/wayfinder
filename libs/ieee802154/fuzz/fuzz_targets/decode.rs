//! Fuzz [`ieee802154::decode`], the outermost boundary for any 802.15.4-radio
//! carrier (`at86rf233`/`nrf-ieee802154`): unwraps the MAC header and
//! zero-copy-parses the embedded `LinkFrame`. Zero setup, no crypto — just the
//! first thing touched off a raw radio buffer.
#![no_main]

use ieee802154::decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode(data);
});
