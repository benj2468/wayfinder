//! Fuzz [`ieee802154::accept_fragment`], the outermost boundary for any
//! 802.15.4-radio carrier (`at86rf233`/`nrf-ieee802154`): it validates the MAC
//! header, parses the fragment header, and drives reassembly — everything a
//! raw radio buffer touches before the router sees a `LinkFrame`.
//!
//! The reassembler is deliberately *persistent* across inputs rather than
//! rebuilt per call. Reassembly is stateful (capacity eviction, duplicate
//! indices, a key whose declared fragment count changes mid-message), and a
//! fresh table each time would never reach any of it. Zero setup, no crypto.
#![no_main]

use std::cell::RefCell;

use ieee802154::Ieee802154Reassembler;
use ieee802154::MAX_REASSEMBLED_LEN;
use ieee802154::accept_fragment;
use ieee802154::decode_frame;
use interfaces::link::LinkMetrics;
use libfuzzer_sys::fuzz_target;

thread_local! {
    static REASSEMBLER: RefCell<Ieee802154Reassembler> =
        RefCell::new(Ieee802154Reassembler::new());
}

fuzz_target!(|data: &[u8]| {
    let mut out = [0u8; MAX_REASSEMBLED_LEN];
    REASSEMBLER.with(|r| {
        if let Some((len, _)) =
            accept_fragment(&mut r.borrow_mut(), data, LinkMetrics::default(), &mut out)
        {
            // A completed reassembly is handed straight to the frame parse on
            // the real path, so fuzz that edge too: a corrupted reassembly
            // (colliding short addresses) must fail here, not panic.
            let _ = decode_frame(&out[..len]);
        }
    });
});
