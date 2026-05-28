#![no_std]

extern crate alloc;

pub mod wayfinder_v1alpha {
    #[expect(unused_imports)]
    use alloc::vec::Vec;

    include!(concat!(env!("OUT_DIR"), "/wayfinder.v1alpha.rs"));
}

pub mod service;
