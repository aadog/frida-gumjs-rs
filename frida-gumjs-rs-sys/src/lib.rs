#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(unused)]


extern crate alloc;

use alloc::vec::Vec;
use log::debug;
#[cfg(any(target_arch = "aarch64",target_arch = "x86_64"))]
pub mod bindings{
    include!("bindings64.rs");
    //include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
#[cfg(any(target_arch = "arm",target_arch = "x86"))]
pub mod bindings{
    include!("bindings.rs");
    //include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
pub use bindings::*;