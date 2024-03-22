#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(unused)]


extern crate alloc;

use alloc::vec::Vec;
use log::debug;

pub mod bindings{
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "\\src\\bindings.rs"));
}
// #[no_mangle]
// pub extern "C" fn __clear_cache(){
//     debug!("调用");
// }

pub use bindings::*;