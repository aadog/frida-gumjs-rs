#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

pub mod error;
pub mod CpuContext;
pub mod process;
pub mod module;
pub mod range_details;
pub mod memory_range;
pub mod script;
pub mod g_object;
pub mod interceptor;

use std::ffi::{c_char, c_void, CStr};
use std::fmt::{Display, Formatter, LowerHex, UpperHex};
use frida_gumjs_sys::{gum_deinit_embedded, gum_init_embedded};
use crate::error::Error;



pub fn init_embedded(){
    unsafe{gum_init_embedded()};
}
pub fn deinit_embedded(){
    unsafe{gum_deinit_embedded()};
}
pub fn g_main_context_get_thread_default()->*mut frida_gumjs_sys::GMainContext{
    unsafe{frida_gumjs_sys::_frida_g_main_context_default()}
}
pub fn g_main_context_pending(context: *mut frida_gumjs_sys::GMainContext)->bool{
    unsafe{frida_gumjs_sys::_frida_g_main_context_pending(context)!=0}
}
pub fn g_main_context_iteration(context: *mut frida_gumjs_sys::GMainContext,may_block:bool)->bool{
    let mut bk =0;
    if may_block{
        bk=1;
    }
    unsafe{frida_gumjs_sys::_frida_g_main_context_iteration(context,bk)!=0}
}


#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct NativePointer(pub *mut c_void);

impl NativePointer {
    /// Check if the pointer is NULL.
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl From<&NativePointer> for *mut c_void {
    fn from(other: &NativePointer) -> Self {
        other.0
    }
}

impl From<NativePointer> for *mut c_void {
    fn from(other: NativePointer) -> Self {
        other.0
    }
}

impl TryFrom<NativePointer> for String {
    type Error = Error;

    fn try_from(ptr: NativePointer) -> Result<Self, Error> {
        if ptr.is_null() {
            Err(Error::MemoryAccessError)
        } else {
            unsafe {
                Ok(
                    Self::from_utf8_lossy(CStr::from_ptr(ptr.0 as *const c_char).to_bytes())
                        .into_owned(),
                )
            }
        }
    }
}

impl AsRef<NativePointer> for NativePointer {
    fn as_ref(&self) -> &NativePointer {
        self
    }
}

impl LowerHex for NativePointer {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&(self.0 as usize), f)
    }
}

impl UpperHex for NativePointer {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&(self.0 as usize), f)
    }
}

impl Display for NativePointer {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&(self.0 as usize), f)
    }
}