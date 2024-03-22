#![allow(unused)]

use std::alloc::{alloc, Layout};
use std::cell::UnsafeCell;
use std::error::Error;
use std::ffi;
use std::ffi::{c_long, c_ulong, c_void, CStr, CString};
use std::io::{Bytes, Write};
use std::mem::{size_of, size_of_val};
use std::ops::{Deref, Index};
use std::os::raw::c_int;
use std::ptr::{null, null_mut, slice_from_raw_parts, slice_from_raw_parts_mut};
use cstr_core::c_char;
use frida_gumjs_rs_sys::{_frida_g_bytes_new, GBytes, GCancellable, gchar, gpointer, gsize, GumScriptBackend, GumScriptMessageHandler, malloc, memset, strcpy, tm, u_long};
use simple_error::{bail, SimpleError};
use log::debug;
use crate::g_object::GObject;
use crate::NativePointer;

unsafe extern "C" fn call_on_message<T:ScriptMessageHandler>(
    message: *const gchar,
    _data: *mut frida_gumjs_sys::GBytes,
    user_data: *mut c_void,
) {
    let handler:&mut T=&mut *(user_data as *mut T);
    let s_message=CStr::from_ptr(message).to_str().unwrap_or_default();
    let mut data:Vec<u8>=vec![];
    if !_data.is_null(){
        let mut d_size:gsize=0;
        let d=frida_gumjs_sys::_frida_g_bytes_get_data(_data,&mut d_size);
        if d_size>0{
            data.write_all(&*slice_from_raw_parts::<u8>(
                d as *mut _,
                d_size as usize,
            ));
        }
    }
    handler.on_message(
        s_message,
        &data
    );
}
unsafe extern "C" fn call_on_debug_message<T:ScriptDebugMessageHandler>(
    message: *const gchar,
    user_data: *mut c_void,
) {
    let handler:&mut T=&mut *(user_data as *mut T);
    let s_message=CStr::from_ptr(message).to_str().unwrap_or_default();
    handler.on_debug_message(
        s_message,
    );
}

pub trait ScriptMessageHandler {
    fn on_message(&self, message: &str,data:&Vec<u8>);
}
pub trait ScriptDebugMessageHandler {
    fn on_debug_message(&self, message: &str);
}

pub struct Script {
    inner: *mut frida_gumjs_sys::GumScript,
}

impl GObject for Script {
    fn un_ref(&self) {
        unsafe { frida_gumjs_sys::_frida_g_object_unref(self.inner.cast()) };
    }
}


impl Script {
    pub fn v8()->*mut GumScriptBackend{
        unsafe{
            frida_gumjs_sys::gum_script_backend_obtain_v8()
        }
    }
    pub fn qjs()->*mut GumScriptBackend{
        unsafe{
            frida_gumjs_sys::gum_script_backend_obtain_qjs()
        }
    }
    pub fn create_qjs_script(backend:*mut frida_gumjs_sys::GumScriptBackend,name: &str, source: &str) -> Result<Script, Box<dyn std::error::Error>>{
        Self::create_script(backend,name,source)
    }
    pub fn create_v8_script(backend:*mut frida_gumjs_sys::GumScriptBackend,name: &str, source: &str) -> Result<Script, Box<dyn std::error::Error>>{
        Self::create_script(backend,name,source)
    }
    pub fn create_script(eng:*mut GumScriptBackend,name: &str, source: &str) -> Result<Script, Box<dyn std::error::Error>> {
        let mut backend:*mut GumScriptBackend=null_mut();
        backend = unsafe { frida_gumjs_sys::gum_script_backend_obtain_qjs() };

        let mut error: *mut frida_gumjs_sys::GError = null_mut();
        let c_name = CString::new(name).unwrap();
        let c_source = CString::new(source).unwrap();

        let gum_script = unsafe {
            frida_gumjs_sys::gum_script_backend_create_sync(
                backend,
                c_name.as_bytes_with_nul().as_ptr() as _,
                c_source.as_bytes_with_nul().as_ptr() as _,
                null_mut(),
                null_mut(),
                &mut error,
            )
        };
        if !error.is_null() {
            let message: String = unsafe { CStr::from_ptr((*error).message) }.to_str().unwrap_or_default().to_string();
            unsafe { frida_gumjs_sys::_frida_g_error_free(error) };
            bail!(message);
        } else {
            Ok(Script {
                inner: gum_script,
            })
        }
    }
    pub fn load(&self) {
        unsafe { frida_gumjs_sys::gum_script_load_sync(self.inner, null_mut()) };
    }
    pub fn unload(&self) {
        unsafe { frida_gumjs_sys::gum_script_unload_sync(self.inner, null_mut()) };
    }
    pub fn on_message<T:ScriptMessageHandler>(&self, handler: &T) {
        unsafe {
            let callback = Some(std::mem::transmute(call_on_message::<T> as *mut c_void));
            frida_gumjs_sys::gum_script_set_message_handler(
                self.inner,
                callback,
                handler as *const _ as *mut c_void,
                None,
            )
        };
    }
    pub fn on_debug_message<T:ScriptDebugMessageHandler>(&self, handler: &T) {
        unsafe {
            let callback = Some(std::mem::transmute(call_on_debug_message::<T> as *mut c_void));
            frida_gumjs_sys::gum_script_set_debug_message_handler(
                self.inner,
                callback,
                handler as *const _ as *mut c_void,
                None,
            )
        };
    }
}