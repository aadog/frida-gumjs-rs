#![allow(unused)]

use std::error::Error;
use std::ptr;
use std::ptr::{null, null_mut};
use frida_gumjs_rs_sys::GumReplaceReturn;
use log::debug;
use simple_error::bail;
use crate::NativePointer;

#[derive(Debug)]
pub struct Interceptor{
    interceptor:*mut frida_gumjs_rs_sys::GumInterceptor
}
unsafe impl Send for Interceptor{}
unsafe impl Sync for Interceptor{}
impl Interceptor{
    pub fn obtain()->Interceptor{
        Interceptor{
            interceptor:unsafe{frida_gumjs_rs_sys::gum_interceptor_obtain()}
        }
    }
    pub fn begin_transaction(&self) {
        unsafe { frida_gumjs_rs_sys::gum_interceptor_begin_transaction(self.interceptor) };
    }
    pub fn end_transaction(&self) {
        unsafe { frida_gumjs_rs_sys::gum_interceptor_end_transaction(self.interceptor) };
    }
    pub fn revert(&mut self, function: NativePointer) {
        unsafe {
            frida_gumjs_rs_sys::gum_interceptor_revert(self.interceptor, function.0);
        }
    }
    pub fn replace(
        &self,
        function: NativePointer,
        replacement: NativePointer,
        replacement_data: NativePointer,
    ) -> Result<NativePointer,Box<dyn std::error::Error>> {
        let mut original_function = NativePointer(ptr::null_mut());
        unsafe {
            let ret=frida_gumjs_rs_sys::gum_interceptor_replace(
                self.interceptor,
                function.0,
                replacement.0,
                replacement_data.0,
                &mut original_function.0,
            );
            match ret {
                frida_gumjs_rs_sys::GumReplaceReturn_GUM_REPLACE_OK => Ok(original_function),
                frida_gumjs_rs_sys::GumReplaceReturn_GUM_REPLACE_WRONG_SIGNATURE => {
                    bail!("InterceptorBadSignature")
                }
                frida_gumjs_rs_sys::GumReplaceReturn_GUM_REPLACE_ALREADY_REPLACED => {
                    bail!("InterceptorAlreadyReplaced")
                }
                frida_gumjs_rs_sys::GumReplaceReturn_GUM_REPLACE_POLICY_VIOLATION => {
                    bail!("PolicyViolation")
                }
                _ => bail!("InterceptorError"),
            }
        }
    }

    pub fn replace_fast(
        &self,
        function: NativePointer,
        replacement: NativePointer,
    ) -> Result<NativePointer,Box<dyn Error>> {
        let mut original_function = NativePointer(ptr::null_mut());
        unsafe {
            let ret=frida_gumjs_rs_sys::gum_interceptor_replace_fast(
                self.interceptor,
                function.0,
                replacement.0,
                &mut original_function.0,
            );
            debug!("original_function:{:?}",original_function);
           match ret{
               frida_gumjs_rs_sys::GumReplaceReturn_GUM_REPLACE_OK => Ok(original_function),
               frida_gumjs_rs_sys::GumReplaceReturn_GUM_REPLACE_WRONG_SIGNATURE => {
                   bail!("InterceptorBadSignature")
               }
               frida_gumjs_rs_sys::GumReplaceReturn_GUM_REPLACE_ALREADY_REPLACED => {
                   bail!("InterceptorAlreadyReplaced")
               }
               frida_gumjs_rs_sys::GumReplaceReturn_GUM_REPLACE_POLICY_VIOLATION => {
                   bail!("PolicyViolation")
               }
               _ => bail!("InterceptorError"),
           }
        }
    }

    pub fn detach(&mut self, listener: NativePointer) {
        unsafe {
            frida_gumjs_rs_sys::gum_interceptor_detach(
                self.interceptor,
                listener.0 as *mut frida_gumjs_rs_sys::GumInvocationListener,
            )
        };
    }
    // pub fn attach_instruction<I: ProbeListener>(
    //     &mut self,
    //     instr: NativePointer,
    //     listener: &mut I,
    // ) -> NativePointer {
    //     let listener = probe_listener_transform(listener);
    //     unsafe {
    //         gum_sys::gum_interceptor_attach(self.interceptor, instr.0, listener, ptr::null_mut())
    //     };
    //     NativePointer(listener as *mut c_void)
    // }
    // pub fn attach<I: InvocationListener>(
    //     &mut self,
    //     f: NativePointer,
    //     listener: &mut I,
    // ) -> NativePointer {
    //     let listener = invocation_listener_transform(listener);
    //     unsafe {
    //         gum_sys::gum_interceptor_attach(self.interceptor, f.0, listener, ptr::null_mut())
    //     };
    //     NativePointer(listener as *mut c_void)
    // }


}