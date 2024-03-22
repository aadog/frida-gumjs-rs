use std::ffi::{c_void, CString};
use frida_gumjs_sys::{gboolean, gpointer, GumExportDetails, GumSymbolDetails};
use crate::NativePointer;
use crate::range_details::{PageProtection, RangeDetails};

/// Module details returned by [`Module::enumerate_modules`].
pub struct ModuleDetailsOwned {
    pub name: String,
    pub path: String,
    pub base_address: usize,
    pub size: usize,
}
/// Module export details returned by [`Module::enumerate_exports`].
pub struct ExportDetails {
    pub typ: u32,
    pub name: String,
    pub address: usize,
}

/// Module symbol details returned by [`Module::enumerate_symbols`].
pub struct SymbolDetails {
    pub name: String,
    pub address: usize,
    pub size: usize,
}

extern "C" fn enumerate_ranges_callout(
    range_details: *const frida_gumjs_sys::_GumRangeDetails,
    user_data: *mut c_void,
) -> gboolean {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(RangeDetails) -> bool>) };
    let r = f(RangeDetails::from_raw(range_details));
    Box::leak(f);
    r as gboolean
}

impl ModuleDetailsOwned{
    pub fn find_export_by_name(
        &self,
        symbol_name: &str,
    ) -> Option<NativePointer> {
        let module_name = CString::new(self.name.as_str()).unwrap();
        let symbol_name = CString::new(symbol_name).unwrap();
        let ptr = unsafe{
            frida_gumjs_sys::gum_module_find_export_by_name(
                module_name.as_ptr().cast(),
                symbol_name.as_ptr().cast(),
            )
        } as *mut c_void;
        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }
    /// The absolute address of the symbol. In the event that no such symbol
    /// could be found, returns NULL.
    pub fn find_symbol_by_name(&self, symbol_name: &str) -> Option<NativePointer> {
        let symbol_name = CString::new(symbol_name).unwrap();
        let module_name = CString::new(self.name.as_str()).unwrap();
        let ptr = unsafe {
            frida_gumjs_sys::gum_module_find_symbol_by_name(
                module_name.as_ptr().cast(),
                symbol_name.as_ptr().cast(),
            )
        } as *mut c_void;

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// Enumerates exports in module.
    pub fn enumerate_exports(&self) -> Vec<ExportDetails> {
        let result: Vec<ExportDetails> = vec![];

        unsafe extern "C" fn callback(
            details: *const GumExportDetails,
            user_data: gpointer,
        ) -> gboolean {
            let res = &mut *(user_data as *mut Vec<ExportDetails>);
            let name: String = NativePointer((*details).name as *mut _)
                .try_into()
                .unwrap_or_default();

            let address = (*details).address as usize;
            let typ = (*details).type_ as u32;
            let info = ExportDetails { typ, name, address };
            res.push(info);
            1
        }


        unsafe {
            frida_gumjs_sys::gum_module_enumerate_exports(
                self.name.as_ptr().cast(),
                Some(callback),
                &result as *const _ as *mut c_void,
            );
        }
        result
    }
    /// Enumerates symbols in module.
    pub fn enumerate_symbols(&self) -> Vec<SymbolDetails> {
        let result: Vec<SymbolDetails> = vec![];
        unsafe extern "C" fn callback(
            details: *const GumSymbolDetails,
            user_data: gpointer,
        ) -> gboolean {
            let res = &mut *(user_data as *mut Vec<SymbolDetails>);

            let name: String = NativePointer((*details).name as *mut _)
                .try_into()
                .unwrap_or_default();
            let address = (*details).address as usize;
            let size = (*details).size as usize;

            let info = SymbolDetails {
                name,
                address,
                size,
            };
            res.push(info);

            1
        }



        unsafe {
            frida_gumjs_sys::gum_module_enumerate_symbols(
                self.name.as_ptr().cast(),
                Some(callback),
                &result as *const _ as *mut c_void,
            );
        }
        result
    }
    /// Enumerates memory ranges satisfying protection given.
    pub fn enumerate_ranges(
        &self,
        prot: PageProtection,
        callout: impl FnMut(RangeDetails) -> bool,
    ) {
        unsafe {
            let user_data = Box::leak(Box::new(
                Box::new(callout) as Box<dyn FnMut(RangeDetails) -> bool>
            )) as *mut _ as *mut c_void;

            frida_gumjs_sys::gum_module_enumerate_ranges(
                self.name.as_ptr().cast(),
                prot as u32,
                Some(enumerate_ranges_callout),
                user_data,
            );

            let _ = Box::from_raw(user_data as *mut Box<dyn FnMut(RangeDetails) -> bool>);
        }
    }
}