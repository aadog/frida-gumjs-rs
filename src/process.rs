use std::ffi::{c_void, CString};
use frida_gumjs_rs_sys::{gboolean, gpointer, GumModuleDetails, GumThreadDetails};
use crate::NativePointer;
use crate::module::ModuleDetailsOwned;

/// Module symbol details returned by [`Module::enumerate_symbols`].
///
///
pub struct ThreadDetailsOwned {
    pub id: usize,
    pub name: String,
    pub state: u32,
    // pub cpu_context: *mut GumCpuContext,
}

pub fn enumerate_threads() -> Vec<ThreadDetailsOwned> {
    let result: Vec<ThreadDetailsOwned> = vec![];
    unsafe extern "C" fn callback(
        details: *const GumThreadDetails,
        user_data: gpointer,
    ) -> gboolean {
        let res = &mut *(user_data as *mut Vec<ThreadDetailsOwned>);
        let id = (*details).id as usize;
        let name: String = NativePointer((*details).name as *mut _).try_into().unwrap_or_default();
        let state = (*details).state as u32;
        let detials = ThreadDetailsOwned {
            id: id,
            name: name,
            state: state,
            // cpu_context:(*details).cpu_context,
            // cpu_context: (*details).cpu_context,
        };
        res.push(detials);
        1
    }

    unsafe {
        frida_gumjs_sys::gum_process_enumerate_threads(
            Some(callback),
            &result as *const _ as gpointer,
        )
    }
    return result;
}

/// Enumerates modules.
pub fn enumerate_modules() -> Vec<ModuleDetailsOwned> {
    let result: Vec<ModuleDetailsOwned> = vec![];

    unsafe extern "C" fn callback(
        details: *const GumModuleDetails,
        user_data: gpointer,
    ) -> gboolean {
        let res = &mut *(user_data as *mut Vec<ModuleDetailsOwned>);

        let name: String = NativePointer((*details).name as *mut _)
            .try_into()
            .unwrap_or_default();
        let path: String = NativePointer((*details).path as *mut _)
            .try_into()
            .unwrap_or_default();
        let range = (*details).range;
        let base_address = (*range).base_address as usize;
        let size = (*range).size as usize;
        let module_details = ModuleDetailsOwned {
            name,
            path,
            base_address,
            size,
        };
        res.push(module_details);

        1
    }

    unsafe {
        frida_gumjs_sys::gum_process_enumerate_modules(
            Some(callback),
            &result as *const _ as *mut c_void,
        );
    }

    result
}

pub fn id() -> usize {
    unsafe { frida_gumjs_sys::gum_process_get_id() as usize }
}

pub fn get_current_thread_id() -> usize {
    unsafe { frida_gumjs_sys::gum_process_get_current_thread_id() as usize }
}

pub fn is_debugger_attached() -> bool {
    unsafe { frida_gumjs_sys::gum_process_is_debugger_attached() != 0 }
}

pub fn get_current_dir() -> String {
    NativePointer(unsafe { frida_gumjs_sys::_frida_g_get_current_dir() as *mut _ }).try_into().unwrap_or_default()
}

pub fn get_home_dir() -> String {
    NativePointer(unsafe { frida_gumjs_sys::_frida_g_get_home_dir() as *mut _ }).try_into().unwrap_or_default()
}

pub fn get_tmp_dir() -> String {
    NativePointer(unsafe { frida_gumjs_sys::_frida_g_get_tmp_dir() as *mut _ }).try_into().unwrap_or_default()
}

pub fn get_main_module() -> ModuleDetailsOwned {
    let details = unsafe { frida_gumjs_sys::gum_process_get_main_module() };
    let name: String = NativePointer(unsafe{(*details).name} as *mut _)
        .try_into()
        .unwrap_or_default();
    let path: String = NativePointer(unsafe{(*details).path} as *mut _)
        .try_into()
        .unwrap_or_default();
    let range = unsafe{(*details).range};
    let base_address = unsafe{(*range).base_address} as usize;
    let size = unsafe{(*range).size} as usize;
    let module_details = ModuleDetailsOwned {
        name,
        path,
        base_address,
        size,
    };
    module_details
}
pub fn find_module_by_name(name:&str)->Option<ModuleDetailsOwned>{
    let modules=enumerate_modules();
    for module in modules {
        let mut cmp_name=String::from(name);
        if cmp_name.starts_with("lib")==false{
            cmp_name=format!("lib{}",cmp_name)
        }
        if cmp_name.starts_with(".so")==false{
            cmp_name=format!("{}.so",cmp_name)
        }
        if module.name==cmp_name{
            return Some(module)
        }
    }
    None
}
/// Returns the base address of the specified module. In the event that no
/// such module could be found, returns NULL.
pub fn find_base_address(module_name: &str) -> NativePointer {
    let module_name = CString::new(module_name).unwrap();
    unsafe {
        NativePointer(
            frida_gumjs_sys::gum_module_find_base_address(module_name.as_ptr().cast()) as *mut c_void,
        )
    }
}
/// The absolute address of the export. In the event that no such export
/// could be found, returns NULL.
/// The absolute address of the export. In the event that no such export
/// could be found, returns NULL.
pub fn find_export_by_name(
    module_name: Option<&str>,
    symbol_name: &str,
) -> Option<NativePointer> {
    let symbol_name = CString::new(symbol_name).unwrap();

    let ptr = match module_name {
        None => unsafe {
            frida_gumjs_sys::gum_module_find_export_by_name(
                core::ptr::null_mut(),
                symbol_name.as_ptr().cast(),
            )
        },
        Some(name) => unsafe {
            let module_name = CString::new(name).unwrap();
            frida_gumjs_sys::gum_module_find_export_by_name(
                module_name.as_ptr().cast(),
                symbol_name.as_ptr().cast(),
            )
        },
    } as *mut c_void;

    if ptr.is_null() {
        None
    } else {
        Some(NativePointer(ptr))
    }
}