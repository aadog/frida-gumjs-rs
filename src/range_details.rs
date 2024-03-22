/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#![cfg_attr(
any(target_arch = "x86_64", target_arch = "x86"),
allow(clippy::unnecessary_cast)
)]

extern crate alloc;
use {
    core::{
        ffi::{c_void, CStr},
        marker::PhantomData,
    },
    frida_gumjs_rs_sys as gumjs_sys,
};

#[cfg(not(feature = "module-names"))]
use num_derive::FromPrimitive;
use crate::memory_range::MemoryRange;

/// The memory protection of an unassociated page.
#[derive(Clone,FromPrimitive)]
#[repr(u32)]
pub enum PageProtection {
    NoAccess = gumjs_sys::_GumPageProtection_GUM_PAGE_NO_ACCESS as u32,
    Read = gumjs_sys::_GumPageProtection_GUM_PAGE_READ as u32,
    Write = gumjs_sys::_GumPageProtection_GUM_PAGE_WRITE as u32,
    Execute = gumjs_sys::_GumPageProtection_GUM_PAGE_EXECUTE as u32,
    ReadWrite = gumjs_sys::_GumPageProtection_GUM_PAGE_READ as u32
        | gumjs_sys::_GumPageProtection_GUM_PAGE_WRITE as u32,
    ReadExecute = gumjs_sys::_GumPageProtection_GUM_PAGE_READ as u32
        | gumjs_sys::_GumPageProtection_GUM_PAGE_EXECUTE as u32,
    ReadWriteExecute = gumjs_sys::_GumPageProtection_GUM_PAGE_READ as u32
        | gumjs_sys::_GumPageProtection_GUM_PAGE_WRITE as u32
        | gumjs_sys::_GumPageProtection_GUM_PAGE_EXECUTE as u32,
}

/// The file association to a page.
#[derive(Clone)]
pub struct FileMapping<'a> {
    path: String,
    size: usize,
    offset: u64,
    phantom: PhantomData<&'a gumjs_sys::GumFileMapping>,
}

impl<'a> FileMapping<'a> {
    pub(crate) fn from_raw(file: *const gumjs_sys::GumFileMapping) -> Option<Self> {
        if file.is_null() {
            None
        } else {
            Some(unsafe {
                Self {
                    path: CStr::from_ptr((*file).path).to_string_lossy().into_owned(),
                    size: (*file).size as usize,
                    offset: (*file).offset as u64,
                    phantom: PhantomData,
                }
            })
        }
    }

    /// The path of the file mapping on disk.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The offset into the file mapping.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The size of the mapping.
    pub fn size(&self) -> usize {
        self.size as usize
    }
}

struct SaveRangeDetailsByAddressContext<'a> {
    address: u64,
    details: Option<RangeDetails<'a>>,
}

unsafe extern "C" fn save_range_details_by_address(
    details: *const gumjs_sys::GumRangeDetails,
    context: *mut c_void,
) -> i32 {
    let context = &mut *(context as *mut SaveRangeDetailsByAddressContext);
    let range = (*details).range;
    let start = (*range).base_address as u64;
    let end = start + (*range).size as u64;
    if start <= context.address && context.address < end {
        context.details = Some(RangeDetails::from_raw(details));
        return 0;
    }

    1
}

unsafe extern "C" fn enumerate_ranges_stub(
    details: *const gumjs_sys::GumRangeDetails,
    context: *mut c_void,
) -> i32 {
    if !(*(context as *mut Box<&mut dyn FnMut(&RangeDetails) -> bool>))(&RangeDetails::from_raw(
        details,
    )) {
        return 0;
    }
    1
}

/// Details a range of virtual memory.
pub struct RangeDetails<'a> {
    range: MemoryRange,
    protection: PageProtection,
    file: Option<FileMapping<'a>>,
    phantom: PhantomData<&'a gumjs_sys::GumRangeDetails>,
}

impl<'a> RangeDetails<'a> {
    pub(crate) fn from_raw(range_details: *const gumjs_sys::GumRangeDetails) -> Self {
        unsafe {
            Self {
                range: MemoryRange::from_raw((*range_details).range),
                protection: num::FromPrimitive::from_u32((*range_details).protection).unwrap(),
                file: FileMapping::from_raw((*range_details).file),
                phantom: PhantomData,
            }
        }
    }

    /// Get a [`RangeDetails`] for the range containing the given address.
    pub fn with_address(address: u64) -> Option<RangeDetails<'a>> {
        let mut context = SaveRangeDetailsByAddressContext {
            address,
            details: None,
        };
        unsafe {
            gumjs_sys::gum_process_enumerate_ranges(
                gumjs_sys::_GumPageProtection_GUM_PAGE_NO_ACCESS as u32,
                Some(save_range_details_by_address),
                &mut context as *mut _ as *mut c_void,
            );
        }

        context.details
    }

    /// Enumerate all ranges which match the given [`PageProtection`], calling the callback
    /// function for each such range.
    pub fn enumerate_with_prot(
        prot: PageProtection,
        callback: &mut dyn FnMut(&RangeDetails) -> bool,
    ) {
        unsafe {
            gumjs_sys::gum_process_enumerate_ranges(
                prot as u32,
                Some(enumerate_ranges_stub),
                &mut Box::new(callback) as *mut _ as *mut c_void,
            );
        }
    }

    /// The range of memory that is detailed.
    pub fn memory_range(&self) -> MemoryRange {
        self.range.clone()
    }

    /// The page protection of the range.
    pub fn protection(&self) -> PageProtection {
        self.protection.clone()
    }

    /// The associated file mapping, if present.
    pub fn file_mapping(&self) -> Option<FileMapping> {
        self.file.clone()
    }
}