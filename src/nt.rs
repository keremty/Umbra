#![allow(non_snake_case, non_camel_case_types)]

use winapi::ctypes::c_void;
use winapi::shared::ntdef::HANDLE;

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

#[repr(C)]
pub(crate) struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut c_void,
    pub SecurityQualityOfService: *mut c_void,
}

impl OBJECT_ATTRIBUTES {
    #[inline]
    pub(crate) const fn null() -> Self {
        Self {
            Length: core::mem::size_of::<Self>() as u32,
            RootDirectory: core::ptr::null_mut(),
            ObjectName: core::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: core::ptr::null_mut(),
            SecurityQualityOfService: core::ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub(crate) struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)]
pub(crate) struct PEB_LDR_DATA {
    pub Reserved1: [u8; 8],
    pub Reserved2: [*mut c_void; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
pub(crate) struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [*mut c_void; 2],
    pub Ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
pub(crate) struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: *mut c_void,
    pub EntryPoint: *mut c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: u32,
    pub LoadCount: u16,
    pub TlsIndex: u16,
    pub HashLinks: LIST_ENTRY,
    pub TimeDateStamp: u32,
}

#[repr(C)]
pub(crate) struct LdrSystemDllInitBlock {
    pub unknown0: u32,
    pub unknown4: u32,
    pub time_date_stamp: u32,
    pub system_call_number: u32,
}

#[repr(C)]
#[allow(dead_code)]
pub(crate) struct IO_STATUS_BLOCK {
    pub status: i32,
    pub information: usize,
}

impl IO_STATUS_BLOCK {
    #[inline]
    #[allow(dead_code)]
    pub(crate) const fn zeroed() -> Self {
        Self { status: 0, information: 0 }
    }
}

#[inline]
pub(crate) const fn nt_success(status: i32) -> bool {
    status >= 0
}

