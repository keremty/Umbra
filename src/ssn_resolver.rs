#![allow(non_snake_case)]

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;

use winapi::shared::minwindef::HMODULE;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE,
};

use crate::config::should_log;
use crate::hash::{get_export_by_hash, get_module_by_hash, H_NTDLL};
use crate::nt::{
    LdrSystemDllInitBlock, LDR_DATA_TABLE_ENTRY, LIST_ENTRY, PEB, UNICODE_STRING,
};
use crate::pe::find_text_section;

const SSN_CACHE_SLOTS: usize = 48;

static CACHE_HASH: [AtomicU64; SSN_CACHE_SLOTS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; SSN_CACHE_SLOTS]
};
static CACHE_SSN: [AtomicU64; SSN_CACHE_SLOTS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; SSN_CACHE_SLOTS]
};
static CACHE_STUB: [AtomicU64; SSN_CACHE_SLOTS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; SSN_CACHE_SLOTS]
};

pub(crate) static SSN_POISONED: OnceLock<AtomicBool> = OnceLock::new();

pub(crate) static SSN_GEN: OnceLock<AtomicU64> = OnceLock::new();

pub(crate) fn clear_ssn_cache() {
    for i in 0..SSN_CACHE_SLOTS {
        CACHE_HASH[i].store(0, Ordering::Release);
        CACHE_SSN[i].store(0, Ordering::Release);
        CACHE_STUB[i].store(0, Ordering::Release);
    }
}

#[inline]
fn cache_lookup(api_hash: u64) -> Option<(u16, u64)> {
    for i in 0..SSN_CACHE_SLOTS {
        let h = CACHE_HASH[i].load(Ordering::Acquire);
        if h == 0 {

            continue;
        }
        if h == api_hash {
            let ssn = CACHE_SSN[i].load(Ordering::Acquire) as u16;
            let masked = CACHE_STUB[i].load(Ordering::Acquire);
            return Some((ssn, masked));
        }
    }
    None
}

#[inline]
fn cache_insert(api_hash: u64, ssn: u16, masked_stub: u64) {
    for i in 0..SSN_CACHE_SLOTS {
        let h = CACHE_HASH[i].load(Ordering::Acquire);
        if h == api_hash {

            CACHE_SSN[i].store(ssn as u64, Ordering::Release);
            CACHE_STUB[i].store(masked_stub, Ordering::Release);
            return;
        }
        if h == 0 {

            CACHE_HASH[i].store(api_hash, Ordering::Release);
            CACHE_SSN[i].store(ssn as u64, Ordering::Release);
            CACHE_STUB[i].store(masked_stub, Ordering::Release);
            return;
        }
    }

}

pub(crate) fn mark_ssn_poisoned() {
    SSN_POISONED
        .get_or_init(|| AtomicBool::new(false))
        .store(true, Ordering::Release);
    let _gen = SSN_GEN
        .get_or_init(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::AcqRel);
    clear_ssn_cache();
    crate::debug_log!(
        "[SSN] Cache poisoned: kernel tolerance exceeded (gen={})",
        _gen + 1
    );
}

pub(crate) fn ssn_poisoned() -> bool {
    SSN_POISONED
        .get_or_init(|| AtomicBool::new(false))
        .load(Ordering::Acquire)
}

pub(crate) fn reset_ssn_poison_if_allowed() -> bool {
    static RESET_USED: OnceLock<AtomicBool> = OnceLock::new();
    let allow_reset = crate::config::ssn_reset_allowed();
    if !allow_reset {
        return false;
    }
    let used = RESET_USED.get_or_init(|| AtomicBool::new(false));
    if used.swap(true, Ordering::AcqRel) {
        return false;
    }
    if let Some(flag) = SSN_POISONED.get() {
        flag.store(false, Ordering::Release);
    }
    if let Some(gen) = SSN_GEN.get() {
        gen.store(0, Ordering::Release);
    }
    clear_ssn_cache();
    if should_log() {
        crate::debug_print!("[SSN] Cache reset (set SSN_RESET=0 to disable)");
    }
    true
}

static LAST_TS: OnceLock<AtomicU32> = OnceLock::new();
static LAST_BASE: OnceLock<std::sync::atomic::AtomicUsize> = OnceLock::new();

pub(crate) fn cache_invalidate_ntdll_change(ts: Option<u32>, base: usize) {
    let ts_slot = LAST_TS.get_or_init(|| AtomicU32::new(0));
    let base_slot = LAST_BASE.get_or_init(|| std::sync::atomic::AtomicUsize::new(0));
    let prev_ts = ts_slot.load(Ordering::Acquire);
    let prev_base = base_slot.load(Ordering::Acquire);
    let ts_val = ts.unwrap_or(0);
    if (prev_ts != 0 && prev_ts != ts_val) || (prev_base != 0 && prev_base != base) {
        clear_ssn_cache();
        if let Some(gen) = SSN_GEN.get() {
            gen.fetch_add(1, Ordering::AcqRel);
        }
    }
    ts_slot.store(ts_val, Ordering::Release);
    base_slot.store(base, Ordering::Release);
}

#[cfg(target_arch = "x86_64")]
extern "C" {
    #[link_name = "asm_get_peb"]
    fn asm_get_peb_internal() -> *mut PEB;
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) unsafe fn get_peb() -> *mut PEB {
    asm_get_peb_internal()
}

pub(crate) unsafe fn is_amd64_ntdll_module(module: HMODULE) -> bool {
    if module.is_null() {
        return false;
    }
    let dos = module as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D {
        return false;
    }
    let nt = (module as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return false;
    }
    if (*nt).FileHeader.Machine != 0x8664 {
        return false;
    }
    if (*nt).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return false;
    }
    true
}

fn wide_equals_ntdll(name: &UNICODE_STRING) -> bool {
    if name.Buffer.is_null() || name.Length < 2 {
        return false;
    }
    let len = (name.Length / 2) as usize;
    let slice = unsafe { std::slice::from_raw_parts(name.Buffer, len) };

    let mut ntdll_w = [0u16; 9];
    unsafe {
        let p = ntdll_w.as_mut_ptr();
        core::ptr::write_volatile(p.add(0), b'n' as u16);
        core::ptr::write_volatile(p.add(1), b't' as u16);
        core::ptr::write_volatile(p.add(2), b'd' as u16);
        core::ptr::write_volatile(p.add(3), b'l' as u16);
        core::ptr::write_volatile(p.add(4), b'l' as u16);
        core::ptr::write_volatile(p.add(5), b'.' as u16);
        core::ptr::write_volatile(p.add(6), b'd' as u16);
        core::ptr::write_volatile(p.add(7), b'l' as u16);
        core::ptr::write_volatile(p.add(8), b'l' as u16);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    if slice.len() != ntdll_w.len() {
        return false;
    }
    slice.iter().zip(ntdll_w.iter()).all(|(a, b)| {
        let c = if (b'A' as u16..=b'Z' as u16).contains(a) {
            a + 32
        } else {
            *a
        };
        c == *b
    })
}

pub(crate) unsafe fn get_preferred_ntdll() -> Option<HMODULE> {
    let peb = get_peb();
    if peb.is_null() || (*peb).Ldr.is_null() {
        crate::debug_log!("[SSN] Module not found");
        return None;
    }
    let ldr = (*peb).Ldr;
    let head = &mut (*ldr).InMemoryOrderModuleList as *mut LIST_ENTRY;
    let mut curr = (*head).Flink;
    while curr != head {
        let entry = (curr as *mut u8).sub(0x10) as *mut LDR_DATA_TABLE_ENTRY;
        if !entry.is_null()
            && !(*entry).BaseDllName.Buffer.is_null()
            && wide_equals_ntdll(&(*entry).BaseDllName)
        {
            let base = (*entry).DllBase as HMODULE;
            if is_amd64_ntdll_module(base) {
                return Some(base);
            }
        }
        curr = (*curr).Flink;
    }

    match get_module_by_hash(H_NTDLL) {
        Some(m) if is_amd64_ntdll_module(m) => Some(m),
        _ => {
            crate::debug_log!("[SSN] Module not found");
            None
        }
    }
}

pub(crate) unsafe fn get_ldr_system_dll_init_block() -> Option<*const LdrSystemDllInitBlock> {
    use winapi::ctypes::c_void;

    let peb = get_peb();
    if peb.is_null() || (*peb).Ldr.is_null() {
        return None;
    }
    let ldr = (*peb).Ldr as *mut c_void;
    let ptr_slot = (ldr as *mut *const c_void).add(1);
    let block = *ptr_slot as *const LdrSystemDllInitBlock;
    if block.is_null() {
        return None;
    }

    if let Some(ntdll) = get_preferred_ntdll() {
        let base = ntdll as usize;
        let dos = base as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != 0x5A4D {
            return None;
        }
        let nt = (base + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return None;
        }
        let size = (*nt).OptionalHeader.SizeOfImage as usize;
        let blk = block as usize;
        if blk < base || blk >= base + size {
            return None;
        }
    }
    Some(block)
}

pub(crate) unsafe fn address_in_loaded_module(addr: u64) -> bool {
    let peb = get_peb();
    if peb.is_null() || (*peb).Ldr.is_null() {
        return false;
    }
    let ldr = (*peb).Ldr;
    let head = &mut (*ldr).InMemoryOrderModuleList as *mut LIST_ENTRY;
    let mut curr = (*head).Flink;
    while curr != head {
        let entry = (curr as *mut u8).sub(0x10) as *mut LDR_DATA_TABLE_ENTRY;
        let base = (*entry).DllBase as u64;
        let size = (*entry).SizeOfImage as u64;
        if size != 0 && addr >= base && addr < base.saturating_add(size) {
            return true;
        }
        curr = (*curr).Flink;
    }
    false
}

pub(crate) fn module_full_path_lower(module: HMODULE) -> Option<String> {
    if module.is_null() {
        return None;
    }
    unsafe {
        let peb = get_peb();
        if peb.is_null() || (*peb).Ldr.is_null() {
            return None;
        }
        let ldr = (*peb).Ldr;
        let head = &mut (*ldr).InMemoryOrderModuleList as *mut LIST_ENTRY;
        let mut curr = (*head).Flink;
        while curr != head {
            let entry = (curr as *mut u8).sub(0x10) as *mut LDR_DATA_TABLE_ENTRY;
            if !entry.is_null() && (*entry).DllBase as HMODULE == module {
                let full = &(*entry).FullDllName;
                if full.Buffer.is_null() || full.Length == 0 {
                    return None;
                }
                let len = (full.Length / 2) as usize;
                let slice = std::slice::from_raw_parts(full.Buffer, len);
                let s = String::from_utf16_lossy(slice);
                return Some(s.to_ascii_lowercase());
            }
            curr = (*curr).Flink;
        }
    }
    None
}

pub(crate) fn is_sxs_or_downlevel_ntdll(module: HMODULE) -> bool {
    module_full_path_lower(module)
        .map(|p| {
            let s1 = crate::stack_str!(b'\\', b'w', b'i', b'n', b's', b'x', b's', b'\\');
            let s2 = crate::stack_str!(b'\\', b's', b'y', b's', b't', b'e', b'm', b'3', b'2', b'\\', b'd', b'o', b'w', b'n', b'l', b'e', b'v', b'e', b'l', b'\\');
            let s3 = crate::stack_str!(b'\\', b's', b'y', b's', b'w', b'o', b'w', b'6', b'4', b'\\');
            let s4 = crate::stack_str!(b'\\', b'w', b'o', b'w', b'6', b'4', b'\\');
            let s5 = crate::stack_str!(b'n', b't', b'd', b'l', b'l', b'k', b'b', b'.');
            let c1 = unsafe { core::str::from_utf8_unchecked(&s1) };
            let c2 = unsafe { core::str::from_utf8_unchecked(&s2) };
            let c3 = unsafe { core::str::from_utf8_unchecked(&s3) };
            let c4 = unsafe { core::str::from_utf8_unchecked(&s4) };
            let c5 = unsafe { core::str::from_utf8_unchecked(&s5) };
            p.contains(c1) || p.contains(c2) || p.contains(c3) || p.contains(c4) || p.contains(c5)
        })
        .unwrap_or(false)
}

pub(crate) fn is_chpe_or_sxs(module: HMODULE) -> bool {
    module_full_path_lower(module)
        .map(|p| {
            let s1 = crate::stack_str!(b'\\', b'w', b'i', b'n', b's', b'x', b's', b'\\');
            let s2 = crate::stack_str!(b'x', b't', b'a', b'j', b'i', b't');
            let s3 = crate::stack_str!(b'c', b'h', b'p', b'e');
            let s4 = crate::stack_str!(b'a', b'r', b'm', b'6', b'4', b'x');
            let c1 = unsafe { core::str::from_utf8_unchecked(&s1) };
            let c2 = unsafe { core::str::from_utf8_unchecked(&s2) };
            let c3 = unsafe { core::str::from_utf8_unchecked(&s3) };
            let c4 = unsafe { core::str::from_utf8_unchecked(&s4) };
            p.contains(c1) || p.contains(c2) || p.contains(c3) || p.contains(c4)
        })
        .unwrap_or(false)
}

pub(crate) fn get_module_timestamp(module: HMODULE) -> Option<u32> {
    if module.is_null() {
        return None;
    }
    unsafe {
        let dos = module as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != 0x5A4D {
            return None;
        }
        let nt = (module as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return None;
        }
        Some((*nt).FileHeader.TimeDateStamp)
    }
}

pub(crate) unsafe fn extract_ssn_direct(stub_addr: *const u8) -> Option<u16> {
    if stub_addr.is_null() {
        return None;
    }

    let b0 = core::ptr::read_volatile(stub_addr);
    let b1 = core::ptr::read_volatile(stub_addr.add(1));
    let b2 = core::ptr::read_volatile(stub_addr.add(2));
    let b3 = core::ptr::read_volatile(stub_addr.add(3));
    if b0 != 0x4C || b1 != 0x8B || b2 != 0xD1 || b3 != 0xB8 {
        return None;
    }

    let ssn_lo = *stub_addr.add(4) as u16;
    let ssn_hi = *stub_addr.add(5) as u16;
    let ssn = ssn_lo | (ssn_hi << 8);

    Some(ssn)
}

pub(crate) unsafe fn decode_ssn_patternless(stub_addr: *const u8) -> Option<u16> {
    if stub_addr.is_null() {
        return None;
    }

    if !address_in_loaded_module(stub_addr as u64) {
        return None;
    }
    const MAX_SCAN: usize = 64;
    let bytes = std::slice::from_raw_parts(stub_addr, MAX_SCAN);

    for i in 0..bytes.len().saturating_sub(8) {
        if bytes[i] == 0x4C && bytes[i + 1] == 0x8B && bytes[i + 2] == 0xD1 {
            let mut j = i + 3;
            while j + 5 <= bytes.len() {
                if bytes[j] == 0xB8 {
                    let ssn_lo = bytes[j + 1] as u16;
                    let ssn_hi = bytes[j + 2] as u16;
                    let ssn = ssn_lo | (ssn_hi << 8);

                    for k in (j + 5)..bytes.len().saturating_sub(1) {
                        if bytes[k] == 0x0F && bytes[k + 1] == 0x05 {
                            return Some(ssn);
                        }
                    }
                }
                j += 1;
            }
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub(crate) enum SyscallHookType {
    Clean,

    JmpRel32,

    CallRel32,

    PushRet,

    MovJmpRax,

    PrologueHook,
}

pub(crate) unsafe fn detect_syscall_hook_type(stub_addr: *const u8) -> SyscallHookType {
    if stub_addr.is_null() {
        return SyscallHookType::PrologueHook;
    }

    let b: [u8; 12] = [
        *stub_addr,
        *stub_addr.add(1),
        *stub_addr.add(2),
        *stub_addr.add(3),
        *stub_addr.add(4),
        *stub_addr.add(5),
        *stub_addr.add(6),
        *stub_addr.add(7),
        *stub_addr.add(8),
        *stub_addr.add(9),
        *stub_addr.add(10),
        *stub_addr.add(11),
    ];

    if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xE9 {
        return SyscallHookType::PrologueHook;
    }

    if b[0] == 0xE9 {
        return SyscallHookType::JmpRel32;
    }

    if b[0] == 0xE8 {
        return SyscallHookType::CallRel32;
    }

    if b[0] == 0x68 && b[5] == 0xC3 {
        return SyscallHookType::PushRet;
    }

    if b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0 {
        return SyscallHookType::MovJmpRax;
    }

    if b[5] == 0xE9 || b[5] == 0xE8 {
        return SyscallHookType::JmpRel32;
    }

    if b[0] != 0x4C || b[1] != 0x8B || b[2] != 0xD1 || b[3] != 0xB8 {
        return SyscallHookType::PrologueHook;
    }

    SyscallHookType::Clean
}

pub(crate) unsafe fn is_syscall_hooked(stub_addr: *const u8) -> bool {
    detect_syscall_hook_type(stub_addr) != SyscallHookType::Clean
}

pub(crate) unsafe fn stub_sane(module_base: *const u8, stub: *const u8) -> bool {
    if crate::config::ssn_allow_bad_stub() {
        return true;
    }

    if stub.is_null() || module_base.is_null() {
        return false;
    }

    if !is_amd64_ntdll_module(module_base as HMODULE) {
        return false;
    }

    let (text_start, text_size) = match find_text_section(module_base) {
        Some(s) => s,
        None => return false,
    };
    let start = text_start as usize;
    let end = start.saturating_add(text_size);
    let addr = stub as usize;

    if addr < start || addr >= end {
        return false;
    }

    let window_start = addr.saturating_sub(8).max(start);
    let window_end = (addr.saturating_add(96)).min(end);
    let window_len = window_end.saturating_sub(window_start);
    if window_len < 16 {
        return false;
    }

    let window = std::slice::from_raw_parts(window_start as *const u8, window_len);
    let rel = addr.saturating_sub(window_start);

    let has_syscall = window.windows(2).any(|w| w == [0x0F, 0x05]);
    if !has_syscall {
        return false;
    }

    let has_mov_r10 = window.windows(3).any(|w| w == [0x4C, 0x8B, 0xD1]);
    if !has_mov_r10 {}

    if rel < window_len {
        let b0 = window[rel];
        if b0 == 0xE9 || b0 == 0xE8 {
            return false;
        }
        if b0 == 0xFF && rel + 1 < window_len {
            let b1 = window[rel + 1];
            if b1 == 0x15 || b1 == 0x25 {
                return false;
            }
        }
    }

    if !address_in_loaded_module(stub as u64) {
        return false;
    }

    true
}

pub(crate) unsafe fn resolve_ssn_by_hash(api_hash: u64) -> Option<(u16, *const u8)> {
    const MAX_RETRIES: usize = 3;

    for attempt in 0..MAX_RETRIES {
        if let Some(result) = try_resolve_ssn(api_hash) {
            return Some(result);
        }

        if attempt < MAX_RETRIES - 1 {
            clear_ssn_cache();

            unsafe { crate::timer_sleep::timer_sleep_jitter(1, 4); }
        }
    }

    crate::debug_log!("[SSN] Resolution unavailable: 0x{:X}", api_hash);
    None
}

unsafe fn try_resolve_ssn(api_hash: u64) -> Option<(u16, *const u8)> {
    let strict = crate::config::ssn_strict();
    let mut lenient = if strict {
        false
    } else {
        crate::config::ssn_lenient()
    };
    let kernel_tol = crate::config::kernel_ssn_tolerance();

    if ssn_poisoned() && !reset_ssn_poison_if_allowed() {
        return None;
    }

    let _gen_before = SSN_GEN
        .get_or_init(|| AtomicU64::new(0))
        .load(Ordering::Acquire);

    if let Some((ssn, stub_masked)) = cache_lookup(api_hash) {
        let stub_addr = stub_masked ^ crate::stack_spoof::pool_key();
        return Some((ssn, stub_addr as *const u8));
    }

    let ntdll = get_preferred_ntdll()?;

    if is_chpe_or_sxs(ntdll) || is_sxs_or_downlevel_ntdll(ntdll) {
        lenient = true;
    }

    let ts_mod = get_module_timestamp(ntdll);
    cache_invalidate_ntdll_change(ts_mod, ntdll as usize);

    let stub_addr = match get_export_by_hash(ntdll, api_hash) {
        Some(p) => p as *const u8,
        None => return None,
    };

    if !stub_sane(ntdll as *const u8, stub_addr) && !lenient {
        return None;
    }

    if is_syscall_hooked(stub_addr) && !lenient {
        return None;
    }

    if let Some(ssn) = decode_ssn_patternless(stub_addr) {
        if let Some(block) = get_ldr_system_dll_init_block() {
            let kernel_ssn = (*block).system_call_number as u16;
            let tol = kernel_tol;
            if ssn == 0 || ssn as i32 <= 0 || (ssn as i32 - kernel_ssn as i32).unsigned_abs() > tol
            {
                mark_ssn_poisoned();
                if !lenient {
                    return None;
                }
            }
        }

        let masked = stub_addr as u64 ^ crate::stack_spoof::pool_key();
        cache_insert(api_hash, ssn, masked);
        return Some((ssn, stub_addr));
    }

    if !address_in_loaded_module(stub_addr as u64) {
        return None;
    }

    if !is_syscall_hooked(stub_addr) || lenient {
        if let Some(ssn) = extract_ssn_direct(stub_addr) {
            let mut kernel_ok = true;
            if let Some(block) = get_ldr_system_dll_init_block() {
                let kernel_ssn = (*block).system_call_number as u16;
                let tol = kernel_tol;
                if ssn == 0
                    || ssn as i32 <= 0
                    || (ssn as i32 - kernel_ssn as i32).unsigned_abs() > tol
                {
                    mark_ssn_poisoned();
                    kernel_ok = false;
                }
            }
            if kernel_ok {
                let masked = stub_addr as u64 ^ crate::stack_spoof::pool_key();
                cache_insert(api_hash, ssn, masked);
                return Some((ssn, stub_addr));
            } else if !lenient {
                return None;
            }
        }
    }

    None
}

