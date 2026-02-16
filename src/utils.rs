#[macro_export]
macro_rules! stack_string {
    ($s:literal) => {{
        const LEN: usize = $s.len();
        let bytes = $s.as_bytes();
        let mut buf: [u8; LEN + 1] = [0u8; LEN + 1];

        unsafe {
            let ptr = buf.as_mut_ptr();
            let mut i = 0usize;
            while i < LEN {
                core::ptr::write_volatile(ptr.add(i), bytes[i]);
                i += 1;
            }
            core::ptr::write_volatile(ptr.add(LEN), 0);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }

        buf
    }};
}

#[macro_export]
macro_rules! stack_wstring {
    ($s:literal) => {{
        const LEN: usize = $s.len();
        let bytes = $s.as_bytes();
        let mut buf: [u16; LEN + 1] = [0u16; LEN + 1];

        unsafe {
            let ptr = buf.as_mut_ptr();
            let mut i = 0usize;
            while i < LEN {
                core::ptr::write_volatile(ptr.add(i), bytes[i] as u16);
                i += 1;
            }
            core::ptr::write_volatile(ptr.add(LEN), 0u16);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }

        buf
    }};
}

pub(crate) unsafe fn load_module(name: &str) -> Option<*mut winapi::ctypes::c_void> {
    const H_LOAD_LIBRARY_A: u64 = crate::hash::fnv1a_hash(b"LoadLibraryA");
    if let Some(k32) = crate::hash::get_module_by_hash(crate::hash::H_KERNEL32) {
        if let Some(f) = crate::hash::get_export_by_hash(k32, H_LOAD_LIBRARY_A) {
            type FnLoadLibraryA = unsafe extern "system" fn(*const i8) -> *mut winapi::ctypes::c_void;
            let load_lib: FnLoadLibraryA = std::mem::transmute(f);
            let h = load_lib(name.as_ptr() as *const i8);
            if !h.is_null() {
                return Some(h);
            }
        }
    }
    None
}

#[macro_export]
macro_rules! stack_bytes {
    ($($byte:expr),+ $(,)?) => {{
        const BYTES: &[u8] = &[$($byte),+];
        const LEN: usize = BYTES.len();
        let mut buf: [u8; LEN] = [0u8; LEN];

        unsafe {
            let ptr = buf.as_mut_ptr();
            let mut i = 0usize;
            while i < LEN {
                core::ptr::write_volatile(ptr.add(i), BYTES[i]);
                i += 1;
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }

        buf
    }};
}

