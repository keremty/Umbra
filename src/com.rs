
use core::sync::atomic::{AtomicU32, Ordering};
use winapi::ctypes::c_void;

const S_OK:             i32 = 0;
const S_FALSE:          i32 = 1;
const E_NOINTERFACE:    i32 = 0x80004002_u32 as i32;
const E_POINTER:        i32 = 0x80004003_u32 as i32;

#[repr(C)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

static IID_IUNKNOWN: GUID = GUID {
    data1: 0x00000000, data2: 0x0000, data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};
static IID_ICLASS_FACTORY: GUID = GUID {
    data1: 0x00000001, data2: 0x0000, data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

unsafe fn guid_eq(a: *const GUID, b: *const GUID) -> bool {
    let pa = a as *const u8;
    let pb = b as *const u8;
    let mut i = 0usize;
    while i < 16 {
        if *pa.add(i) != *pb.add(i) {
            return false;
        }
        i += 1;
    }
    true
}

#[repr(C)]
struct IUnknownVtbl {
    query_interface: unsafe extern "system" fn(
        this: *mut StubComObject,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> i32,
    add_ref: unsafe extern "system" fn(this: *mut StubComObject) -> u32,
    release: unsafe extern "system" fn(this: *mut StubComObject) -> u32,
}

#[repr(C)]
struct StubComObject {
    vtable: *const IUnknownVtbl,
    ref_count: AtomicU32,
}

unsafe impl Sync for StubComObject {}

unsafe extern "system" fn stub_query_interface(
    this: *mut StubComObject,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if ppv.is_null() {
        return E_POINTER;
    }

    if guid_eq(riid, &IID_IUNKNOWN) {
        *ppv = this as *mut c_void;
        stub_add_ref(this);
        return S_OK;
    }

    *ppv = core::ptr::null_mut();
    E_NOINTERFACE
}

unsafe extern "system" fn stub_add_ref(this: *mut StubComObject) -> u32 {
    let obj = &*this;
    obj.ref_count.fetch_add(1, Ordering::Relaxed) + 1
}

unsafe extern "system" fn stub_release(this: *mut StubComObject) -> u32 {
    let obj = &*this;
    let prev = obj.ref_count.fetch_sub(1, Ordering::Release);
    if prev == 1 {

        core::sync::atomic::fence(Ordering::Acquire);
    }
    prev - 1
}

static STUB_OBJECT_VTBL: IUnknownVtbl = IUnknownVtbl {
    query_interface: stub_query_interface,
    add_ref: stub_add_ref,
    release: stub_release,
};

static STUB_OBJECT: StubComObject = StubComObject {
    vtable: &STUB_OBJECT_VTBL,
    ref_count: AtomicU32::new(1),
};

#[repr(C)]
struct IClassFactoryVtbl {

    query_interface: unsafe extern "system" fn(
        this: *mut StubClassFactory,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> i32,
    add_ref: unsafe extern "system" fn(this: *mut StubClassFactory) -> u32,
    release: unsafe extern "system" fn(this: *mut StubClassFactory) -> u32,

    create_instance: unsafe extern "system" fn(
        this: *mut StubClassFactory,
        outer: *mut c_void,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> i32,
    lock_server: unsafe extern "system" fn(
        this: *mut StubClassFactory,
        lock: i32,
    ) -> i32,
}

#[repr(C)]
struct StubClassFactory {
    vtable: *const IClassFactoryVtbl,
    ref_count: AtomicU32,
}

unsafe impl Sync for StubClassFactory {}

unsafe extern "system" fn factory_query_interface(
    this: *mut StubClassFactory,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if ppv.is_null() {
        return E_POINTER;
    }

    if guid_eq(riid, &IID_IUNKNOWN) || guid_eq(riid, &IID_ICLASS_FACTORY) {
        *ppv = this as *mut c_void;
        factory_add_ref(this);
        return S_OK;
    }

    *ppv = core::ptr::null_mut();
    E_NOINTERFACE
}

unsafe extern "system" fn factory_add_ref(this: *mut StubClassFactory) -> u32 {
    let obj = &*this;
    obj.ref_count.fetch_add(1, Ordering::Relaxed) + 1
}

unsafe extern "system" fn factory_release(this: *mut StubClassFactory) -> u32 {
    let obj = &*this;
    let prev = obj.ref_count.fetch_sub(1, Ordering::Release);
    if prev == 1 {
        core::sync::atomic::fence(Ordering::Acquire);
    }
    prev - 1
}

unsafe extern "system" fn factory_create_instance(
    _this: *mut StubClassFactory,
    outer: *mut c_void,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    if ppv.is_null() {
        return E_POINTER;
    }

    if !outer.is_null() {
        *ppv = core::ptr::null_mut();
        return 0x80040110_u32 as i32;
    }

    let obj_ptr = &STUB_OBJECT as *const StubComObject as *mut StubComObject;
    stub_query_interface(obj_ptr, riid, ppv)
}

unsafe extern "system" fn factory_lock_server(
    _this: *mut StubClassFactory,
    _lock: i32,
) -> i32 {

    S_OK
}

static FACTORY_VTBL: IClassFactoryVtbl = IClassFactoryVtbl {
    query_interface: factory_query_interface,
    add_ref: factory_add_ref,
    release: factory_release,
    create_instance: factory_create_instance,
    lock_server: factory_lock_server,
};

static FACTORY: StubClassFactory = StubClassFactory {
    vtable: &FACTORY_VTBL,
    ref_count: AtomicU32::new(1),
};

pub unsafe fn dll_get_class_object(
    _rclsid: *const c_void,
    riid: *const c_void,
    ppv: *mut *mut c_void,
) -> i32 {
    if ppv.is_null() {
        return E_POINTER;
    }

    let riid = riid as *const GUID;

    if guid_eq(riid, &IID_ICLASS_FACTORY) || guid_eq(riid, &IID_IUNKNOWN) {
        let factory_ptr = &FACTORY as *const StubClassFactory as *mut c_void;
        *ppv = factory_ptr;
        factory_add_ref(&FACTORY as *const StubClassFactory as *mut StubClassFactory);
        return S_OK;
    }

    *ppv = core::ptr::null_mut();
    E_NOINTERFACE
}

pub fn dll_can_unload_now() -> i32 {
    S_FALSE
}

