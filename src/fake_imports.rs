
use core::ptr;

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThreadId() -> u32;
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut core::ffi::c_void;
    fn GetModuleHandleW(lpModuleName: *const u16) -> *mut core::ffi::c_void;
    fn GetProcessHeap() -> *mut core::ffi::c_void;
    fn GetEnvironmentVariableA(lpName: *const u8, lpBuffer: *mut u8, nSize: u32) -> u32;

    fn CloseHandle(hObject: *mut core::ffi::c_void) -> i32;
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *const core::ffi::c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
    fn GetFileSize(hFile: *mut core::ffi::c_void, lpFileSizeHigh: *mut u32) -> u32;
    fn FindFirstFileW(
        lpFileName: *const u16,
        lpFindFileData: *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
    fn FindClose(hFindFile: *mut core::ffi::c_void) -> i32;

    fn InitializeCriticalSection(lpCriticalSection: *mut core::ffi::c_void);
    fn DeleteCriticalSection(lpCriticalSection: *mut core::ffi::c_void);
    fn EnterCriticalSection(lpCriticalSection: *mut core::ffi::c_void);
    fn LeaveCriticalSection(lpCriticalSection: *mut core::ffi::c_void);

    fn HeapAlloc(hHeap: *mut core::ffi::c_void, dwFlags: u32, dwBytes: usize) -> *mut core::ffi::c_void;
    fn HeapFree(hHeap: *mut core::ffi::c_void, dwFlags: u32, lpMem: *mut core::ffi::c_void) -> i32;

    fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *mut core::ffi::c_void);
}

#[link(name = "user32")]
extern "system" {
    fn GetDesktopWindow() -> *mut core::ffi::c_void;
    fn GetForegroundWindow() -> *mut core::ffi::c_void;
    fn GetKeyboardLayout(idThread: u32) -> *mut core::ffi::c_void;
    fn GetKeyState(nVirtKey: i32) -> i16;
    fn GetMessagePos() -> u32;
}

#[link(name = "advapi32")]
extern "system" {
    fn RegCloseKey(hKey: *mut core::ffi::c_void) -> i32;
    fn RegOpenKeyExW(
        hKey: *mut core::ffi::c_void,
        lpSubKey: *const u16,
        ulOptions: u32,
        samDesired: u32,
        phkResult: *mut *mut core::ffi::c_void,
    ) -> i32;
    fn GetUserNameA(lpBuffer: *mut u8, pcbBuffer: *mut u32) -> i32;
}

#[link(name = "ntdll")]
extern "system" {
    fn RtlInitUnicodeString(
        DestinationString: *mut core::ffi::c_void,
        SourceString: *const u16,
    );
    fn RtlFreeUnicodeString(UnicodeString: *mut core::ffi::c_void);
}

#[link(name = "msvcrt")]
extern "C" {
    fn memcpy(dest: *mut core::ffi::c_void, src: *const core::ffi::c_void, n: usize) -> *mut core::ffi::c_void;
    fn memset(s: *mut core::ffi::c_void, c: i32, n: usize) -> *mut core::ffi::c_void;
    fn _wcsicmp(string1: *const u16, string2: *const u16) -> i32;
}

#[repr(transparent)]
struct SyncFnPtr(*const ());

unsafe impl Sync for SyncFnPtr {}

impl SyncFnPtr {
    const fn new(ptr: *const ()) -> Self {
        Self(ptr)
    }

    #[cfg(debug_assertions)]
    #[inline]
    #[allow(dead_code)]
    const fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

#[used]
#[link_section = ".rdata$z"]
static IAT_ANCHOR: [SyncFnPtr; 33] = [

    SyncFnPtr::new(GetLastError as *const ()),
    SyncFnPtr::new(GetCurrentProcessId as *const ()),
    SyncFnPtr::new(GetCurrentThreadId as *const ()),
    SyncFnPtr::new(GetModuleHandleA as *const ()),
    SyncFnPtr::new(GetModuleHandleW as *const ()),
    SyncFnPtr::new(GetProcessHeap as *const ()),
    SyncFnPtr::new(GetEnvironmentVariableA as *const ()),
    SyncFnPtr::new(CloseHandle as *const ()),
    SyncFnPtr::new(CreateFileW as *const ()),
    SyncFnPtr::new(GetFileSize as *const ()),
    SyncFnPtr::new(FindFirstFileW as *const ()),
    SyncFnPtr::new(FindClose as *const ()),
    SyncFnPtr::new(InitializeCriticalSection as *const ()),
    SyncFnPtr::new(DeleteCriticalSection as *const ()),
    SyncFnPtr::new(EnterCriticalSection as *const ()),
    SyncFnPtr::new(LeaveCriticalSection as *const ()),
    SyncFnPtr::new(HeapAlloc as *const ()),
    SyncFnPtr::new(HeapFree as *const ()),
    SyncFnPtr::new(GetSystemTimeAsFileTime as *const ()),

    SyncFnPtr::new(GetDesktopWindow as *const ()),
    SyncFnPtr::new(GetForegroundWindow as *const ()),
    SyncFnPtr::new(GetKeyboardLayout as *const ()),
    SyncFnPtr::new(GetKeyState as *const ()),
    SyncFnPtr::new(GetMessagePos as *const ()),

    SyncFnPtr::new(RegCloseKey as *const ()),
    SyncFnPtr::new(RegOpenKeyExW as *const ()),
    SyncFnPtr::new(GetUserNameA as *const ()),

    SyncFnPtr::new(RtlInitUnicodeString as *const ()),
    SyncFnPtr::new(RtlFreeUnicodeString as *const ()),

    SyncFnPtr::new(memcpy as *const ()),
    SyncFnPtr::new(memset as *const ()),
    SyncFnPtr::new(_wcsicmp as *const ()),

    SyncFnPtr::new(ptr::null()),
];

#[inline(never)]
pub(crate) fn force_linkage() {
    unsafe {

        let _ = core::ptr::read_volatile(&(GetLastError as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetCurrentProcessId as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetCurrentThreadId as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetModuleHandleA as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetModuleHandleW as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetProcessHeap as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetEnvironmentVariableA as *const () as usize));
        let _ = core::ptr::read_volatile(&(CloseHandle as *const () as usize));
        let _ = core::ptr::read_volatile(&(CreateFileW as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetFileSize as *const () as usize));
        let _ = core::ptr::read_volatile(&(FindFirstFileW as *const () as usize));
        let _ = core::ptr::read_volatile(&(FindClose as *const () as usize));
        let _ = core::ptr::read_volatile(&(InitializeCriticalSection as *const () as usize));
        let _ = core::ptr::read_volatile(&(DeleteCriticalSection as *const () as usize));
        let _ = core::ptr::read_volatile(&(EnterCriticalSection as *const () as usize));
        let _ = core::ptr::read_volatile(&(LeaveCriticalSection as *const () as usize));
        let _ = core::ptr::read_volatile(&(HeapAlloc as *const () as usize));
        let _ = core::ptr::read_volatile(&(HeapFree as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetSystemTimeAsFileTime as *const () as usize));

        let _ = core::ptr::read_volatile(&(GetDesktopWindow as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetForegroundWindow as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetKeyboardLayout as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetKeyState as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetMessagePos as *const () as usize));

        let _ = core::ptr::read_volatile(&(RegCloseKey as *const () as usize));
        let _ = core::ptr::read_volatile(&(RegOpenKeyExW as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetUserNameA as *const () as usize));

        let _ = core::ptr::read_volatile(&(RtlInitUnicodeString as *const () as usize));
        let _ = core::ptr::read_volatile(&(RtlFreeUnicodeString as *const () as usize));

        let _ = core::ptr::read_volatile(&(memcpy as *const () as usize));
        let _ = core::ptr::read_volatile(&(memset as *const () as usize));
        let _ = core::ptr::read_volatile(&(_wcsicmp as *const () as usize));
    }
}

const _: () = {
    assert!(core::mem::size_of::<SyncFnPtr>() == core::mem::size_of::<*const ()>());
};

