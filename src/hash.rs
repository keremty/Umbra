use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, PIMAGE_DOS_HEADER, PIMAGE_EXPORT_DIRECTORY, PIMAGE_NT_HEADERS64,
};

pub(crate) use crate::nt::{
    LDR_DATA_TABLE_ENTRY, LIST_ENTRY,
};
use crate::ssn_resolver::get_peb;

pub(crate) const FNV_OFFSET: u64 = include!(concat!(env!("OUT_DIR"), "/fnv_offset.in"));

pub(crate) const FNV_PRIME: u64 = include!(concat!(env!("OUT_DIR"), "/fnv_prime.in"));

pub(crate) const HASH_SALT: u64 = include!(concat!(env!("OUT_DIR"), "/hash_salt.in"));

pub(crate) const HASH_TAG: u64 = include!(concat!(env!("OUT_DIR"), "/hash_tag.in"));

pub const fn fnv1a_hash(s: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    let mut i = 0;
    while i < s.len() {
        hash ^= s[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }

    let tag_mix = HASH_TAG.rotate_left((s.len() as u32) & 31);
    hash ^ HASH_SALT ^ tag_mix
}

#[inline]
pub(crate) fn fnv1a_hash_runtime(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    let tag_mix = HASH_TAG.rotate_left((data.len() as u32) & 31);
    hash ^ HASH_SALT ^ tag_mix
}

pub(crate) const H_NTDLL: u64 = fnv1a_hash(b"ntdll.dll");
pub(crate) const H_KERNEL32: u64 = fnv1a_hash(b"kernel32.dll");
pub(crate) const H_KERNELBASE: u64 = fnv1a_hash(b"kernelbase.dll");

pub(crate) const H_RTL_USER_THREAD_START: u64 = fnv1a_hash(b"RtlUserThreadStart");
pub(crate) const H_BASE_THREAD_INIT_THUNK: u64 = fnv1a_hash(b"BaseThreadInitThunk");

pub unsafe fn get_module_by_hash(target_hash: u64) -> Option<HMODULE> {
    let peb = get_peb();
    if peb.is_null() || (*peb).Ldr.is_null() {
        return None;
    }
    let ldr = (*peb).Ldr;
    let head = &mut (*ldr).InMemoryOrderModuleList as *mut LIST_ENTRY;
    let mut curr = (*head).Flink;

    while curr != head {
        let entry = (curr as *mut u8).sub(0x10) as *mut LDR_DATA_TABLE_ENTRY;
        if !(*entry).BaseDllName.Buffer.is_null() {
            let name_len = (*entry).BaseDllName.Length as usize / 2;
            let name_slice = std::slice::from_raw_parts((*entry).BaseDllName.Buffer, name_len);

            let mut buf = [0u8; 64];
            let len = name_len.min(buf.len());
            for i in 0..len {
                buf[i] = (name_slice[i] as u8).to_ascii_lowercase();
            }

            let computed_hash = fnv1a_hash_runtime(&buf[..len]);
            if computed_hash == target_hash {
                return Some((*entry).DllBase as HMODULE);
            }
        }
        curr = (*curr).Flink;
    }
    None
}

pub unsafe fn get_export_by_hash(module: HMODULE, target_hash: u64) -> Option<FARPROC> {
    let dos_header = module as PIMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D {
        return None;
    }

    let nt_headers = (module as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != 0x4550 {
        return None;
    }

    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        .VirtualAddress;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = (module as usize + export_dir_rva as usize) as PIMAGE_EXPORT_DIRECTORY;
    let names = (module as usize + (*export_dir).AddressOfNames as usize) as *const u32;
    let ordinals = (module as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;
    let functions = (module as usize + (*export_dir).AddressOfFunctions as usize) as *const u32;

    let num_names = (*export_dir).NumberOfNames as usize;

    for i in 0..num_names {
        let name_rva = *names.add(i);
        let name_ptr = (module as usize + name_rva as usize) as *const i8;

        let mut name_len = 0usize;
        while *name_ptr.add(name_len) != 0 && name_len < 256 {
            name_len += 1;
        }
        let name_bytes = std::slice::from_raw_parts(name_ptr as *const u8, name_len);
        let computed_hash = fnv1a_hash_runtime(name_bytes);

        if computed_hash == target_hash {
            let ordinal = *ordinals.add(i) as usize;
            let func_rva = *functions.add(ordinal);
            return Some((module as usize + func_rva as usize) as FARPROC);
        }
    }
    None
}

