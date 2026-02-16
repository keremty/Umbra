#![allow(non_snake_case)]

use winapi::shared::minwindef::HMODULE;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE,
};

pub(crate) const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub(crate) const IMAGE_PE_SIGNATURE: u32 = 0x4550;
pub(crate) const IMAGE_NT_OPTIONAL_HDR64_MAGIC_LOCAL: u16 = 0x20B;

#[inline]

pub(crate) unsafe fn validate_dos_header(base: *const u8) -> Option<u32> {
    if base.is_null() {
        return None;
    }

    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    Some((*dos).e_lfanew as u32)
}

#[inline]

pub(crate) unsafe fn validate_pe_header(base: *const u8) -> Option<*const IMAGE_NT_HEADERS64> {
    let e_lfanew = validate_dos_header(base)?;

    let nt = (base as usize + e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    Some(nt)
}

pub(crate) unsafe fn find_text_section(base: *const u8) -> Option<(*const u8, usize)> {
    if base.is_null() {
        return None;
    }

    let dos_magic = *(base as *const u16);
    if dos_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let e_lfanew = *(base.add(0x3C) as *const u32);
    let pe_header = base.add(e_lfanew as usize);

    let pe_sig = *(pe_header as *const u32);
    if pe_sig != IMAGE_PE_SIGNATURE {
        return None;
    }

    let optional_header = pe_header.add(0x18);
    let magic = *(optional_header as *const u16);

    let (section_offset, num_sections_offset) = if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC_LOCAL {
        (0x18 + 0xF0, 0x06)
    } else {
        (0x18 + 0xE0, 0x06)
    };

    let num_sections = *(pe_header.add(num_sections_offset) as *const u16);
    let sections = pe_header.add(section_offset);

    for i in 0..num_sections as usize {
        let section = sections.add(i * 0x28);
        let name = core::slice::from_raw_parts(section, 8);

        if name[0] == b'.'
            && name[1] == b't'
            && name[2] == b'e'
            && name[3] == b'x'
            && name[4] == b't'
        {
            let virtual_size = *(section.add(8) as *const u32) as usize;
            let virtual_address = *(section.add(12) as *const u32) as usize;
            let text_start = base.add(virtual_address);
            return Some((text_start, virtual_size));
        }
    }

    None
}

pub(crate) unsafe fn get_ntdll_text_bounds() -> Option<(usize, usize)> {
    use crate::hash::{get_module_by_hash, H_NTDLL};

    let ntdll = get_module_by_hash(H_NTDLL)?;
    if ntdll.is_null() {
        return None;
    }

    let base = ntdll as *const u8;

    let (text_start, text_size) = find_text_section(base)?;
    let start = text_start as usize;
    let end = start + text_size;

    Some((start, end))
}

pub(crate) unsafe fn get_module_size(module: HMODULE) -> Option<u32> {
    if module.is_null() {
        return None;
    }

    let base = module as *const u8;
    let nt = validate_pe_header(base)?;

    Some((*nt).OptionalHeader.SizeOfImage)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

pub(crate) unsafe fn find_pdata_entries(base: *const u8) -> Option<(*const RuntimeFunction, usize)> {
    if base.is_null() {
        return None;
    }

    let e_lfanew = validate_dos_header(base)? as usize;
    let nt_headers = base.add(e_lfanew);

    let pe_sig = *(nt_headers as *const u32);
    if pe_sig != IMAGE_PE_SIGNATURE {
        return None;
    }

    let optional_header = nt_headers.add(0x18);
    let magic = *(optional_header as *const u16);
    if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC_LOCAL {
        return None;
    }

    let exception_rva = *(optional_header.add(0x88) as *const u32);
    let exception_size = *(optional_header.add(0x8C) as *const u32);

    if exception_rva == 0 || exception_size == 0 {
        return None;
    }

    let pdata = base.add(exception_rva as usize) as *const RuntimeFunction;
    let count = exception_size as usize / core::mem::size_of::<RuntimeFunction>();

    Some((pdata, count))
}

pub(crate) unsafe fn lookup_function_entry(
    pdata: *const RuntimeFunction,
    count: usize,
    rva: u32,
) -> Option<*const RuntimeFunction> {
    if count == 0 || pdata.is_null() {
        return None;
    }

    let mut low: usize = 0;
    let mut high: usize = count;

    while low < high {
        let mid = low + (high - low) / 2;
        let entry = pdata.add(mid);

        if rva < (*entry).begin_address {
            high = mid;
        } else if rva >= (*entry).end_address {
            low = mid + 1;
        } else {
            return Some(entry);
        }
    }

    None
}

pub(crate) unsafe fn function_has_frame_register(
    module_base: *const u8,
    rf: *const RuntimeFunction,
) -> bool {
    let raw_rva = (*rf).unwind_info_address;

    if raw_rva & 1 != 0 {
        return true;
    }

    let unwind_info = module_base.add(raw_rva as usize);

    let frame_reg = core::ptr::read_volatile(unwind_info.add(3)) & 0x0F;
    frame_reg != 0
}

pub(crate) unsafe fn calculate_frame_allocation(
    module_base: *const u8,
    rf: *const RuntimeFunction,
) -> u32 {
    let raw_rva = (*rf).unwind_info_address;

    if raw_rva & 1 != 0 {
        return 0x40;
    }

    let unwind_info = module_base.add(raw_rva as usize);

    let count_of_codes = core::ptr::read_volatile(unwind_info.add(2)) as usize;

    if count_of_codes > 64 {
        return 0x40;
    }

    let codes_base = unwind_info.add(4);

    let mut total_alloc: u32 = 0;
    let mut push_count: u32 = 0;
    let mut i: usize = 0;

    while i < count_of_codes {
        let code_word = core::ptr::read_volatile(codes_base.add(i * 2) as *const u16);

        let unwind_op = ((code_word >> 8) & 0x0F) as u8;
        let op_info = ((code_word >> 12) & 0x0F) as u8;

        match unwind_op {
            0 => {

                push_count += 1;
                i += 1;
            }
            1 => {

                if op_info == 0 {

                    i += 1;
                    if i < count_of_codes {
                        let size_div8 = core::ptr::read_volatile(
                            codes_base.add(i * 2) as *const u16
                        ) as u32;
                        total_alloc += size_div8 * 8;
                    }
                    i += 1;
                } else {

                    i += 1;
                    if i + 1 < count_of_codes {
                        let lo = core::ptr::read_volatile(
                            codes_base.add(i * 2) as *const u16
                        ) as u32;
                        let hi = core::ptr::read_volatile(
                            codes_base.add((i + 1) * 2) as *const u16
                        ) as u32;
                        total_alloc += lo | (hi << 16);
                    }
                    i += 2;
                }
            }
            2 => {

                total_alloc += (op_info as u32) * 8 + 8;
                i += 1;
            }
            3 => {

                i += 1;
            }
            4 => {

                i += 2;
            }
            5 => {

                i += 3;
            }
            6 | 7 => {

                i += 2;
            }
            8 => {

                i += 2;
            }
            9 => {

                i += 3;
            }
            10 => {

                if op_info == 0 {
                    total_alloc += 40;
                } else {
                    total_alloc += 48;
                }
                i += 1;
            }
            _ => {

                i += 1;
            }
        }
    }

    let frame_size = total_alloc + push_count * 8 + 8;

    let frame_size = if frame_size < 0x28 { 0x28 } else { frame_size };
    let frame_size = if frame_size > 0x80 { 0x80 } else { frame_size };

    (frame_size + 7) & !7
}

