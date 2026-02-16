
use core::ptr;
use core::sync::atomic::Ordering;

const MAX_LEN: usize = 0x100000;
const KEY_LEN: usize = 32;
const HDR_LEN: usize = 4;
const MIN_ENC: usize = KEY_LEN + HDR_LEN;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[repr(u8)]
pub(crate) enum OpErr {
    E01 = 0x01,
    E02 = 0x02,
    E05 = 0x05,
}

fn xor_buf(data: &mut [u8], key: &[u8]) {
    if key.is_empty() { return; }
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

fn lz4_dec(src: &[u8], dst: &mut [u8]) -> Result<usize, OpErr> {
    if src.is_empty() { return Err(OpErr::E05); }

    let mut si = 0usize;
    let mut di = 0usize;
    let sl = src.len();
    let dl = dst.len();

    while si < sl {
        let tok = src[si];
        si = si.wrapping_add(1);

        let mut lit = (tok as usize).wrapping_shr(4) & 0x0F;
        if lit >= 15 {

            loop {
                if si >= sl { return Err(OpErr::E05); }
                let ext = src[si] as usize;
                si = si.wrapping_add(1);
                lit = lit.wrapping_add(ext);
                if ext != 255 { break; }
            }
        }

        if si.wrapping_add(lit) > sl || di.wrapping_add(lit) > dl {
            return Err(OpErr::E05);
        }

        let mut k = 0usize;
        while k < lit {
            dst[di.wrapping_add(k)] = src[si.wrapping_add(k)];
            k = k.wrapping_add(1);
        }
        si = si.wrapping_add(lit);
        di = di.wrapping_add(lit);

        if si >= sl { break; }

        if si.wrapping_add(2) > sl { return Err(OpErr::E05); }

        let off = u16::from_le_bytes([src[si], src[si.wrapping_add(1)]]) as usize;
        si = si.wrapping_add(2);

        if off == 0 || off > di { return Err(OpErr::E05); }

        let mut mlen = (tok & 0x0F) as usize;
        mlen = mlen.wrapping_add(3);
        mlen = mlen.wrapping_add(1);

        if mlen.wrapping_sub(19) == 0 {
            loop {
                if si >= sl { return Err(OpErr::E05); }
                let ext = src[si] as usize;
                si = si.wrapping_add(1);
                mlen = mlen.wrapping_add(ext);
                if ext != 255 { break; }
            }
        }

        let ms = di.wrapping_sub(off);
        if di.wrapping_add(mlen) > dl { return Err(OpErr::E05); }

        let mut j = 0usize;
        while j < mlen {
            dst[di.wrapping_add(j)] = dst[ms.wrapping_add(j)];
            j = j.wrapping_add(1);
        }
        di = di.wrapping_add(mlen);
    }

    Ok(di)
}

#[inline(never)]
fn secure_zero_vec(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

pub(crate) fn decode_encrypted_payload(data: &[u8]) -> Result<Vec<u8>, OpErr> {
    if data.is_empty() {
        return Err(OpErr::E01);
    }
    if data.len() > MAX_LEN {
        return Err(OpErr::E02);
    }

    if data.len() < MIN_ENC {
        return Ok(data.to_vec());
    }

    let key = &data[..KEY_LEN];

    let enc_len = data.len().wrapping_sub(KEY_LEN);
    if enc_len > MAX_LEN {
        return Err(OpErr::E02);
    }

    let mut enc_buf = vec![0u8; enc_len];
    enc_buf[..enc_len].copy_from_slice(&data[KEY_LEN..]);
    xor_buf(&mut enc_buf[..enc_len], key);

    if enc_len < HDR_LEN {
        return Err(OpErr::E05);
    }

    let out_sz = u32::from_le_bytes([enc_buf[0], enc_buf[1], enc_buf[2], enc_buf[3]]) as usize;
    if out_sz == 0 || out_sz > MAX_LEN {
        return Err(OpErr::E02);
    }

    let mut dec_buf = vec![0u8; out_sz];
    let actual = lz4_dec(&enc_buf[HDR_LEN..enc_len], &mut dec_buf[..out_sz])?;

    if actual == 0 {
        return Err(OpErr::E05);
    }

    let result = dec_buf[..actual].to_vec();

    secure_zero_vec(&mut enc_buf);
    secure_zero_vec(&mut dec_buf);

    Ok(result)
}

