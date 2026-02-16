use crate::config::{XOR_KEY, XOR_KEY2};

pub(crate) fn decrypt_payload(encrypted: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(encrypted.len());

    for (i, &byte) in encrypted.iter().enumerate() {
        let k1 = XOR_KEY[i % XOR_KEY.len()];
        let k2 = XOR_KEY2[i % XOR_KEY2.len()];
        let k3 = ((i.wrapping_mul(7)) & 0xFF) as u8;

        let decrypted = byte ^ k1 ^ k2 ^ k3;
        output.push(decrypted);
    }

    output
}

