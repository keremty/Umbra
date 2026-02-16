
pub(crate) const PAYLOAD_ENCRYPTED: bool = false;

pub(crate) const PAYLOAD_ONESHOT: bool = true;





pub(crate) fn decode_payload() -> Vec<u8> {

    let mut data = vec![0x90u8; 512];


    if PAYLOAD_ENCRYPTED {
        data = crate::obfuscation::decrypt_payload(&data);
    }

    data
}


