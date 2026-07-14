use clap::Parser;
use pelite::pe32::{Pe, PeFile};
use sha3::{Digest, Sha3_384};
use std::fs;
use std::path::PathBuf;
use flate2::read::ZlibDecoder;
use std::io::Read;

use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::core::HSTRING;
use std::os::raw::c_void;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    exe: PathBuf,
    #[arg(long)]
    work_dir: PathBuf,
    #[arg(long)]
    out: Option<PathBuf>,
}

fn rotl32(v: u32, n: u32) -> u32 {
    v.rotate_left(n)
}

fn chacha8_block(state: &mut [u32; 16]) {
    let mut s = *state;
    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            s[$a] = s[$a].wrapping_add(s[$b]);
            s[$d] ^= s[$a];
            s[$d] = rotl32(s[$d], 16);
            s[$c] = s[$c].wrapping_add(s[$d]);
            s[$b] ^= s[$c];
            s[$b] = rotl32(s[$b], 12);
            s[$a] = s[$a].wrapping_add(s[$b]);
            s[$d] ^= s[$a];
            s[$d] = rotl32(s[$d], 8);
            s[$c] = s[$c].wrapping_add(s[$d]);
            s[$b] ^= s[$c];
            s[$b] = rotl32(s[$b], 7);
        };
    }
    for _ in 0..4 {
        qr!(0, 4, 8, 12); qr!(1, 5, 9, 13); qr!(2, 6, 10, 14); qr!(3, 7, 11, 15);
        qr!(0, 5, 10, 15); qr!(1, 6, 11, 12); qr!(2, 7, 8, 13); qr!(3, 4, 9, 14);
    }
    for i in 0..16 {
        state[i] = state[i].wrapping_add(s[i]);
    }
}

fn decrypt_bres(ciphertext: &[u8], path_key: &str, salt: &[u8]) -> Vec<u8> {
    let mut h = Sha3_384::new();
    let path_utf16: Vec<u8> = path_key.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    h.update(&path_utf16);
    h.update(salt);
    let digest = h.finalize();

    let mut key_words = [0u32; 8];
    for i in 0..8 {
        key_words[i] = u32::from_le_bytes(digest[i*4 .. i*4+4].try_into().unwrap());
    }
    
    let mut nonce_words = [0u32; 2];
    nonce_words[0] = u32::from_le_bytes(digest[32..36].try_into().unwrap());
    nonce_words[1] = u32::from_le_bytes(digest[36..40].try_into().unwrap());
    
    let ctr_base = u32::from_le_bytes(digest[40..44].try_into().unwrap());
    let ctr_high = u32::from_le_bytes(digest[44..48].try_into().unwrap());
    let chacha_const = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574];
    
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let total_blocks = (ciphertext.len() + 63) / 64;

    for bn in 0..total_blocks {
        let ctr_low = ctr_base ^ (bn as u32);
        let mut orig_state = [
            chacha_const[0], chacha_const[1], chacha_const[2], chacha_const[3],
            key_words[0], key_words[1], key_words[2], key_words[3],
            key_words[4], key_words[5], key_words[6], key_words[7],
            ctr_low, ctr_high, nonce_words[0], nonce_words[1]
        ];
        
        chacha8_block(&mut orig_state);
        
        let mut keystream = [0u8; 64];
        for i in 0..16 {
            keystream[i*4..i*4+4].copy_from_slice(&orig_state[i].to_le_bytes());
        }

        let offset = bn * 64;
        let end = std::cmp::min(offset + 64, ciphertext.len());
        for i in 0..(end - offset) {
            plaintext.push(ciphertext[offset + i] ^ keystream[i]);
        }
    }
    plaintext
}

use pelite::pe32::PeObject;

fn get_resource_data<'a>(pe: &PeFile<'a>, type_id: pelite::resources::Name, name_id: pelite::resources::Name) -> Option<&'a [u8]> {
    let res = pe.resources().ok()?;
    let root = res.root().ok()?;
    let t_dir = root.get_dir(type_id).ok()?;
    let n_dir = t_dir.get_dir(name_id).ok()?;
    let entry = n_dir.entries().next()?.entry().ok()?;
    if let Some(d) = entry.data() {
        return d.bytes().ok();
    }
    if let Some(l_dir) = entry.dir() {
        let data_entry = l_dir.entries().next()?.entry().ok()?.data()?;
        return data_entry.bytes().ok();
    }
    None
}

fn get_text_127<'a>(pe: &PeFile<'a>) -> Option<String> {
    if let Some(bytes) = get_resource_data(pe, pelite::resources::Name::Str("TEXT".into()), pelite::resources::Name::Id(127)) {
        let u16s: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&u16s).trim_end_matches('\0').to_string())
    } else {
        None
    }
}


fn search_salt<'a>(pe: &PeFile<'a>) -> Option<&'a [u8]> {
    let data = pe.image();
    for off in 0..data.len()-20 {
        if data[off] == 0xC7 && data[off+1] == 0x05 {
            let salt_va = u32::from_le_bytes([data[off+6], data[off+7], data[off+8], data[off+9]]);
            if salt_va < pe.optional_header().ImageBase as u32 { continue; }
            let salt_rva = salt_va - pe.optional_header().ImageBase as u32;
            if let Ok(salt_offset) = pe.rva_to_file_offset(salt_rva) {
                if salt_offset + 0x2000 > data.len() { continue; }
                let end = std::cmp::min(data.len() - 10, off + 64);
                for size_off in off+10..end {
                    if data[size_off] == 0xC7 && data[size_off+1] == 0x05 {
                        let sz = u32::from_le_bytes([data[size_off+6], data[size_off+7], data[size_off+8], data[size_off+9]]);
                        if sz == 0x2000 {
                            return Some(&data[salt_offset .. salt_offset + 0x2000]);
                        }
                    }
                }
            }
        }
    }
    None
}

fn parse_config_table(dll_data: &[u8], rva: u32) -> std::collections::HashMap<String, Vec<u8>> {
    let mut map = std::collections::HashMap::new();
    let pe = PeFile::from_bytes(dll_data).unwrap();
    if let Ok(offset) = pe.rva_to_file_offset(rva) {
        let mut cur = offset;
        while cur < dll_data.len() {
            let mut end = cur;
            while end < dll_data.len() && dll_data[end] != 0 { end += 1; }
            if end == cur { break; }
            let label = String::from_utf8_lossy(&dll_data[cur..end]).to_string();
            cur = end + 1;
            let length = u16::from_le_bytes([dll_data[cur], dll_data[cur+1]]) as usize;
            cur += 2;
            map.insert(label, dll_data[cur..cur+length].to_vec());
            cur += length;
        }
    }
    map
}

fn parse_tjs_strings(data: &[u8]) -> Vec<String> {
    if data.len() < 12 || &data[0..8] != b"TJS2100\0" {
        return Vec::new();
    }
    let mut off = 12;
    while off + 8 <= data.len() {
        let tag = &data[off..off+4];
        let size = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]) as usize;
        let chunk_end = off + size;
        if size < 8 || chunk_end > data.len() { break; }
        
        if tag == b"DATA" {
            let body = &data[off+8..chunk_end];
            let mut p = 0;
            let align4 = |n: usize| (n + 3) & !3;
            let mut take_count = |unit: usize| {
                if p + 4 > body.len() { return; }
                let count = u32::from_le_bytes([body[p], body[p+1], body[p+2], body[p+3]]) as usize;
                p += 4;
                p += align4(count * unit);
            };
            take_count(1); // bytes
            take_count(2); // shorts
            take_count(4); // ints
            take_count(8); // int64s
            take_count(8); // reals_raw

            if p + 4 <= body.len() {
                let string_count = u32::from_le_bytes([body[p], body[p+1], body[p+2], body[p+3]]) as usize;
                p += 4;
                let mut strings = Vec::new();
                for _ in 0..string_count {
                    if p + 4 > body.len() { break; }
                    let length = u32::from_le_bytes([body[p], body[p+1], body[p+2], body[p+3]]) as usize;
                    p += 4;
                    let raw_len = length * 2;
                    if p + raw_len > body.len() { break; }
                    let u16s: Vec<u16> = body[p..p+raw_len].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    strings.push(String::from_utf16_lossy(&u16s));
                    p += align4(raw_len);
                }
                return strings;
            }
        }
        off = chunk_end;
    }
    Vec::new()
}

type ManagerCtor = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;
type BootstrapDerive = unsafe extern "thiscall" fn(*mut c_void, *const u8, usize, *const u8, usize) -> u8;
type ArchiveDerive = unsafe extern "thiscall" fn(*mut c_void, *const u8, usize, *const u8) -> i32;
type HashKeyDerive = unsafe extern "C" fn(*mut u8, usize, *const u8, usize, i32);

unsafe fn read_u32(ptr: *const u8) -> u32 {
    let slice = unsafe { std::slice::from_raw_parts(ptr, 4) };
    u32::from_le_bytes(slice.try_into().unwrap())
}

fn derive_drip(dll_path: &PathBuf, bootstrap_bytes: &[u8], params_bytes: &[u8], out_path: &PathBuf, archive_name: &str) -> Result<serde_json::Value, String> {
    unsafe {
        let module = LoadLibraryW(&HSTRING::from(dll_path.to_str().unwrap())).map_err(|e| e.to_string())?;
        let base = module.0 as *mut u8;
        
        let ctor: ManagerCtor = std::mem::transmute(base.add(0x0E2D0));
        let boot_derive: BootstrapDerive = std::mem::transmute(base.add(0x15630));
        let arch_derive: ArchiveDerive = std::mem::transmute(base.add(0x157D0));
        let hash_derive: HashKeyDerive = std::mem::transmute(base.add(0x10410));

        let manager_size = 0x30B0;
        let manager = VirtualAlloc(None, manager_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        ctor(manager);
        let core = (manager as *mut u8).add(0x08);
        
        let ok = boot_derive(core as *mut c_void, bootstrap_bytes.as_ptr(), bootstrap_bytes.len(), params_bytes.as_ptr(), params_bytes.len());
        if ok == 0 { return Err("BootstrapDerive failed".into()); }
        
        let mut hash_key = vec![0u8; 32];
        hash_derive(hash_key.as_mut_ptr(), 32, (manager as *const u8).add(0x3040), 0x40, -1);
        
        // Find archive seed
        let mut seed = [0u8; 8];
        let static_seed = std::slice::from_raw_parts(base.add(0x81758), 8);
        if static_seed.iter().any(|&x| x != 0) {
            seed.copy_from_slice(static_seed);
        } else {
            let code = std::slice::from_raw_parts(base.add(0x157D0), 0x80);
            for i in 0..code.len()-14 {
                if code[i] == 0xC7 && code[i+1] == 0x45 && code[i+7] == 0xC7 && code[i+8] == 0x45 && (code[i+2].wrapping_add(4) == code[i+9]) {
                    seed[0..4].copy_from_slice(&code[i+3..i+7]);
                    seed[4..8].copy_from_slice(&code[i+10..i+14]);
                    break;
                }
            }
        }
        
        if archive_name != "" {
            let utf16_archive: Vec<u8> = archive_name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            arch_derive(core as *mut c_void, utf16_archive.as_ptr(), utf16_archive.len(), seed.as_ptr());
        }
        
        let manager_va = manager as u32;
        let drip_impl = read_u32((manager as *const u8).add(0x08));
        
        let mut lanes = Vec::new();
        for lane_idx in 0..128 {
            let lane_ptr = (drip_impl + 0x04 + lane_idx * 0x10) as *const u8;
            let begin = read_u32(lane_ptr);
            let end = read_u32(lane_ptr.add(4));
            
            let mut records = Vec::new();
            let mut record_ptr = begin;
            while record_ptr < end {
                let param = read_u32(record_ptr as *const u8);
                let cb = read_u32((record_ptr + 4) as *const u8);
                let mut cb_rva = cb;
                if cb >= base as u32 && cb < base as u32 + 0x200000 {
                    cb_rva = cb - base as u32;
                }
                records.push(vec![serde_json::json!(param), serde_json::json!(cb_rva)]);
                record_ptr += 8;
            }
            lanes.push(serde_json::json!({
                "index": lane_idx,
                "begin_va": begin,
                "end_va": end,
                "current_va": read_u32(lane_ptr.add(8)),
                "ctx_va": read_u32(lane_ptr.add(12)),
                "records": records
            }));
        }
        
        let hxv4_key = hex::encode(std::slice::from_raw_parts((manager as *const u8).add(0x08 + 0x3038), 32));
        let hxv4_nonce0 = hex::encode(std::slice::from_raw_parts((manager as *const u8).add(0x08 + 0x3078), 24));
        let hxv4_nonce1 = hex::encode(std::slice::from_raw_parts((manager as *const u8).add(0x08 + 0x3058), 24));
        
        let context_size = 0x30B0 - 0x28;
        let mut context_u32 = Vec::new();
        for i in 0..(context_size/4) {
            context_u32.push(read_u32((manager as *const u8).add(0x28 + i*4)));
        }
        let mut holder_words = Vec::new();
        for i in 0..6 {
            holder_words.push(read_u32((manager as *const u8).add(0x08 + i*4)));
        }
        
        let payload = serde_json::json!({
            "version": 1,
            "source_module": dll_path.file_name().unwrap().to_str().unwrap(),
            "source_module_base": base as u32,
            "manager_va": manager_va,
            "drip_impl_va": drip_impl,
            "hxv4_key": hxv4_key,
            "hxv4_nonce0": hxv4_nonce0,
            "hxv4_nonce1": hxv4_nonce1,
            "hash_key": hex::encode(hash_key),
            "holder_words": holder_words,
            "context_va": manager as u32 + 0x28,
            "context_u32": context_u32,
            "callback_rva_base": base as u32,
            "lanes": lanes
        });
        
        fs::write(out_path, serde_json::to_string(&payload).unwrap()).unwrap();
        Ok(payload)
    }
}

#[repr(C, packed)]
struct SteamStub32Var31Header {
    xor_key: u32,
    signature: u32,
    image_base: u64,
    address_of_entry_point: u64,
    bind_section_offset: u32,
    unknown0000: u32,
    original_entry_point: u64,
    unknown0001: u32,
    payload_size: u32,
    drmp_dll_offset: u32,
    drmp_dll_size: u32,
    steam_app_id: u32,
    flags: u32,
    bind_section_virtual_size: u32,
    unknown0002: u32,
    code_section_virtual_address: u64,
    code_section_raw_size: u64,
    aes_key: [u8; 32],
    aes_iv: [u8; 16],
    code_section_stolen_data: [u8; 16],
    encryption_keys: [u32; 4],
    unknown0003: [u32; 8],
    get_module_handle_a_rva: u64,
    get_module_handle_w_rva: u64,
    load_library_a_rva: u64,
    load_library_w_rva: u64,
    get_proc_address_rva: u64,
}

fn steam_xor(data: &mut [u8], key: &mut u32) {
    let mut offset = 0;
    if *key == 0 {
        offset = 4;
        *key = u32::from_le_bytes(data[0..4].try_into().unwrap());
    }
    for x in (offset..data.len()).step_by(4) {
        if x + 4 <= data.len() {
            let val = u32::from_le_bytes(data[x..x+4].try_into().unwrap());
            let plain = val ^ *key;
            data[x..x+4].copy_from_slice(&plain.to_le_bytes());
            *key = val;
        }
    }
}

fn aes_256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &mut [u8]) -> Result<(), String> {
    use aes::Aes256;
    use cbc::Decryptor;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};

    type Aes256CbcDec = Decryptor<Aes256>;

    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    decryptor.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(ciphertext)
        .map_err(|e| format!("AES decryption error: {:?}", e))?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    fs::create_dir_all(&args.work_dir)?;
    
    let mut file_data = fs::read(&args.exe)?;
    
    // SteamStub Decryption
    let pe_temp = PeFile::from_bytes(&file_data)?;
    let mut is_steam = false;
    let mut bind_section_info = None;
    
    for s in pe_temp.section_headers() {
        let name = String::from_utf8_lossy(&s.Name);
        if name.starts_with(".bind") {
            is_steam = true;
            bind_section_info = Some((s.VirtualAddress, s.VirtualSize, s.PointerToRawData, s.SizeOfRawData));
            break;
        }
    }
    
    if is_steam {
        println!("检测到 SteamStub 保护，正在进行内存解壳与代码段还原...");
        if let Some((bind_va, bind_vsize, _, _)) = bind_section_info {
            let oep = pe_temp.optional_header().AddressOfEntryPoint;
            let mut check_oep_va = oep;
            
            // Check if TLS callbacks exist, check TLS as fallback
            if !(check_oep_va >= bind_va && check_oep_va < bind_va + bind_vsize) {
                if let Ok(tls) = pe_temp.tls() {
                    if let Ok(callbacks) = tls.callbacks() {
                        if let Some(&callback) = callbacks.first() {
                            if callback != 0 {
                                check_oep_va = callback - pe_temp.optional_header().ImageBase as u32;
                            }
                        }
                    }
                }
            }
            
            if check_oep_va >= bind_va && check_oep_va < bind_va + bind_vsize {
                if let Ok(oep_offset) = pe_temp.rva_to_file_offset(check_oep_va) {
                    let oep_offset = oep_offset as usize;
                    if oep_offset >= 240 {
                        let mut header_bytes = file_data[oep_offset - 240 .. oep_offset].to_vec();
                        let mut xor_key = 0;
                        steam_xor(&mut header_bytes, &mut xor_key);
                        
                        let header: SteamStub32Var31Header = unsafe {
                            std::ptr::read_unaligned(header_bytes.as_ptr() as *const SteamStub32Var31Header)
                        };
                        
                        let signature = header.signature;
                        let steam_app_id = header.steam_app_id;
                        let aes_key = header.aes_key;
                        let aes_iv = header.aes_iv;
                        let stolen_data = header.code_section_stolen_data;
                        let code_va = header.code_section_virtual_address as u32;
                        let code_size = header.code_section_raw_size as usize;
                        
                        if signature == 0xC0DEC0DF {
                            println!("SteamStub Variant 3.1 签名验证成功。Steam AppID: {}", steam_app_id);
                            
                            // Find code section
                            let mut code_section_info = None;
                            for s in pe_temp.section_headers() {
                                let vsize = if s.VirtualSize == 0 { s.SizeOfRawData } else { s.VirtualSize };
                                if code_va >= s.VirtualAddress && code_va < s.VirtualAddress + vsize {
                                    code_section_info = Some((s.PointerToRawData as usize, s.SizeOfRawData as usize));
                                    break;
                                }
                            }
                            
                            if let Some((code_raw_offset, code_raw_size)) = code_section_info {
                                let read_size = std::cmp::min(code_size, code_raw_size);
                                
                                // Construct cipher buffer: stolen data (16 bytes) + encrypted code
                                let mut cipher_buf = vec![0u8; 16 + read_size];
                                cipher_buf[0..16].copy_from_slice(&stolen_data);
                                cipher_buf[16..].copy_from_slice(&file_data[code_raw_offset .. code_raw_offset + read_size]);
                                
                                if aes_256_cbc_decrypt(&aes_key, &aes_iv, &mut cipher_buf).is_ok() {
                                    println!("代码段 AES 解密还原成功，覆盖映射中。");
                                    // Overwrite the file_data code section with decrypted data (skipping stolen block output)
                                    file_data[code_raw_offset .. code_raw_offset + read_size].copy_from_slice(&cipher_buf[16 .. 16 + read_size]);
                                } else {
                                    println!("警告: 代码段 AES 解密失败！");
                                }
                            }
                        } else {
                            println!("警告: SteamStub 签名验证失败，可能为未支持的 Variant 版本。");
                        }
                    }
                }
            }
        }
    }
    
    let pe = PeFile::from_bytes(&file_data)?;
    
    let root_url = get_text_127(&pe).unwrap_or_default();
    let startup_key = root_url.replace("bres://./", "").trim_matches('/').to_string();
    let salt = search_salt(&pe).ok_or("Could not find bres salt")?;
    
    let startup_res = get_resource_data(&pe, pelite::resources::Name::Id(10), pelite::resources::Name::Str("STARTUP.TJS".into())).unwrap();
    let bootstrap_res = get_resource_data(&pe, pelite::resources::Name::Id(10), pelite::resources::Name::Str("BOOTSTRAP".into())).unwrap();

    let startup_plain = decrypt_bres(startup_res, &startup_key, salt);
    println!("startup_key: {}", startup_key);
    println!("startup starts with TJS2100: {}", startup_plain.starts_with(b"TJS2100\0"));
    let strings = parse_tjs_strings(&startup_plain);
    let mut bootstrap_url = "".to_string();
    for s in &strings {
        if s.starts_with("bres://./") && s.to_lowercase().ends_with("/bootstrap") {
            bootstrap_url = s.clone();
            break;
        }
    }
    let bootstrap_key = bootstrap_url.replace("bres://./", "").split('/').next().unwrap_or("").to_string();
    println!("bootstrap_key: {}", bootstrap_key);
    let bootstrap_plain = decrypt_bres(bootstrap_res, &bootstrap_key, salt);
    
    let mut decoder = ZlibDecoder::new(&bootstrap_plain[8..]);
    let mut dll_bytes = Vec::new();
    decoder.read_to_end(&mut dll_bytes)?;
    
    let dll_path = args.work_dir.join("bootstrap.dll");
    fs::write(&dll_path, &dll_bytes)?;
    
    let config = parse_config_table(&dll_bytes, 0x80E38);
    let unique = String::from_utf16_lossy(&config.get("UNIQUE").unwrap().chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<u16>>()).trim_end_matches('\0').to_string();
    let warning = String::from_utf8_lossy(config.get("WARNING").unwrap()).trim_end_matches('\0').to_string();
    
    let mut bootstrap_prefix = unique.clone();
    let mut candidates = Vec::new();
    for s in &strings {
        if s.to_lowercase().contains("all") { candidates.push(s.clone()); }
    }
    if candidates.len() == 1 { bootstrap_prefix = candidates[0].clone(); }
    else {
        let reserved: Vec<String> = candidates.iter().filter(|s| s.to_lowercase().contains("right") || s.to_lowercase().contains("reserved")).cloned().collect();
        if reserved.len() == 1 { bootstrap_prefix = reserved[0].clone(); }
        else if !candidates.is_empty() { bootstrap_prefix = candidates[0].clone(); }
    }
    
    let params_bytes = config.get("PARAMS").unwrap().clone();
    let bootstrap_text = format!("{}{}", bootstrap_prefix, warning);
    let bootstrap_bytes: Vec<u8> = bootstrap_text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    let out_path = args.out.unwrap_or(args.work_dir.join("drip_program.json"));
    
    let _drip_payload = derive_drip(&dll_path, &bootstrap_bytes, &params_bytes, &out_path, &unique)?;
    
    let summary = serde_json::json!({
        "startup_key": startup_key,
        "bootstrap_url": bootstrap_url,
        "bootstrap_key": bootstrap_key,
        "bootstrap_prefix": bootstrap_prefix,
        "warning": warning,
        "archive_unique_key": unique,
        "is_steam": is_steam,
        "outputs": {
            "dll": dll_path.to_string_lossy(),
            "drip_program": out_path.to_string_lossy()
        }
    });
    fs::write(args.work_dir.join("static_recover.summary.json"), serde_json::to_string_pretty(&summary)?)?;
    
    println!("Extraction successful. Drip generated.");
    Ok(())
}
