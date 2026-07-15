use pelite::{PeFile, Wrap};
use pelite::pe32::Pe as Pe32Trait;
use pelite::pe64::Pe as Pe64Trait;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SteamStubStatus {
    NotDetected,
    Decrypted,
}

pub fn is_steamstub(data: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    let pe = PeFile::from_bytes(data)?;
    Ok(pe.section_headers().iter().any(|section| {
        String::from_utf8_lossy(&section.Name).starts_with(".bind")
    }))
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

pub fn decrypt_steamstub_in_memory(file_data: &mut [u8]) -> Result<SteamStubStatus, Box<dyn std::error::Error>> {
    let pe_temp = PeFile::from_bytes(&file_data)?;
    let mut bind_section_info = None;
    
    for s in pe_temp.section_headers() {
        let name = String::from_utf8_lossy(&s.Name);
        if name.starts_with(".bind") {
            bind_section_info = Some((s.VirtualAddress, s.VirtualSize, s.PointerToRawData, s.SizeOfRawData));
            break;
        }
    }
    
    if bind_section_info.is_none() {
        return Ok(SteamStubStatus::NotDetected);
    }
    
    tracing::info!("检测到 SteamStub 保护，正在尝试进行内存解壳...");
    if let Some((bind_va, bind_vsize, _, _)) = bind_section_info {
        let oep = match pe_temp {
            Wrap::T32(pe32) => pe32.optional_header().AddressOfEntryPoint,
            Wrap::T64(pe64) => pe64.optional_header().AddressOfEntryPoint,
        };
        let mut check_oep_va = oep;
        
        let ib = match pe_temp {
            Wrap::T32(pe32) => pe32.optional_header().ImageBase as u64,
            Wrap::T64(pe64) => pe64.optional_header().ImageBase,
        };

        if !(check_oep_va >= bind_va && check_oep_va < bind_va + bind_vsize) {
            if let Ok(tls) = pe_temp.tls() {
                if let Ok(callbacks) = tls.callbacks() {
                    let first_cb = match callbacks {
                        Wrap::T32(cb) => cb.first().map(|&x| x as u64),
                        Wrap::T64(cb) => cb.first().copied(),
                    };
                    if let Some(callback) = first_cb {
                        if callback != 0 {
                            check_oep_va = (callback - ib) as u32;
                        }
                    }
                }
            }
        }
        
        if check_oep_va >= bind_va && check_oep_va < bind_va + bind_vsize {
            let oep_offset_res = match pe_temp {
                Wrap::T32(pe32) => pe32.rva_to_file_offset(check_oep_va),
                Wrap::T64(pe64) => pe64.rva_to_file_offset(check_oep_va),
            };
            let oep_offset = oep_offset_res
                .map_err(|e| format!("SteamStub entry point cannot be mapped to file offset: {e}"))? as usize;
            if oep_offset < 240 {
                return Err("SteamStub header is outside the file boundary".into());
            }
            {
                    let mut header_bytes = file_data[oep_offset - 240 .. oep_offset].to_vec();
                    let mut xor_key = 0;
                    steam_xor(&mut header_bytes, &mut xor_key);
                    
                    let header: SteamStub32Var31Header = unsafe {
                        std::ptr::read_unaligned(header_bytes.as_ptr() as *const SteamStub32Var31Header)
                    };
                    
                    let signature = header.signature;
                    if signature == 0xC0DEC0DF {
                        let steam_app_id = header.steam_app_id;
                        let aes_key = header.aes_key;
                        let aes_iv = header.aes_iv;
                        let stolen_data = header.code_section_stolen_data;
                        let code_va = header.code_section_virtual_address as u32;
                        let code_size = header.code_section_raw_size as usize;
                        
                        tracing::info!("SteamStub Variant 3.1 签名验证成功。Steam AppID: {}", steam_app_id);
                        
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
                            if read_size == 0 || code_raw_offset.checked_add(read_size).is_none_or(|end| end > file_data.len()) {
                                return Err("SteamStub encrypted code section is outside the file boundary".into());
                            }
                            
                            let mut cipher_buf = vec![0u8; 16 + read_size];
                            cipher_buf[0..16].copy_from_slice(&stolen_data);
                            cipher_buf[16..].copy_from_slice(&file_data[code_raw_offset .. code_raw_offset + read_size]);
                            
                            aes_256_cbc_decrypt(&aes_key, &aes_iv, &mut cipher_buf)
                                .map_err(|e| format!("SteamStub code section AES decryption failed: {e}"))?;
                            tracing::info!("代码段 AES 解密还原成功，已应用至内存。");
                            file_data[code_raw_offset .. code_raw_offset + read_size].copy_from_slice(&cipher_buf[16 .. 16 + read_size]);
                        } else {
                            return Err(format!("SteamStub code RVA 0x{code_va:08x} does not belong to any PE section").into());
                        }
                    } else {
                        return Err(format!("Unsupported SteamStub variant or invalid signature: 0x{signature:08x}. Please try a Steamless-unpacked EXE").into());
                    }
            }
        } else {
            return Err("Detected .bind section, but neither entry point nor TLS callback points into it. Please try a Steamless-unpacked EXE".into());
        }
    }

    // Reparse the modified image and ensure its resource directory remains usable.
    let reparsed = PeFile::from_bytes(file_data)?;
    reparsed.resources()?.root()?;
    Ok(SteamStubStatus::Decrypted)
}
