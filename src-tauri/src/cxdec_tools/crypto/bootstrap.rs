use crate::cxdec_tools::crypto::exe_resource::{
    decrypt_resource, EXE_RESOURCE_SALT_SIZE,
};
use pelite::{PeFile, Wrap};
use pelite::pe32::Pe as Pe32Trait;
use pelite::pe64::Pe as Pe64Trait;
use pelite::resources::{Name, Directory, Entry};
use std::path::Path;
use memchr::memmem;

/// Manually traverse the resource directory tree to find data bytes.
/// This mirrors the proven `get_resource_data` approach from cxdec-rs-analyzer
/// rather than relying on `find_resource` which doesn't reliably match
/// string type names like "TEXT" through the Wrap enum.
fn get_resource_bytes<'a>(
    root: &Directory<'a>,
    type_name: Name<'_>,
    res_name: Name<'_>,
) -> Option<&'a [u8]> {
    // Debug: log all top-level type entries
    for de in root.entries() {
        if let Ok(n) = de.name() {
            tracing::debug!("Resource type entry: {}", n);
        }
    }

    let type_dir = root.get_dir(type_name).ok()?;

    // Debug: log all name entries under this type
    for de in type_dir.entries() {
        if let Ok(n) = de.name() {
            tracing::debug!("Resource name entry under type: {}", n);
        }
    }

    let name_dir = type_dir.get_dir(res_name).ok()?;

    // Do not assume a particular language entry or nesting depth. Some games put
    // the usable data behind a non-default language entry.
    for language_entry in name_dir.entries() {
        let Ok(entry) = language_entry.entry() else { continue };
        match entry {
            Entry::DataEntry(data) => {
                if let Ok(bytes) = data.bytes() {
                    return Some(bytes);
                }
            }
            Entry::Directory(sub_dir) => {
                for inner_entry in sub_dir.entries() {
                    let Ok(inner) = inner_entry.entry() else { continue };
                    if let Some(data) = inner.data() {
                        if let Ok(bytes) = data.bytes() {
                            return Some(bytes);
                        }
                    }
                }
            }
        }
    }
    None
}

fn resource_names(root: &Directory<'_>, type_name: Name<'_>) -> Vec<String> {
    root.get_dir(type_name)
        .map(|dir| {
            dir.entries()
                .filter_map(|entry| entry.name().ok().map(|name| name.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn resource_tree_summary(root: &Directory<'_>) -> Vec<String> {
    let mut summary = Vec::new();
    for type_entry in root.entries() {
        let Ok(type_name) = type_entry.name() else { continue };
        let children = type_entry
            .entry()
            .ok()
            .and_then(|entry| entry.dir())
            .map(|dir| {
                dir.entries()
                    .filter_map(|entry| entry.name().ok().map(|name| name.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        summary.push(format!("{} => {:?}", type_name, children));
    }
    summary
}

fn iter_auto_salt_candidates(pe: &PeFile, data: &[u8]) -> Vec<usize> {
    let mut candidates = Vec::new();
    let salt_size = EXE_RESOURCE_SALT_SIZE;

    // 1. Packed neighborhood
    // a) V2Link
    for pos in memmem::find_iter(data, b"V2Link\0\0") {
        if pos >= salt_size {
            candidates.push(pos - salt_size);
        }
    }

    // b) forcedataxp3
    for pos in memmem::find_iter(data, b"forcedataxp3\0") {
        let window_start = (pos + b"forcedataxp3\0".len() + 0xF) & !0xF;
        let window_end = std::cmp::min(pos + 0x100, data.len().saturating_sub(salt_size));
        for offset in (window_start..=window_end).step_by(0x10) {
            candidates.push(offset);
        }
    }

    // 2. Code assignment (mov dword ptr [ptr], offset; mov dword ptr [size], 0x2000)
    let image_base = match pe {
        pelite::Wrap::T32(pe32) => pe32.optional_header().ImageBase as u64,
        pelite::Wrap::T64(pe64) => pe64.optional_header().ImageBase,
    };

    for pos in memmem::find_iter(data, b"\xC7\x05") {
        if pos + 10 > data.len() { continue; }
        let salt_va = u32::from_le_bytes([data[pos+6], data[pos+7], data[pos+8], data[pos+9]]) as u64;
        
        if salt_va < image_base { continue; }
        let salt_rva = (salt_va - image_base) as u32;
        
        let salt_offset_res = match pe {
            pelite::Wrap::T32(pe32) => pe32.rva_to_file_offset(salt_rva),
            pelite::Wrap::T64(pe64) => pe64.rva_to_file_offset(salt_rva),
        };
        let salt_offset = match salt_offset_res {
            Ok(o) => o,
            Err(_) => continue,
        };
        
        if salt_offset + salt_size > data.len() { continue; }

        let window_end = std::cmp::min(data.len().saturating_sub(10), pos + 64);
        for size_off in pos+10..window_end {
            if data[size_off] == 0xC7 && data[size_off+1] == 0x05 {
                let size_val = u32::from_le_bytes([data[size_off+6], data[size_off+7], data[size_off+8], data[size_off+9]]);
                if size_val == salt_size as u32 {
                    candidates.push(salt_offset);
                    break;
                }
            }
        }
    }

    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

pub fn extract_bootstrap_unique(exe_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file_data = std::fs::read(exe_path)?;
    
    // Attempt SteamStub decryption in-memory
    let steam_status = crate::cxdec_tools::crypto::steamstub::decrypt_steamstub_in_memory(&mut file_data)?;
    tracing::info!("SteamStub status: {:?}", steam_status);

    let pe = PeFile::from_bytes(&file_data)?;
    tracing::info!(
        "Parsed PE architecture: {}",
        match pe { Wrap::T32(_) => "PE32", Wrap::T64(_) => "PE32+" }
    );
    let data = &file_data;

    let resources = pe.resources()?;

    let root = resources.root()?;

    // 1. Get startup_key from TEXT 127 via manual directory traversal
    //    (find_resource doesn't reliably resolve string type names like "TEXT" through Wrap)
    let startup_key = {
        // 尝试多种 type name 查找方式，因为不同游戏 PE 的资源结构可能不同
        let text_bytes = get_resource_bytes(&root, Name::Str("TEXT"), Name::Id(127))
            .or_else(|| get_resource_bytes(&root, Name::Id(10), Name::Id(127)));
        
        let text_bytes = match text_bytes {
            Some(b) => b,
            None => {
                let types = resource_tree_summary(&root);
                return Err(format!(
                    "Could not find TEXT/127 resource to extract startup key.\n\
                     可用的资源树: {:?}\n\
                     请确认该 EXE 是 Kirikiri/Krkrz HXV4 引擎的游戏主程序。", types
                ).into());
            }
        };
        if text_bytes.is_empty() || text_bytes.len() % 2 != 0 {
            return Err(format!("TEXT/127 resource is not valid UTF-16LE data ({} bytes)", text_bytes.len()).into());
        }
        let u16s: Vec<u16> = text_bytes.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let root_url = String::from_utf16_lossy(&u16s);
        let root_url = root_url.trim_start_matches('\u{feff}').trim_matches('\0').trim();
        let key = root_url.replace("bres://./", "").trim_matches('/').to_string();
        if key.is_empty() {
            return Err("TEXT/127 resource produced an empty startup key".into());
        }
        key
    };

    tracing::info!("Extracted startup_key: {}", startup_key);

    let rcdata_names = resource_names(&root, Name::Id(10));
    let startup_res = get_resource_bytes(&root, Name::Id(10), Name::Str("STARTUP.TJS"))
        .ok_or_else(|| format!("Could not find STARTUP.TJS in RCDATA resources. Available names: {:?}", rcdata_names))?;

    let candidates = iter_auto_salt_candidates(&pe, data);
    tracing::info!("Found {} automatic salt candidates", candidates.len());
    let mut found_salt: Option<&[u8]> = None;
    let mut startup_plain = Vec::new();

    for &offset in &candidates {
        if offset + EXE_RESOURCE_SALT_SIZE > data.len() { continue; }
        let salt = &data[offset..offset + EXE_RESOURCE_SALT_SIZE];
        let plain = decrypt_resource(startup_res, &startup_key, salt);
        if plain.starts_with(b"TJS2100\0") {
            found_salt = Some(salt);
            startup_plain = plain;
            break;
        }
    }
    tracing::info!("STARTUP.TJS validation succeeded");

    let salt = found_salt.ok_or(
        "Could not find correct salt; decrypted STARTUP.TJS is not TJS2100 bytecode.\n\
         【提示】如果您的游戏是通过 Steam 下载的，该 EXE 可能被 SteamStub 加壳加密了（导致特征码被隐藏）。请尝试使用 Steamless 脱壳后重新选择 unpacked.exe！"
    )?;

    // Parse TJS strings to find bootstrap url
    let bootstrap_url = find_bootstrap_url(&startup_plain).ok_or("could not find bootstrap bres URL in STARTUP.TJS")?;
    let bootstrap_key = bres_key_from_url(&bootstrap_url).ok_or("invalid bres URL")?;

    // Extract BOOTSTRAP
    let bootstrap_res = get_resource_bytes(&root, Name::Id(10), Name::Str("BOOTSTRAP"))
        .ok_or_else(|| format!("Could not find BOOTSTRAP in RCDATA resources. Available names: {:?}", rcdata_names))?;
    let bootstrap_plain = decrypt_resource(bootstrap_res, &bootstrap_key, salt);

    // Decompress BOOTSTRAP (skip 8 bytes offset)
    if bootstrap_plain.len() <= 8 {
        return Err("BOOTSTRAP payload too small".into());
    }
    
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    
    let compressed_data = &bootstrap_plain[8..];
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut dll_bytes = Vec::new();
    decoder.read_to_end(&mut dll_bytes)?;
    tracing::info!("Decompressed BOOTSTRAP payload: {} bytes", dll_bytes.len());

    if !dll_bytes.starts_with(b"MZ") {
        return Err("decompressed BOOTSTRAP is not a PE DLL".into());
    }

    // Find UNIQUE config label
    let unique_marker = b"UNIQUE\0";
    let pos = dll_bytes.windows(unique_marker.len())
        .position(|w| w == unique_marker)
        .ok_or("UNIQUE label not found in BOOTSTRAP DLL")?;
    
    let cursor = pos + unique_marker.len();
    if cursor + 2 > dll_bytes.len() {
        return Err("EOF reading UNIQUE length".into());
    }
    
    let length = u16::from_le_bytes([dll_bytes[cursor], dll_bytes[cursor+1]]) as usize;
    let cursor = cursor + 2;
    if cursor + length > dll_bytes.len() {
        return Err("EOF reading UNIQUE data".into());
    }
    
    let utf16_data = &dll_bytes[cursor..cursor+length];
    if utf16_data.len() % 2 != 0 {
        return Err("UNIQUE data length not even".into());
    }
    
    let utf16_chars: Vec<u16> = utf16_data.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
        
    let unique_str = String::from_utf16(&utf16_chars)?;
    tracing::info!("Extracted UNIQUE value: {}", unique_str);
    Ok(unique_str)
}

fn find_bootstrap_url(data: &[u8]) -> Option<String> {
    // Instead of full TJS parsing, let's just search for the UTF-16LE sequence of "bres://./"
    let prefix = [0x62, 0x00, 0x72, 0x00, 0x65, 0x00, 0x73, 0x00, 0x3a, 0x00, 0x2f, 0x00, 0x2f, 0x00, 0x2e, 0x00, 0x2f, 0x00];
    
    let mut pos = 0;
    while pos < data.len() - prefix.len() {
        if data[pos..pos+prefix.len()] == prefix {
            // Find the end of the utf-16 string (0x00 0x00)
            let mut end = pos;
            while end < data.len() - 1 {
                if data[end] == 0 && data[end+1] == 0 {
                    break;
                }
                end += 2;
            }
            let utf16_data = &data[pos..end];
            let utf16_chars: Vec<u16> = utf16_data.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            if let Ok(s) = String::from_utf16(&utf16_chars) {
                if s.to_lowercase().ends_with("/bootstrap") {
                    return Some(s);
                }
            }
        }
        pos += 1;
    }
    None
}

fn bres_key_from_url(url: &str) -> Option<String> {
    let marker = "bres://./";
    if !url.starts_with(marker) {
        return None;
    }
    let rest = &url[marker.len()..];
    let parts: Vec<&str> = rest.split('/').collect();
    if !parts.is_empty() {
        Some(parts[0].to_string())
    } else {
        None
    }
}
