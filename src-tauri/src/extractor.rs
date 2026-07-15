use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use flate2::read::ZlibDecoder;
use std::io::Read;

use crate::xp3::Xp3Parser;
use crate::vm::DripProgram;
use crate::crypto::{find_hxv4_descriptor, parse_hxv4_table_payload, Hxv4Record};

#[derive(Debug, Clone)]
struct FilterBoundary {
    pos0: u32,
    pos1: u32,
    key: u32,
    byte0: u8,
    byte1: u8,
}

#[derive(Debug, Clone)]
pub struct FilterRuntimeState {
    boundary0: FilterBoundary,
    boundary1: FilterBoundary,
    split_offset: u64,
    bulk_key: Vec<u8>,
}

impl FilterRuntimeState {
    pub fn new(seed: &[u8]) -> Result<Self, String> {
        if seed.len() != 48 {
            return Err("Seed state must be 48 bytes".to_string());
        }
        let null_mode = seed[45] != 0;
        
        let v0 = u64::from_le_bytes(seed[0..8].try_into().unwrap());
        let v1 = u64::from_le_bytes(seed[8..16].try_into().unwrap());
        
        let boundary0 = Self::init_boundary(v0, null_mode);
        let boundary1 = Self::init_boundary(v1, null_mode);
        
        let split_offset = u64::from_le_bytes(seed[16..24].try_into().unwrap());
        
        let has_bulk = seed[44] != 0;
        let bulk_key = if has_bulk {
            seed[24..40].to_vec()
        } else {
            Vec::new()
        };

        Ok(FilterRuntimeState {
            boundary0,
            boundary1,
            split_offset,
            bulk_key,
        })
    }

    fn init_boundary(value: u64, null_mode: bool) -> FilterBoundary {
        let pos0 = ((value >> 48) & 0xFFFF) as u32;
        let mut pos1 = ((value >> 32) & 0xFFFF) as u32;
        if pos0 == pos1 {
            pos1 = pos1.wrapping_add(1);
        }

        let mut key_byte = (value & 0xFF) as u32;
        let mut byte0 = ((value >> 8) & 0xFF) as u8;
        let mut byte1 = ((value >> 16) & 0xFF) as u8;

        if key_byte == 0 {
            key_byte = if null_mode { 0 } else { 0xA5 };
        }
        let key = key_byte.wrapping_mul(0x01010101);

        if null_mode {
            byte0 = 0;
            byte1 = 0;
        }

        FilterBoundary { pos0, pos1, key, byte0, byte1 }
    }

    fn apply_boundary(b: &FilterBoundary, data: &mut [u8], chunk_start: u64, buffer_start: usize, size: usize) {
        if size == 0 { return; }

        for i in 0..size {
            let shift = ((chunk_start + i as u64) & 3) * 8;
            data[buffer_start + i] ^= (b.key >> shift) as u8;
        }

        if b.byte0 != 0 && (b.pos0 as u64) >= chunk_start && (b.pos0 as u64) < chunk_start + size as u64 {
            let idx = buffer_start + (b.pos0 as u64 - chunk_start) as usize;
            data[idx] ^= b.byte0;
        }
        if b.byte1 != 0 && (b.pos1 as u64) >= chunk_start && (b.pos1 as u64) < chunk_start + size as u64 {
            let idx = buffer_start + (b.pos1 as u64 - chunk_start) as usize;
            data[idx] ^= b.byte1;
        }
    }

    pub fn apply(&self, data: &mut [u8], offset: u64) {
        if data.is_empty() { return; }
        
        let size = data.len();
        let end = offset + size as u64;

        if !self.bulk_key.is_empty() && offset < self.bulk_key.len() as u64 {
            let overlap_start = offset;
            let overlap_end = std::cmp::min(end, self.bulk_key.len() as u64);
            for logical in overlap_start..overlap_end {
                data[(logical - offset) as usize] ^= self.bulk_key[logical as usize];
            }
        }

        let split = self.split_offset;
        if split <= offset {
            Self::apply_boundary(&self.boundary1, data, offset, 0, size);
        } else if split < end {
            let first_size = (split - offset) as usize;
            Self::apply_boundary(&self.boundary0, data, offset, 0, first_size);
            Self::apply_boundary(&self.boundary1, data, split, first_size, size - first_size);
        } else {
            Self::apply_boundary(&self.boundary0, data, offset, 0, size);
        }
    }
}

pub struct ExtractOptions {
    pub xp3_path: PathBuf,
    pub drip_program_path: PathBuf,
    pub out_dir: PathBuf,
    pub lst_path: Option<PathBuf>,
}

pub fn extract_all<F>(options: ExtractOptions, progress_callback: F) -> Result<String, String>
where
    F: Fn(usize, usize) + Send + Sync + 'static,
{
    std::fs::create_dir_all(&options.out_dir).map_err(|e| e.to_string())?;

    let drip = DripProgram::load(&options.drip_program_path)?;
    let (_info, entries, index_blob) = Xp3Parser::read_archive(&options.xp3_path).map_err(|e| format!("{:?}", e))?;
    let desc = find_hxv4_descriptor(&index_blob);
    let records = if let Some(desc) = desc.as_ref() {
        use std::io::{Seek, SeekFrom};
        let mut file = File::open(&options.xp3_path).map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start(desc.offset)).map_err(|e| e.to_string())?;
        let mut payload = vec![0u8; desc.size as usize];
        file.read_exact(&mut payload).map_err(|e| e.to_string())?;
        match parse_hxv4_table_payload(&payload, desc.flags, &entries, &drip.hxv4_key, &drip.hxv4_nonce0, &drip.hxv4_nonce1) {
            Ok(records) => records,
            Err(e) => return Err(format!("HXV4 Parse Error: {:?}, IndexBlob Size: {}", e, index_blob.len())),
        }
    } else {
        Vec::new()
    };
    
    let mut filter_states: HashMap<usize, FilterRuntimeState> = HashMap::new();
    let mut hxv4_records: HashMap<usize, Hxv4Record> = HashMap::new();

    if let Some(desc) = desc {
        let open_flag = (desc.flags & 1) as u32;
        for rec in records {
            if let Some(idx) = rec.xp3_entry_index {
                hxv4_records.insert(idx, rec.clone());
                if let Ok(seed) = drip.build_filter_state(rec.key, open_flag) {
                    if let Ok(state) = FilterRuntimeState::new(&seed) {
                        filter_states.insert(idx, state);
                    }
                }
            }
        }
    }

    let total = entries.len();
    let written = Arc::new(Mutex::new(0));

    let mut lst_map: HashMap<String, String> = HashMap::new();
    if let Some(lst_p) = &options.lst_path {
        if let Ok(content) = std::fs::read_to_string(lst_p) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() { continue; }
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim().to_lowercase();
                    let val = parts[1].trim().to_string();
                    if !key.is_empty() && !val.is_empty() {
                        lst_map.insert(key, val);
                    }
                }
            }
        }
    }

    let xp3_stem = options.xp3_path.file_stem().unwrap_or_default().to_string_lossy();
    let manifest_name = format!("{}_manifest.jsonl", xp3_stem);
    let manifest_path = if let Some(parent) = options.out_dir.parent() {
        parent.join(&manifest_name)
    } else {
        options.out_dir.join(&manifest_name)
    };
    let mut manifest_out = File::create(&manifest_path).unwrap();
    
    let mut mapped_paths: Vec<PathBuf> = Vec::with_capacity(entries.len());

    for (idx, entry) in entries.iter().enumerate() {

        
        let (domain_hash, file_hash) = if let Some(rec) = hxv4_records.get(&idx) {
            (rec.domain_hash.clone(), rec.file_hash.clone())
        } else {
            (entry.name.clone(), entry.name.clone())
        };

        let file_hash_lower = file_hash.to_lowercase();
        let domain_hash_lower = domain_hash.to_lowercase();
        
        let leaf_name = lst_map.get(&file_hash_lower).cloned().unwrap_or_else(|| file_hash.clone());
        let mut dir_name = lst_map.get(&domain_hash_lower).cloned().unwrap_or_default();
        if dir_name == "/" { dir_name = String::new(); }
        
        if !dir_name.is_empty() {
            let mapped_leaf = PathBuf::from(&dir_name).file_name().unwrap_or_default().to_string_lossy().to_string();
            let output_leaf = options.out_dir.file_name().unwrap_or_default().to_string_lossy().to_string();
            if mapped_leaf.eq_ignore_ascii_case(&output_leaf) {
                dir_name = String::new();
            }
        }
        
        let rel_path = if dir_name.is_empty() {
            leaf_name.clone()
        } else {
            format!("{}/{}", dir_name, leaf_name)
        };
        
        let rel_path = rel_path.replace("\\", "/");
        let mut clean_rel = PathBuf::new();
        for p in rel_path.split('/') {
            if p != "." && p != ".." && !p.is_empty() {
                clean_rel.push(p);
            }
        }
        if clean_rel.as_os_str().is_empty() {
            clean_rel = PathBuf::from(format!("{}.bin", idx));
        }

        mapped_paths.push(clean_rel.clone());
        let output_name = clean_rel.to_string_lossy().replace("\\", "/");

        let manifest_line = format!(
            "{{\"filename_hash\": \"{}\", \"pathname_hash\": \"{}\", \"offset\": {}, \"size\": {}, \"output\": \"{}\"}}\n",
            file_hash, domain_hash, entry.original_size, entry.original_size, output_name
        );
        manifest_out.write_all(manifest_line.as_bytes()).unwrap();
    }
    
    use rayon::prelude::*;
    // Process files in parallel
    let result: Result<(), String> = entries.into_par_iter().enumerate().try_for_each(|(idx, entry)| {
        use std::io::{Seek, SeekFrom};
        let mut archive = File::open(&options.xp3_path).map_err(|e| e.to_string())?;
        let mut file_data = Vec::with_capacity(entry.original_size as usize);
        let mut logical_off = 0;

        for seg in &entry.segments {
            archive.seek(SeekFrom::Start(seg.offset)).map_err(|e| e.to_string())?;
            let mut chunk = vec![0u8; seg.archived_size as usize];
            archive.read_exact(&mut chunk).map_err(|e| e.to_string())?;
            
            if seg.is_compressed() {
                let mut uncompressed = Vec::with_capacity(seg.original_size as usize);
                let mut decoder = ZlibDecoder::new(&chunk[..]);
                decoder.read_to_end(&mut uncompressed).map_err(|e| e.to_string())?;
                chunk = uncompressed;
            }

            if let Some(state) = filter_states.get(&idx) {
                state.apply(&mut chunk, logical_off);
            }

            file_data.extend_from_slice(&chunk);
            logical_off += chunk.len() as u64;
        }

        let out_path = options.out_dir.join(&mapped_paths[idx]);
        if let Some(parent) = out_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut outf = File::create(out_path).map_err(|e| e.to_string())?;
        outf.write_all(&file_data).map_err(|e| e.to_string())?;

        let mut w = written.lock().unwrap();
        *w += 1;
        if *w % 10 == 0 || *w == total {
            progress_callback(*w, total);
        }

        Ok(())
    });

    result?;

    Ok(format!("Processed {} files.", total))
}
