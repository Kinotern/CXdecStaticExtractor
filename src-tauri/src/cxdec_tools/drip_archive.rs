use crate::crypto::{find_hxv4_descriptor, parse_hxv4_table_payload, Hxv4Record};
use crate::extractor::FilterRuntimeState;
use crate::vm::DripProgram;
use crate::xp3::{Xp3Entry, Xp3Parser};
use flate2::read::ZlibDecoder;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub struct DripArchive {
    pub path: PathBuf,
    pub entries: Vec<Xp3Entry>,
    pub records: HashMap<usize, Hxv4Record>,
    states: HashMap<usize, FilterRuntimeState>,
}

impl DripArchive {
    pub fn open(path: &Path, drip: &DripProgram) -> Result<Self, String> {
        let (_, entries, index) = Xp3Parser::read_archive(path)
            .map_err(|error| format!("XP3 index error: {error:?}"))?;
        let desc = find_hxv4_descriptor(&index)
            .ok_or_else(|| format!("HXV4 descriptor not found: {}", path.display()))?;
        let mut file = File::open(path).map_err(|error| error.to_string())?;
        file.seek(SeekFrom::Start(desc.offset)).map_err(|error| error.to_string())?;
        let mut payload = vec![0u8; desc.size as usize];
        file.read_exact(&mut payload).map_err(|error| error.to_string())?;
        let parsed = parse_hxv4_table_payload(
            &payload,
            desc.flags,
            &entries,
            &drip.hxv4_key,
            &drip.hxv4_nonce0,
            &drip.hxv4_nonce1,
        )?;
        let open_flag = (desc.flags & 1) as u32;
        let mut records = HashMap::new();
        let mut states = HashMap::new();
        for record in parsed {
            if let Some(index) = record.xp3_entry_index {
                if let Ok(seed) = drip.build_filter_state(record.key, open_flag) {
                    if let Ok(state) = FilterRuntimeState::new(&seed) {
                        states.insert(index, state);
                    }
                }
                records.insert(index, record);
            }
        }
        Ok(Self { path: path.to_path_buf(), entries, records, states })
    }

    pub fn read_entry(&self, index: usize) -> Result<Vec<u8>, String> {
        self.read_entry_limit(index, usize::MAX)
    }

    pub fn read_entry_prefix(&self, index: usize, max_len: usize) -> Result<Vec<u8>, String> {
        self.read_entry_limit(index, max_len)
    }

    fn read_entry_limit(&self, index: usize, max_len: usize) -> Result<Vec<u8>, String> {
        let entry = self.entries.get(index).ok_or("XP3 entry index out of range")?;
        let mut file = File::open(&self.path).map_err(|error| error.to_string())?;
        let mut output = Vec::with_capacity((entry.original_size as usize).min(max_len));
        let mut logical_offset = 0u64;
        for segment in &entry.segments {
            if output.len() >= max_len { break; }
            file.seek(SeekFrom::Start(segment.offset)).map_err(|error| error.to_string())?;
            let mut data = vec![0u8; segment.archived_size as usize];
            file.read_exact(&mut data).map_err(|error| error.to_string())?;
            if segment.is_compressed() {
                let mut plain = Vec::with_capacity(segment.original_size as usize);
                ZlibDecoder::new(&data[..]).read_to_end(&mut plain).map_err(|error| error.to_string())?;
                data = plain;
            }
            if let Some(state) = self.states.get(&index) {
                state.apply(&mut data, logical_offset);
            }
            logical_offset += data.len() as u64;
            let remaining = max_len.saturating_sub(output.len());
            output.extend_from_slice(&data[..data.len().min(remaining)]);
        }
        Ok(output)
    }
}
