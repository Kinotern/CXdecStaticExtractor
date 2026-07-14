use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use serde_json::Value;

pub const DRIP_OP_ADD_IMM: u32 = 0x17C50;
pub const DRIP_OP_RECURSE: u32 = 0x17C60;
pub const DRIP_OP_ADD_SCRATCH: u32 = 0x17CB0;
pub const DRIP_OP_MUL_SCRATCH: u32 = 0x17CD0;
pub const DRIP_OP_SCRATCH_MINUS_RESULT: u32 = 0x17CF0;
pub const DRIP_OP_SHL_SCRATCH: u32 = 0x17D10;
pub const DRIP_OP_SHR_SCRATCH: u32 = 0x17D30;
pub const DRIP_OP_SUB_SCRATCH: u32 = 0x17D50;
pub const DRIP_OP_BIT_SHUFFLE: u32 = 0x17D70;
pub const DRIP_OP_SET_IMM: u32 = 0x17DA0;
pub const DRIP_OP_SET_SEED: u32 = 0x17DB0;
pub const DRIP_OP_DEC: u32 = 0x17DD0;
pub const DRIP_OP_INC: u32 = 0x17DE0;
pub const DRIP_OP_NEG: u32 = 0x17DF0;
pub const DRIP_OP_NOT: u32 = 0x17E00;
pub const DRIP_OP_TABLE_IMM: u32 = 0x17E10;
pub const DRIP_OP_TABLE_MASKED: u32 = 0x17E30;
pub const DRIP_OP_SUB_IMM: u32 = 0x17E50;
pub const DRIP_OP_STORE_SCRATCH: u32 = 0x17E60;
pub const DRIP_OP_XOR_IMM: u32 = 0x17E80;
pub const DRIP_OP_STOP: u32 = 0x51D90;

#[derive(Debug, Clone, Copy)]
pub struct DripRecord {
    pub param: u32,
    pub op: u32,
}

#[derive(Debug, Clone)]
pub struct DripProgram {
    pub holder_words: Vec<u32>,
    pub context_u32: Vec<u32>,
    pub lanes: Vec<Vec<DripRecord>>,
    pub hxv4_key: Vec<u8>,
    pub hxv4_nonce0: Vec<u8>,
    pub hxv4_nonce1: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DripEvalState {
    seed: u32,
    scratch: u32,
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn safe_u32(val: &Value) -> u32 {
    if let Some(n) = val.as_u64() {
        n as u32
    } else if let Some(n) = val.as_i64() {
        n as u32
    } else if let Some(n) = val.as_f64() {
        n as u32
    } else {
        0
    }
}

impl DripProgram {
    pub fn load<P: AsRef<Path>>(json_path: P) -> Result<Self, String> {
        let json_str = std::fs::read_to_string(&json_path).map_err(|e| e.to_string())?;
        let payload: Value = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;

        let mut prog = DripProgram {
            holder_words: Vec::new(),
            context_u32: Vec::new(),
            lanes: Vec::new(),
            hxv4_key: Vec::new(),
            hxv4_nonce0: Vec::new(),
            hxv4_nonce1: Vec::new(),
        };

        let mut lanes_from_bin = false;

        if payload.get("holder_words").is_some() && payload.get("context_u32").is_some() {
            if let Some(hw) = payload["holder_words"].as_array() {
                prog.holder_words = hw.iter().map(safe_u32).collect();
            }
            if let Some(cu) = payload["context_u32"].as_array() {
                prog.context_u32 = cu.iter().map(safe_u32).collect();
            }
        } else {
            let bin_path = json_path.as_ref().with_extension("bin");
            let mut bf = File::open(&bin_path).map_err(|_| "Cannot open drip program BIN file and JSON lacks context data".to_string())?;
            
            let mut header = [0u8; 16];
            let read_bytes = bf.read(&mut header).unwrap_or(0);
            if read_bytes < 12 {
                return Err("Invalid BIN header".into());
            }

            let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
            if magic != 0x50495244 { // 'DRIP'
                return Err("Invalid BIN magic (expected 'DRIP')".into());
            }

            let hlen = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
            let clen = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
            
            let mut lane_count = 0;
            let mut new_format = false;
            
            if read_bytes >= 16 {
                lane_count = u32::from_le_bytes(header[12..16].try_into().unwrap());
                new_format = lane_count > 0 && lane_count <= 256;
            }

            if !new_format {
                bf.seek(SeekFrom::Start(12)).map_err(|e| e.to_string())?;
            }

            if hlen > 0 {
                let mut hw_bytes = vec![0u8; hlen * 4];
                bf.read_exact(&mut hw_bytes).map_err(|_| "Failed to read holder_words".to_string())?;
                prog.holder_words = hw_bytes.chunks_exact(4)
                    .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();
            }

            if clen > 0 {
                let mut cu_bytes = vec![0u8; clen * 4];
                bf.read_exact(&mut cu_bytes).map_err(|_| "Failed to read context_u32".to_string())?;
                prog.context_u32 = cu_bytes.chunks_exact(4)
                    .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();
            }

            if new_format && lane_count > 0 {
                for _ in 0..lane_count {
                    let mut rcount_bytes = [0u8; 4];
                    bf.read_exact(&mut rcount_bytes).map_err(|_| "Failed to read lane record count")?;
                    let rcount = u32::from_le_bytes(rcount_bytes) as usize;
                    
                    let mut records = Vec::with_capacity(rcount);
                    if rcount > 0 {
                        let mut rec_bytes = vec![0u8; rcount * 8];
                        bf.read_exact(&mut rec_bytes).map_err(|_| "Failed to read lane records")?;
                        for chunk in rec_bytes.chunks_exact(8) {
                            records.push(DripRecord {
                                param: u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
                                op: u32::from_le_bytes(chunk[4..8].try_into().unwrap()),
                            });
                        }
                    }
                    prog.lanes.push(records);
                }
                lanes_from_bin = true;
            }
        }

        if !lanes_from_bin {
            if let Some(lanes) = payload["lanes"].as_array() {
                for lane in lanes {
                    let mut records = Vec::new();
                    if let Some(recs) = lane["records"].as_array() {
                        for r in recs {
                            if let Some(arr) = r.as_array() {
                                if arr.len() == 2 {
                                    records.push(DripRecord {
                                        param: safe_u32(&arr[0]),
                                        op: safe_u32(&arr[1]),
                                    });
                                }
                            }
                        }
                    }
                    prog.lanes.push(records);
                }
            }
        }

        if prog.lanes.len() != 128 {
            return Err("Drip program must contain 128 lanes".into());
        }
        if prog.holder_words.len() < 6 {
            return Err("Drip program holder_words is truncated".into());
        }

        if let Some(k) = payload["hxv4_key"].as_str() {
            prog.hxv4_key = hex_to_bytes(k);
        }
        if let Some(n0) = payload["hxv4_nonce0"].as_str() {
            prog.hxv4_nonce0 = hex_to_bytes(n0);
        }
        if let Some(n1) = payload["hxv4_nonce1"].as_str() {
            prog.hxv4_nonce1 = hex_to_bytes(n1);
        }

        Ok(prog)
    }

    fn context_value(&self, index: u32) -> Result<u32, String> {
        self.context_u32.get(index as usize).copied().ok_or_else(|| "Drip context index out of range".to_string())
    }

    fn eval_records(
        &self,
        records: &[DripRecord],
        pc: &mut usize,
        result: &mut u32,
        state: &mut DripEvalState,
    ) -> Result<(), String> {
        let mut scratch = state.scratch;
        let seed = state.seed;

        while *pc < records.len() {
            let param = records[*pc].param;
            let op = records[*pc].op;
            *pc += 1;

            if op == DRIP_OP_STOP {
                break;
            }
            if op == DRIP_OP_RECURSE {
                let mut nested_state = DripEvalState { seed, scratch };
                self.eval_records(records, pc, result, &mut nested_state)?;
                continue;
            }

            match op {
                DRIP_OP_ADD_IMM => *result = result.wrapping_add(param),
                DRIP_OP_ADD_SCRATCH => *result = result.wrapping_add(scratch),
                DRIP_OP_MUL_SCRATCH => *result = result.wrapping_mul(scratch),
                DRIP_OP_SCRATCH_MINUS_RESULT => *result = scratch.wrapping_sub(*result),
                DRIP_OP_SHL_SCRATCH => *result <<= scratch & 0xF,
                DRIP_OP_SHR_SCRATCH => *result >>= scratch & 0xF,
                DRIP_OP_SUB_SCRATCH => *result = result.wrapping_sub(scratch),
                DRIP_OP_BIT_SHUFFLE => {
                    *result = (2 * (*result & !param)) | ((param >> 1) & (*result >> 1));
                }
                DRIP_OP_SET_IMM => *result = param,
                DRIP_OP_SET_SEED => *result = seed,
                DRIP_OP_DEC => *result = result.wrapping_sub(1),
                DRIP_OP_INC => *result = result.wrapping_add(1),
                DRIP_OP_NEG => *result = result.wrapping_neg(),
                DRIP_OP_NOT => *result = !*result,
                DRIP_OP_TABLE_IMM => *result = self.context_value(param)?,
                DRIP_OP_TABLE_MASKED => *result = self.context_value(param & *result)?,
                DRIP_OP_SUB_IMM => *result = result.wrapping_sub(param),
                DRIP_OP_STORE_SCRATCH => scratch = *result,
                DRIP_OP_XOR_IMM => *result ^= param,
                _ => return Err(format!("Unknown Drip op: {:#x}", op)),
            }
        }
        state.scratch = scratch;
        Ok(())
    }

    fn eval_lane(&self, lane_index: u32, seed: u32) -> Result<u32, String> {
        let lane = self.lanes.get(lane_index as usize).ok_or_else(|| "Drip lane out of range".to_string())?;
        let mut pc = 0;
        let mut result = 0;
        let mut state = DripEvalState { seed, scratch: 0 };
        self.eval_records(lane, &mut pc, &mut result, &mut state)?;
        Ok(result)
    }

    fn get_64_from_u32(&self, value: u32) -> Result<u64, String> {
        let lane_index = value & 0x7F;
        let seed = value >> 7;
        let lo = self.eval_lane(lane_index, seed)?;
        let hi = self.eval_lane(lane_index, !seed)?;
        Ok((lo as u64) | ((hi as u64) << 32))
    }

    pub fn build_filter_state(&self, key: u64, open_flag: u32) -> Result<Vec<u8>, String> {
        let mut key_lo = (key & 0xFFFFFFFF) as u32;
        let mut key_hi = (key >> 32) as u32;

        if (open_flag & 1) == 0 {
            key_lo ^= self.holder_words[2];
            key_hi ^= self.holder_words[3];
        }

        let key64 = (key_lo as u64) | ((key_hi as u64) << 32);

        let mut state = vec![0u8; 48];
        let val0 = self.get_64_from_u32(key_lo)?;
        let val1 = self.get_64_from_u32(key_hi)?;

        state[0..8].copy_from_slice(&val0.to_le_bytes());
        state[8..16].copy_from_slice(&val1.to_le_bytes());

        let bulk_offset = self.holder_words[5].wrapping_add(self.holder_words[4] & ((key64 >> 16) as u32));
        state[16..20].copy_from_slice(&bulk_offset.to_le_bytes());
        state[20..24].copy_from_slice(&0u32.to_le_bytes());

        let mut cur = !key64;
        let mut bitpos: i32 = -1;
        let mut out = 24;

        while out < 40 {
            if bitpos < 0 {
                cur = !self.get_64_from_u32((cur & 0xFFFFFFFF) as u32)?;
                bitpos = 64;
            } else {
                state[out] = ((cur >> bitpos) & 0xFF) as u8;
                out += 1;
            }
            bitpos -= 8;
        }

        state[44] = 1; // has_bulk
        state[45] = 0; // null_mode

        Ok(state)
    }
}
