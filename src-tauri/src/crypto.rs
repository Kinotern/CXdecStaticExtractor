use std::collections::HashMap;
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce, aead::{Aead, KeyInit}};
use flate2::read::ZlibDecoder;
use std::io::Read;
use crate::xp3::Xp3Entry;

const HXV4_KEY: &[u8] = &[
    0xe4, 0xdc, 0x1d, 0x99, 0xd9, 0xd9, 0xfb, 0x1a, 
    0xe5, 0xf7, 0x52, 0x9e, 0xe7, 0x0f, 0x84, 0x1b, 
    0xfa, 0xdb, 0x13, 0xd1, 0x2f, 0x4d, 0x22, 0xb9, 
    0x91, 0x70, 0xd6, 0xcc, 0x6a, 0x62, 0xbc, 0x54 
];

const HXV4_NONCES: [&[u8]; 2] = [
    &[0xd9, 0x92, 0x30, 0xe0, 0x26, 0x23, 0xf4, 0xa0, 0xc4, 0xf2, 0x85, 0x76, 0x82, 0xb4, 0xde, 0x6d, 0xfe, 0xfe, 0x82, 0x0b, 0x57, 0x06, 0x0e, 0x50],
    &[0xb9, 0x6f, 0x89, 0x63, 0x08, 0x50, 0xdd, 0x23, 0xa1, 0x38, 0x10, 0xc7, 0x71, 0x8a, 0xd0, 0x03, 0x93, 0x6d, 0x1d, 0x4a, 0x3a, 0xe0, 0x08, 0x90]
];

#[derive(Debug, Clone)]
pub struct Hxv4Descriptor {
    pub offset: u64,
    pub size: u32,
    pub flags: u16,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Hxv4Record {
    pub domain_hash: String,
    pub file_hash: String,
    pub archive_slot: u32,
    pub filter_flag: u32,
    pub key: u64,
    pub xp3_entry_index: Option<usize>,
}

pub fn find_hxv4_descriptor(index: &[u8]) -> Option<Hxv4Descriptor> {
    let mut cursor = 0;
    while cursor + 12 <= index.len() {
        let tag = &index[cursor..cursor + 4];
        let chunk_size = u64::from_le_bytes(index[cursor + 4..cursor + 12].try_into().unwrap()) as usize;
        cursor += 12;

        if cursor + chunk_size > index.len() {
            break;
        }

        if tag == b"Hxv4" && chunk_size >= 14 {
            let chunk = &index[cursor..];
            let offset = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let size = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
            let flags = u16::from_le_bytes(chunk[12..14].try_into().unwrap());
            return Some(Hxv4Descriptor { offset, size, flags });
        }
        cursor += chunk_size;
    }
    None
}

pub fn decrypt_hxv4_payload(
    payload: &[u8],
    flags: u16,
    custom_key: &[u8],
    custom_nonce0: &[u8],
    custom_nonce1: &[u8]
) -> Result<Vec<u8>, String> {
    if payload.len() < 16 {
        return Err("Truncated Hxv4 encrypted payload".to_string());
    }

    let key_bytes = if custom_key.len() == 32 { custom_key } else { HXV4_KEY };
    let nonce_bytes = if (flags & 1) != 0 {
        if custom_nonce1.len() == 24 { custom_nonce1 } else { HXV4_NONCES[1] }
    } else {
        if custom_nonce0.len() == 24 { custom_nonce0 } else { HXV4_NONCES[0] }
    };

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = XNonce::from_slice(nonce_bytes);

    let decrypted = cipher.decrypt(nonce, payload)
        .map_err(|_| "Hxv4 Payload MAC verification failed!".to_string())?;

    Ok(decrypted)
}

// TJS Parsing
#[allow(dead_code)]
#[derive(Debug, Clone)]
enum TJSValue {
    Null,
    String(String),
    Octet(Vec<u8>),
    Int(i64),
    Real(f64),
    Array(Vec<TJSValue>),
    Dict(HashMap<String, TJSValue>),
}

struct TJSBinaryReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TJSBinaryReader<'a> {
    fn read_u8(&mut self) -> Result<u8, String> {
        if self.pos >= self.data.len() { return Err("EOF".into()); }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn read_i32(&mut self) -> Result<i32, String> {
        if self.pos + 4 > self.data.len() { return Err("EOF".into()); }
        let v = i32::from_le_bytes(self.data[self.pos..self.pos+4].try_into().unwrap());
        self.pos += 4;
        Ok(v.swap_bytes()) // Actually the C++ code reads as big endian! Wait...
        // let's check C++: (data[pos] << 24) | ... => yes, Big Endian!
    }
    fn read_i64(&mut self) -> Result<i64, String> {
        if self.pos + 8 > self.data.len() { return Err("EOF".into()); }
        let mut v: i64 = 0;
        for i in 0..8 {
            v = (v << 8) | (self.data[self.pos + i] as i64);
        }
        self.pos += 8;
        Ok(v)
    }
    fn read_f64(&mut self) -> Result<f64, String> {
        let bits = self.read_i64()?;
        Ok(f64::from_bits(bits as u64))
    }
    fn read_string(&mut self) -> Result<String, String> {
        let chars = self.read_i32()?;
        if chars < 0 || self.pos + (chars as usize) * 2 > self.data.len() {
            return Err("Invalid string len".into());
        }
        let mut out = String::new();
        for i in 0..(chars as usize) {
            let wc = ((self.data[self.pos + i*2] as u16) << 8) | (self.data[self.pos + i*2 + 1] as u16);
            if let Some(c) = std::char::from_u32(wc as u32) {
                out.push(c);
            }
        }
        self.pos += (chars as usize) * 2;
        Ok(out)
    }
    fn read_value(&mut self) -> Result<TJSValue, String> {
        let tag = self.read_u8()?;
        let signed_tag = if tag < 0x80 { tag as i8 } else { (tag as i16 - 0x100) as i8 };
        
        match signed_tag {
            0 | 1 => Ok(TJSValue::Null),
            2 => Ok(TJSValue::String(self.read_string()?)),
            3 => {
                let sz = self.read_i32()?;
                if sz < 0 || self.pos + (sz as usize) > self.data.len() {
                    return Err("Invalid octet len".into());
                }
                let slice = &self.data[self.pos..self.pos + (sz as usize)];
                self.pos += sz as usize;
                Ok(TJSValue::Octet(slice.to_vec()))
            },
            4 => Ok(TJSValue::Int(self.read_i64()?)),
            5 => Ok(TJSValue::Real(self.read_f64()?)),
            -127 => {
                let count = self.read_i32()?;
                if count < 0 { return Err("Invalid array len".into()); }
                let mut arr = Vec::new();
                for _ in 0..count {
                    arr.push(self.read_value()?);
                }
                Ok(TJSValue::Array(arr))
            },
            -63 => {
                let count = self.read_i32()?;
                if count < 0 { return Err("Invalid dict len".into()); }
                let mut dict = HashMap::new();
                for _ in 0..count {
                    let k = self.read_string()?;
                    let v = self.read_value()?;
                    dict.insert(k, v);
                }
                Ok(TJSValue::Dict(dict))
            },
            _ => Err("unsupported TJS binary tag".into()),
        }
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn parse_hxv4_table(
    blob: &[u8],
    index_blob: &[u8],
    entries: &[Xp3Entry],
    custom_key: &[u8],
    custom_nonce0: &[u8],
    custom_nonce1: &[u8]
) -> Result<Vec<Hxv4Record>, String> {
    let desc = match find_hxv4_descriptor(index_blob) {
        Some(d) => d,
        None => return Ok(Vec::new()),
    };

    let end = desc.offset + (desc.size as u64);
    if desc.offset > blob.len() as u64 || end > blob.len() as u64 {
        return Err("Hxv4 payload points outside archive".to_string());
    }

    let payload = &blob[(desc.offset as usize)..(end as usize)];
    println!("DEBUG: desc.offset = {}, size = {}", desc.offset, desc.size);
    println!("DEBUG: payload MAC = {:?}", &payload[0..16]);

    let decrypted = decrypt_hxv4_payload(payload, desc.flags, custom_key, custom_nonce0, custom_nonce1)?;

    if decrypted.len() < 4 {
        return Err("truncated decrypted Hxv4 payload".into());
    }

    let uncompressed_size = u32::from_le_bytes(decrypted[0..4].try_into().unwrap()) as usize;
    
    let mut table_blob = Vec::new();
    let mut decoder = ZlibDecoder::new(&decrypted[4..]);
    decoder.read_to_end(&mut table_blob).map_err(|_| "Hxv4 table decompression failed".to_string())?;

    if table_blob.len() != uncompressed_size {
        return Err("Hxv4 table decompression size mismatch".into());
    }

    let mut reader = TJSBinaryReader { data: &table_blob, pos: 0 };
    let value = reader.read_value()?;

    let root_array = match value {
        TJSValue::Array(arr) if arr.len() % 2 == 0 => arr,
        _ => return Err("unexpected Hxv4 table shape".into()),
    };

    let entry_base = if entries.len() > 1 && entries[1].name == "startup.tjs" { 1 } else { 0 };
    let mut records = Vec::new();

    for g in (0..root_array.len()).step_by(2) {
        let domain_hash = match &root_array[g] {
            TJSValue::Octet(o) => bytes_to_hex(o),
            _ => return Err("unexpected Hxv4 group shape".into()),
        };

        let group_arr = match &root_array[g + 1] {
            TJSValue::Array(arr) if arr.len() % 2 == 0 => arr,
            _ => return Err("unexpected Hxv4 group shape".into()),
        };

        for i in (0..group_arr.len()).step_by(2) {
            let file_hash = match &group_arr[i] {
                TJSValue::Octet(o) => bytes_to_hex(o),
                _ => return Err("unexpected Hxv4 record shape".into()),
            };

            let pair = match &group_arr[i + 1] {
                TJSValue::Array(arr) if arr.len() == 2 => arr,
                _ => return Err("unexpected Hxv4 record shape".into()),
            };

            let packed = match &pair[0] {
                TJSValue::Int(n) => *n as u64,
                _ => return Err("unexpected Hxv4 record type".into()),
            };

            let key = match &pair[1] {
                TJSValue::Int(n) => *n as u64,
                _ => return Err("unexpected Hxv4 record type".into()),
            };

            let archive_slot = ((packed >> 16) & 0xFFFF) as u32;
            let filter_flag = (packed & 0xFFFF) as u32;

            let mut xp3_entry_index = None;
            if archive_slot == 0 {
                let idx = (filter_flag as usize) + entry_base;
                if idx < entries.len() {
                    xp3_entry_index = Some(idx);
                }
            }

            records.push(Hxv4Record {
                domain_hash: domain_hash.clone(),
                file_hash,
                archive_slot,
                filter_flag,
                key,
                xp3_entry_index,
            });
        }
    }

    Ok(records)
}
