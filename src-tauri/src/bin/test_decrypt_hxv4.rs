use std::fs::File;
use std::io::Read;
use std::io::Seek;
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce, aead::{Aead, KeyInit}};

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| e.to_string())
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let xp3_path = r"D:\Program\Steam\steamapps\common\CafeStella\bgimage.xp3";
    println!("Reading archive: {}", xp3_path);
    
    let mut file = File::open(xp3_path)?;
    let file_size = file.metadata()?.len();
    
    let mut magic = [0u8; 11];
    file.read_exact(&mut magic)?;
    if &magic[0..3] != b"XP3" {
        println!("Not a valid XP3 archive.");
        return Ok(());
    }
    
    // Read header offset
    let mut offset_bytes = [0u8; 8];
    file.read_exact(&mut offset_bytes)?;
    let mut header_offset = u64::from_le_bytes(offset_bytes);
    
    if header_offset == 0x17 && file_size >= 0x28 {
        file.seek(std::io::SeekFrom::Start(0x20))?;
        let mut candidate_bytes = [0u8; 8];
        file.read_exact(&mut candidate_bytes)?;
        let candidate = u64::from_le_bytes(candidate_bytes);
        if candidate > 0 && candidate < file_size {
            header_offset = candidate;
        }
    }
    
    println!("Header offset: {}", header_offset);
    file.seek(std::io::SeekFrom::Start(header_offset))?;
    
    let mut flag_bytes = [0u8; 1];
    file.read_exact(&mut flag_bytes)?;
    let flag = flag_bytes[0];
    
    let mut index_data = Vec::new();
    if flag == 0 {
        let mut sz_bytes = [0u8; 8];
        file.read_exact(&mut sz_bytes)?;
        let index_size = u64::from_le_bytes(sz_bytes);
        index_data = vec![0u8; index_size as usize];
        file.read_exact(&mut index_data)?;
    } else if flag == 1 {
        let mut comp_sz_bytes = [0u8; 8];
        file.read_exact(&mut comp_sz_bytes)?;
        let comp_size = u64::from_le_bytes(comp_sz_bytes);
        
        let mut orig_sz_bytes = [0u8; 8];
        file.read_exact(&mut orig_sz_bytes)?;
        let _orig_size = u64::from_le_bytes(orig_sz_bytes);
        
        let mut chunk = vec![0u8; comp_size as usize];
        file.read_exact(&mut chunk)?;
        
        let mut decoder = flate2::read::ZlibDecoder::new(&chunk[..]);
        decoder.read_to_end(&mut index_data)?;
    }
    
    println!("Parsed index data length: {}", index_data.len());
    
    // Find Hxv4 descriptor in index_data
    let mut cursor = 0;
    let mut hxv4_desc = None;
    while cursor + 12 <= index_data.len() {
        let tag = &index_data[cursor..cursor + 4];
        let chunk_size = u64::from_le_bytes(index_data[cursor + 4..cursor + 12].try_into().unwrap()) as usize;
        cursor += 12;
        if cursor + chunk_size > index_data.len() { break; }
        if tag == b"Hxv4" && chunk_size >= 14 {
            let offset = u64::from_le_bytes(index_data[cursor..cursor + 8].try_into().unwrap());
            let size = u32::from_le_bytes(index_data[cursor + 8..cursor + 12].try_into().unwrap());
            let flags = u16::from_le_bytes(index_data[cursor + 12..cursor + 14].try_into().unwrap());
            hxv4_desc = Some((offset, size, flags));
            break;
        }
        cursor += chunk_size;
    }
    
    let (hxv4_offset, hxv4_size, hxv4_flags) = match hxv4_desc {
        Some(x) => x,
        None => {
            println!("Hxv4 descriptor not found in index.");
            return Ok(());
        }
    };
    
    println!("Hxv4 descriptor: offset={}, size={}, flags={}", hxv4_offset, hxv4_size, hxv4_flags);
    
    // Seek to hxv4_offset and read payload
    file.seek(std::io::SeekFrom::Start(hxv4_offset))?;
    let mut payload = vec![0u8; hxv4_size as usize];
    file.read_exact(&mut payload)?;
    
    if payload.len() < 16 {
        println!("Payload too small.");
        return Ok(());
    }
    
    // Re-arrange payload: HXV4 format is [MAC (16 bytes) | Ciphertext], Rust AEAD expects [Ciphertext | MAC]
    let mac = &payload[0..16];
    let ciphertext = &payload[16..];
    let mut rust_aead_payload = vec![0u8; ciphertext.len() + 16];
    rust_aead_payload[0..ciphertext.len()].copy_from_slice(ciphertext);
    rust_aead_payload[ciphertext.len()..].copy_from_slice(mac);
    
    // Try decrypting with various keys and BOTH nonces
    let key_configs = vec![
        (
            "Default HXV4 Key",
            vec![
                0xe4, 0xdc, 0x1d, 0x99, 0xd9, 0xd9, 0xfb, 0x1a, 
                0xe5, 0xf7, 0x52, 0x9e, 0xe7, 0x0f, 0x84, 0x1b, 
                0xfa, 0xdb, 0x13, 0xd1, 0x2f, 0x4d, 0x22, 0xb9, 
                0x91, 0x70, 0xd6, 0xcc, 0x6a, 0x62, 0xbc, 0x54 
            ],
            vec![
                0xd9, 0x92, 0x30, 0xe0, 0x26, 0x23, 0xf4, 0xa0, 0xc4, 0xf2, 0x85, 0x76, 0x82, 0xb4, 0xde, 0x6d, 0xfe, 0xfe, 0x82, 0x0b, 0x57, 0x06, 0x0e, 0x50
            ],
            vec![
                0xb9, 0x6f, 0x89, 0x63, 0x08, 0x50, 0xdd, 0x23, 0xa1, 0x38, 0x10, 0xc7, 0x71, 0x8a, 0xd0, 0x03, 0x93, 0x6d, 0x1d, 0x4a, 0x3a, 0xe0, 0x08, 0x90
            ]
        ),
        (
            "CafeStella Steam Extracted Key",
            hex_decode("77987faf3a8bb3ec9c31ec618319360721ab314cb2198cf10d96fed40affcc24")?,
            hex_decode("6e69de1b066aa4823bd31dcb789a384b1d726c36d1241ec3")?,
            hex_decode("524ce3acd0bfd8a906654cc06fb462deaf978684e3ee7cd8")?
        ),
        (
            "CafeStella HF (Non-Steam) Key",
            hex_decode("77987faf3a8bb3ec9c31ec618319360721ab314cb2198cf10d96fed40affcc24")?,
            hex_decode("7ae70eab3e7cb0028bb9c15fd2c965890bab13edba0bd2bb")?,
            hex_decode("524ce3acd0bfd8a906654cc06fb462deaf978684e3ee7cd8")?
        )
    ];
    
    for (label, k, n0, n1) in key_configs {
        for (nonce_label, nonce_bytes) in vec![("Nonce0", &n0), ("Nonce1", &n1)] {
            println!("Testing: {} + {} (length: {})", label, nonce_label, nonce_bytes.len());
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&k));
            let nonce = XNonce::from_slice(nonce_bytes);
            
            match cipher.decrypt(nonce, rust_aead_payload.as_slice()) {
                Ok(dec) => {
                    println!("  --> SUCCESS! Decrypted payload size: {}", dec.len());
                    if dec.len() >= 4 {
                        let uncomp = u32::from_le_bytes(dec[0..4].try_into().unwrap());
                        println!("  --> Uncompressed size: {}", uncomp);
                    }
                }
                Err(e) => {
                    println!("  --> Failed: {:?}", e);
                }
            }
        }
    }
    
    Ok(())
}
