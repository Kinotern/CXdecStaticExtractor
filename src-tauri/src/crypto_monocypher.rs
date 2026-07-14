use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20Legacy, XChaCha20};
use poly1305::Poly1305;
use universal_hash::{KeyInit, UniversalHash};

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

    let key_bytes = if custom_key.len() == 32 { custom_key } else { super::HXV4_KEY };
    let nonce_bytes = if (flags & 1) != 0 {
        if custom_nonce1.len() == 24 { custom_nonce1 } else { super::HXV4_NONCES[1] }
    } else {
        if custom_nonce0.len() == 24 { custom_nonce0 } else { super::HXV4_NONCES[0] }
    };

    let mac_tag = &payload[0..16];
    let ciphertext = &payload[16..];

    // Monocypher's XChaCha20Poly1305:
    // 1. HChaCha20(key, nonce[0..16]) -> subkey
    let mut subkey = [0u8; 32];
    chacha20::hchacha20(key_bytes.into(), nonce_bytes[0..16].into(), &mut subkey);

    // 2. ChaCha20Legacy(subkey, nonce[16..24])
    let legacy_nonce = &nonce_bytes[16..24];
    
    // Auth key is ChaCha20Legacy keystream with counter = 0
    let mut auth_key = [0u8; 64];
    let mut auth_cipher = ChaCha20Legacy::new(&subkey.into(), legacy_nonce.into());
    // In ChaCha20Legacy, set_block_pos takes a 64-bit counter. Default is 0.
    auth_cipher.apply_keystream(&mut auth_key);

    // Poly1305 key is the first 32 bytes of auth_key
    let mut poly = Poly1305::new_from_slice(&auth_key[0..32]).unwrap();

    // Poly1305 over AD (empty) + Ciphertext + Sizes (empty=0, text=text_len)
    // Actually, we pad ciphertext to 16 bytes
    let text_len = ciphertext.len() as u64;
    
    poly.update(ciphertext);
    let pad_len = (16 - (text_len % 16)) % 16;
    poly.update(&vec![0u8; pad_len as usize]);

    let mut sizes = [0u8; 16];
    sizes[8..16].copy_from_slice(&text_len.to_le_bytes());
    poly.update(&sizes);

    let real_mac = poly.finalize().into_bytes();

    if real_mac.as_slice() != mac_tag {
        return Err("Hxv4 Payload MAC verification failed!".to_string());
    }

    // Decrypt ciphertext with counter = 1
    let mut plain_text = ciphertext.to_vec();
    let mut text_cipher = ChaCha20Legacy::new(&subkey.into(), legacy_nonce.into());
    // apply_keystream advances counter. Since auth_cipher processed 64 bytes (1 block), 
    // we can just make a new cipher and set block pos to 1!
    text_cipher.set_block_pos(1);
    text_cipher.apply_keystream(&mut plain_text);

    Ok(plain_text)
}
