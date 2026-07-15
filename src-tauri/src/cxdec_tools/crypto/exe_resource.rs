//! EXE RCDATA BasicCryptoFilter used by Magalumina's embedded scripts.

use crate::cxdec_tools::crypto::hxv4_compute::{HX_CHACHA_BLOCK_LEN, chacha_transform_words};
use sha3::{Digest, Sha3_384};

pub const EXE_IMAGE_BASE: u32 = 0x400000;
pub const EXE_RESOURCE_SALT_VA: u32 = 0x6E5A60;
pub const EXE_RESOURCE_SALT_SIZE: usize = 0x2000;
pub const BOOTSTRAP_RESOURCE_NAME: &str = "BOOTSTRAP";
pub const BOOTSTRAP_FILTER_PATH: &str = "jvmyz325w2iw6rpvqxxrvf2x7s";
pub const STARTUP_RESOURCE_NAME: &str = "STARTUP.TJS";
pub const STARTUP_FILTER_PATH: &str = "tv5z6ta4ijnzxke266sheh6fai";

const EXE_CHACHA_ROUNDS: u32 = 8;
const EXE_CHACHA_DOUBLE_ROUNDS: usize = 4;
const OBFUSCATED_CHACHA_CONSTANT: [u8; 16] = [
    0x9a, 0x87, 0x8f, 0x9e, 0x91, 0x9b, 0xdf, 0xcc, 0xcd, 0xd2, 0x9d, 0x86, 0x8b, 0x9a, 0xdf, 0x94,
];

#[derive(Debug, Clone)]
pub struct ExeBasicCryptoFilter {
    stored_state: [u32; 16],
    qword1_low: u32,
    qword1_high: u32,
    rounds: u32,
}

impl ExeBasicCryptoFilter {
    // Handles from path and salt behavior.
    pub fn from_path_and_salt(path: &str, salt: &[u8]) -> Self {
        let material = derive_path_key_material(path, salt);
        let mut stored_state = [0u32; 16];

        for (index, value) in stored_state.iter_mut().take(4).enumerate() {
            *value = read_le_u32(&OBFUSCATED_CHACHA_CONSTANT, index * 4);
        }
        for (index, value) in stored_state.iter_mut().skip(4).take(8).enumerate() {
            *value = !read_le_u32(&material, index * 4);
        }

        let qword0_low = read_le_u32(&material, 0x20);
        let qword0_high = read_le_u32(&material, 0x24);
        stored_state[12] = u32::MAX;
        stored_state[13] = u32::MAX;
        stored_state[14] = !qword0_low;
        stored_state[15] = !qword0_high;

        ExeBasicCryptoFilter {
            stored_state,
            qword1_low: read_le_u32(&material, 0x28),
            qword1_high: read_le_u32(&material, 0x2c),
            rounds: EXE_CHACHA_ROUNDS,
        }
    }

    // Decrypts in place.
    pub fn decrypt_in_place(&self, offset: u64, data: &mut [u8]) {
        let mut done = 0usize;
        while done < data.len() {
            let pos = offset + done as u64;
            let block_index = pos >> 6;
            let block_offset = (pos & 0x3f) as usize;
            let count = (data.len() - done).min(HX_CHACHA_BLOCK_LEN - block_offset);
            let key_stream = self.key_stream_block(block_index);

            for i in 0..count {
                data[done + i] ^= key_stream[block_offset + i];
            }
            done += count;
        }
    }

    // Handles decrypt behavior.
    pub fn decrypt(&self, offset: u64, input: &[u8]) -> Vec<u8> {
        let mut output = input.to_vec();
        self.decrypt_in_place(offset, &mut output);
        output
    }

    // Handles key stream block behavior.
    fn key_stream_block(&self, block_index: u64) -> [u8; HX_CHACHA_BLOCK_LEN] {
        let mut block_state = self.stored_state;
        let counter =
            !(((self.qword1_high as u64) << 32) | ((self.qword1_low ^ block_index as u32) as u64));
        block_state[12] = counter as u32;
        block_state[13] = (counter >> 32) as u32;
        chacha_block_from_stored_state(&block_state, self.rounds)
    }
}

// Decrypts resource.
pub fn decrypt_resource(resource: &[u8], filter_path: &str, salt: &[u8]) -> Vec<u8> {
    ExeBasicCryptoFilter::from_path_and_salt(filter_path, salt).decrypt(0, resource)
}

// Derives path key material.
pub fn derive_path_key_material(path: &str, salt: &[u8]) -> [u8; 48] {
    let mut hasher = Sha3_384::new();
    for word in path.encode_utf16() {
        hasher.update(word.to_le_bytes());
    }
    hasher.update(salt);
    hasher.finalize().into()
}

// Handles ChaCha block from stored state behavior.
fn chacha_block_from_stored_state(
    stored_state: &[u32; 16],
    rounds: u32,
) -> [u8; HX_CHACHA_BLOCK_LEN] {
    let mut initial = [0u32; 16];
    for (dst, src) in initial.iter_mut().zip(stored_state.iter()) {
        *dst = !*src;
    }

    let double_rounds = (((rounds - 1) >> 1) + 1) as usize;
    debug_assert_eq!(double_rounds, EXE_CHACHA_DOUBLE_ROUNDS);
    let transformed = chacha_transform_words(initial, double_rounds);

    let mut out = [0u8; HX_CHACHA_BLOCK_LEN];
    for i in 0..16 {
        let value = transformed[i].wrapping_add(initial[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    out
}

// Reads le u32.
fn read_le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
