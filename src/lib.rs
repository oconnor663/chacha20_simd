extern crate byteorder;

use byteorder::{ByteOrder, LittleEndian};
use std::arch::x86_64::*;
use std::cmp;

const IV: &[u8; 16] = b"expand 32-byte k";

// NOTE: This is the IETF-standardized 12-byte nonce.
pub const NONCEBYTES: usize = 12;
pub const KEYBYTES: usize = 32;
pub const BLOCKBYTES: usize = 64;

fn chacha_block_init(
    block: &mut [u8; BLOCKBYTES],
    key: &[u8; KEYBYTES],
    nonce: &[u8; NONCEBYTES],
    block_num: u32,
) {
    block[0..16].copy_from_slice(IV);
    block[16..48].copy_from_slice(key);
    LittleEndian::write_u32(&mut block[48..52], block_num);
    // NOTE: This is the IETF-standardized 12-byte nonce.
    block[52..64].copy_from_slice(nonce);
}

fn chacha_quarter_round(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = v[a].wrapping_add(v[b]);
    v[d] = (v[d] ^ v[a]).rotate_left(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_left(12);
    v[a] = v[a].wrapping_add(v[b]);
    v[d] = (v[d] ^ v[a]).rotate_left(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_left(7);
}

fn chacha_double_round(v: &mut [u32; 16]) {
    // odd round, columns
    chacha_quarter_round(v, 0, 4, 8, 12);
    chacha_quarter_round(v, 1, 5, 9, 13);
    chacha_quarter_round(v, 2, 6, 10, 14);
    chacha_quarter_round(v, 3, 7, 11, 15);
    // even round, diagonals
    chacha_quarter_round(v, 0, 5, 10, 15);
    chacha_quarter_round(v, 1, 6, 11, 12);
    chacha_quarter_round(v, 2, 7, 8, 13);
    chacha_quarter_round(v, 3, 4, 9, 14);
}

pub fn chacha20_permute(block: &mut [u8; BLOCKBYTES]) {
    let mut words = [0u32; 16];
    for i in 0..16 {
        words[i] = LittleEndian::read_u32(&block[i * 4..][..4]);
    }
    for _ in 0..10 {
        chacha_double_round(&mut words);
    }
    for i in 0..16 {
        let orig = LittleEndian::read_u32(&block[i * 4..][..4]);
        LittleEndian::write_u32(&mut block[i * 4..][..4], orig.wrapping_add(words[i]));
    }
}

// NOTE: This is the IETF-standardized 12-byte nonce.
pub fn chacha20_xor(input: &mut [u8], key: &[u8; 32], nonce: &[u8; 12]) {
    let mut block = [0; BLOCKBYTES];
    let mut block_start = 0;
    while block_start < input.len() {
        chacha_block_init(&mut block, key, nonce, (block_start / BLOCKBYTES) as u32);
        chacha20_permute(&mut block);

        // XOR in as many block bytes as possible.
        let block_len = cmp::min(input.len() - block_start, BLOCKBYTES);
        for i in 0..block_len {
            input[block_start + i] ^= block[i];
        }

        block_start += block_len;
    }
}

#[inline(always)]
unsafe fn add(a: __m256i, b: __m256i) -> __m256i {
    _mm256_add_epi32(a, b)
}

#[inline(always)]
unsafe fn xor(a: __m256i, b: __m256i) -> __m256i {
    _mm256_xor_si256(a, b)
}

#[inline(always)]
unsafe fn rotate_left_16(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(x, 16), _mm256_srli_epi32(x, 32 - 16))
}

#[inline(always)]
unsafe fn rotate_left_12(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(x, 12), _mm256_srli_epi32(x, 32 - 12))
}

#[inline(always)]
unsafe fn rotate_left_8(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(x, 8), _mm256_srli_epi32(x, 32 - 8))
}

#[inline(always)]
unsafe fn rotate_left_7(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(x, 7), _mm256_srli_epi32(x, 32 - 7))
}

#[inline(always)]
unsafe fn avx2_quarter_round(vecs: &mut [__m256i; 16], a: usize, b: usize, c: usize, d: usize) {
    vecs[a] = add(vecs[a], vecs[b]);
    vecs[d] = rotate_left_16(xor(vecs[d], vecs[a]));
    vecs[c] = add(vecs[c], vecs[d]);
    vecs[b] = rotate_left_12(xor(vecs[b], vecs[c]));
    vecs[a] = add(vecs[a], vecs[b]);
    vecs[d] = rotate_left_8(xor(vecs[d], vecs[a]));
    vecs[c] = add(vecs[c], vecs[d]);
    vecs[b] = rotate_left_7(xor(vecs[b], vecs[c]));
}

#[inline(always)]
unsafe fn avx2_double_round(vecs: &mut [__m256i; 16]) {
    // odd round, columns
    avx2_quarter_round(vecs, 0, 4, 8, 12);
    avx2_quarter_round(vecs, 1, 5, 9, 13);
    avx2_quarter_round(vecs, 2, 6, 10, 14);
    avx2_quarter_round(vecs, 3, 7, 11, 15);
    // even round, diagonals
    avx2_quarter_round(vecs, 0, 5, 10, 15);
    avx2_quarter_round(vecs, 1, 6, 11, 12);
    avx2_quarter_round(vecs, 2, 7, 8, 13);
    avx2_quarter_round(vecs, 3, 4, 9, 14);
}

#[target_feature(enable = "avx2")]
pub unsafe fn avx2_permute_8way_transposed(vecs: &mut [__m256i; 16]) {
    debug_assert!(is_x86_feature_detected!("avx2"), "oops no AVX2 support");
    let orig = *vecs;
    for _ in 0..10 {
        avx2_double_round(vecs);
    }
    for i in 0..vecs.len() {
        vecs[i] = add(vecs[i], orig[i]);
    }
}

#[cfg(test)]
mod tests {
    extern crate libsodium_ffi;

    use super::*;
    use std::mem;

    const KEY: &[u8; 32] = b"This is my key. It is very nice.";
    const NONCE: &[u8; 12] = b"my nonce foo";
    const STREAM_LEN: usize = 1_000_000;

    #[test]
    fn test_iv_constants() {
        assert_eq!(0x61707865, LittleEndian::read_u32(&IV[0..][..4]));
        assert_eq!(0x3320646e, LittleEndian::read_u32(&IV[4..][..4]));
        assert_eq!(0x79622d32, LittleEndian::read_u32(&IV[8..][..4]));
        assert_eq!(0x6b206574, LittleEndian::read_u32(&IV[12..][..4]));
    }

    #[test]
    fn test_against_libsodium() {
        let mut libsodium_encrypted = vec![0xab; STREAM_LEN];
        unsafe {
            libsodium_ffi::crypto_stream_chacha20_ietf_xor_ic(
                libsodium_encrypted.as_mut_ptr(),
                libsodium_encrypted.as_ptr(),
                libsodium_encrypted.len() as u64,
                NONCE.as_ptr(),
                0,
                KEY.as_ptr(),
            );
        }

        let mut self_encrypted = vec![0xab; STREAM_LEN];
        chacha20_xor(&mut self_encrypted, KEY, NONCE);

        assert_eq!(libsodium_encrypted, self_encrypted);
    }

    fn transpose8(blocks: [[u8; BLOCKBYTES]; 8]) -> [__m256i; 16] {
        unsafe {
            let mut vecs: [__m256i; 16] = mem::zeroed();
            for vec_i in 0..16 {
                let mut ints = [0; 8];
                for int_i in 0..8 {
                    ints[int_i] = LittleEndian::read_u32(&blocks[int_i][4 * vec_i..][..4]);
                }
                vecs[vec_i] = mem::transmute(ints);
            }
            vecs
        }
    }

    fn transpose8_back(vecs: [__m256i; 16]) -> [[u8; BLOCKBYTES]; 8] {
        unsafe {
            let mut blocks = [[0; BLOCKBYTES]; 8];
            for vec_i in 0..16 {
                let ints: [u32; 8] = mem::transmute(vecs[vec_i]);
                for int_i in 0..8 {
                    LittleEndian::write_u32(&mut blocks[int_i][4 * vec_i..][..4], ints[int_i]);
                }
            }
            blocks
        }
    }

    #[test]
    fn test_transpose() {
        let blocks = [
            [0; BLOCKBYTES],
            [1; BLOCKBYTES],
            [2; BLOCKBYTES],
            [3; BLOCKBYTES],
            [4; BLOCKBYTES],
            [5; BLOCKBYTES],
            [6; BLOCKBYTES],
            [7; BLOCKBYTES],
        ];

        let transposed = transpose8(blocks);

        let back = transpose8_back(transposed);

        for i in 0..blocks.len() {
            println!("block {}", i);
            assert_eq!(&blocks[i][..], &back[i][..]);
        }
    }

    #[test]
    fn test_avx2() {
        debug_assert!(is_x86_feature_detected!("avx2"), "oops no AVX2 support");
        unsafe {
            let blocks = [
                [0; BLOCKBYTES],
                [1; BLOCKBYTES],
                [2; BLOCKBYTES],
                [3; BLOCKBYTES],
                [4; BLOCKBYTES],
                [5; BLOCKBYTES],
                [6; BLOCKBYTES],
                [7; BLOCKBYTES],
            ];

            let mut transposed = transpose8(blocks);
            avx2_permute_8way_transposed(&mut transposed);
            let output = transpose8_back(transposed);

            let mut expected = blocks;
            chacha20_permute(&mut expected[0]);
            chacha20_permute(&mut expected[1]);
            chacha20_permute(&mut expected[2]);
            chacha20_permute(&mut expected[3]);
            chacha20_permute(&mut expected[4]);
            chacha20_permute(&mut expected[5]);
            chacha20_permute(&mut expected[6]);
            chacha20_permute(&mut expected[7]);

            for i in 0..expected.len() {
                println!("block {}", i);
                assert_eq!(&expected[i][..], &output[i][..]);
            }
        }
    }
}
