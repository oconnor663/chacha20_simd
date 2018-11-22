extern crate byteorder;

use byteorder::{ByteOrder, LittleEndian};
use std::cmp;

const IV: &[u8; 16] = b"expand 32-byte k";
const BLOCKSIZE: usize = 64;

#[inline(always)]
fn chacha_quarter(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = v[a].wrapping_add(v[b]);
    v[d] = (v[d] ^ v[a]).rotate_left(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_left(12);
    v[a] = v[a].wrapping_add(v[b]);
    v[d] = (v[d] ^ v[a]).rotate_left(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_left(7);
}

fn chacha20_block(block: &mut [u8; BLOCKSIZE]) {
    let mut words = [0u32; 16];
    for i in 0..16 {
        words[i] = LittleEndian::read_u32(&block[i * 4..][..4]);
    }
    for _ in 0..10 {
        // odd round, columns
        chacha_quarter(&mut words, 0, 4, 8, 12);
        chacha_quarter(&mut words, 1, 5, 9, 13);
        chacha_quarter(&mut words, 2, 6, 10, 14);
        chacha_quarter(&mut words, 3, 7, 11, 15);
        // even round, diagonals
        chacha_quarter(&mut words, 0, 5, 10, 15);
        chacha_quarter(&mut words, 1, 6, 11, 12);
        chacha_quarter(&mut words, 2, 7, 8, 13);
        chacha_quarter(&mut words, 3, 4, 9, 14);
    }
    for i in 0..16 {
        let orig = LittleEndian::read_u32(&block[i * 4..][..4]);
        LittleEndian::write_u32(&mut block[i * 4..][..4], orig.wrapping_add(words[i]));
    }
}

// NOTE: This is the IETF-standardized 12-byte nonce.
pub fn chacha20_stream(out: &mut [u8], key: &[u8; 32], nonce: &[u8; 12]) {
    let mut block = [0; BLOCKSIZE];
    let mut block_num: u32 = 0;
    let mut block_start: usize = 0;
    while block_start < out.len() {
        // Populate the block.
        block[0..16].copy_from_slice(IV);
        block[16..48].copy_from_slice(key);
        // NOTE: This is the IETF-standardized 4-byte counter.
        LittleEndian::write_u32(&mut block[48..52], block_num);
        // NOTE: This is the IETF-standardized 12-byte nonce.
        block[52..64].copy_from_slice(nonce);

        // Permute the block.
        chacha20_block(&mut block);

        // Write as many block bytes as possible.
        let block_len = cmp::min(out.len() - block_start, BLOCKSIZE);
        out[block_start..][..block_len].copy_from_slice(&block[..block_len]);
        block_num += 1;
        block_start += block_len;
    }
}

#[cfg(test)]
mod tests {
    extern crate libsodium_ffi;

    use super::*;

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
        let mut libsodium_stream = vec![0x00; STREAM_LEN];
        unsafe {
            libsodium_ffi::crypto_stream_chacha20_ietf_xor_ic(
                libsodium_stream.as_mut_ptr(),
                libsodium_stream.as_ptr(),
                libsodium_stream.len() as u64,
                NONCE.as_ptr(),
                0,
                KEY.as_ptr(),
            );
        }

        let mut crate_encrypted = vec![0x00; STREAM_LEN];
        chacha20_stream(&mut crate_encrypted, KEY, NONCE);

        assert_eq!(libsodium_stream, crate_encrypted);
    }
}
