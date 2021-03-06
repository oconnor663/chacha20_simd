#![feature(test)]

extern crate chacha20_simd;
extern crate libsodium_ffi;
extern crate openssl;
extern crate test;

use chacha20_simd::*;
use std::mem;
use test::Bencher;

const KEY: &[u8; 32] = b"This is my key. It is very nice.";
const NONCE: &[u8; 12] = b"my nonce foo";

const MB: usize = 1_000_000;

#[bench]
fn libsodium_chacha20_1mb(b: &mut Bencher) {
    b.bytes = MB as u64;
    assert_eq!(0, unsafe { libsodium_ffi::sodium_init() });
    let mut input = vec![0xff; MB];
    b.iter(|| unsafe {
        libsodium_ffi::crypto_stream_chacha20_ietf_xor_ic(
            input.as_mut_ptr(),
            input.as_ptr(),
            input.len() as u64,
            NONCE.as_ptr(),
            0,
            KEY.as_ptr(),
        )
    });
}

#[bench]
fn openssl_chacha20_1mb(b: &mut Bencher) {
    b.bytes = MB as u64;
    let cipher = openssl::symm::Cipher::chacha20();
    let input = vec![0xff; MB];
    let key = vec![0xff; cipher.key_len()];
    let nonce = vec![0xff; cipher.iv_len().unwrap()];
    b.iter(|| {
        openssl::symm::encrypt(
            openssl::symm::Cipher::chacha20(),
            &key,
            Some(&nonce),
            &input,
        ).unwrap()
    });
}

#[bench]
fn self_chacha20_xor_1mb(b: &mut Bencher) {
    b.bytes = MB as u64;
    let mut input = vec![0xff; MB];
    b.iter(|| {
        chacha20_xor(&mut input, KEY, NONCE);
    });
}

#[bench]
fn self_chacha20_permute_portable(b: &mut Bencher) {
    b.bytes = BLOCKBYTES as u64;
    let mut input = [0xab; BLOCKBYTES];
    b.iter(|| {
        chacha20_permute(&mut input);
    });
}

#[bench]
fn self_chacha20_permute_avx2(b: &mut Bencher) {
    unsafe {
        debug_assert!(is_x86_feature_detected!("avx2"), "oops no AVX2 support");
        b.bytes = BLOCKBYTES as u64 * 8;
        let mut input = mem::transmute([0x42u8; BLOCKBYTES * 8]);
        b.iter(|| {
            avx2_permute_8way_transposed(&mut input);
        });
    }
}
