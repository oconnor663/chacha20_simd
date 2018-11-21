#![feature(test)]

extern crate chacha20_simd;
extern crate libsodium_ffi;
extern crate openssl;
extern crate test;

use test::Bencher;

const MB: usize = 1_000_000;

#[bench]
fn libsodium_chacha20_1mb(b: &mut Bencher) {
    b.bytes = MB as u64;
    assert_eq!(0, unsafe { libsodium_ffi::sodium_init() });
    let mut input = vec![0xff; MB];
    let key = vec![0xff; 32];
    let nonce = vec![0xff; 8];
    b.iter(|| unsafe {
        libsodium_ffi::crypto_stream_chacha20(
            input.as_mut_ptr(),
            input.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
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
