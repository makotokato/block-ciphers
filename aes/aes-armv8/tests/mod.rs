//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/
#![no_std]
#![cfg(target_arch = "aarch64")]
extern crate aes_armv8;
#[macro_use]
extern crate block_cipher_trait;

new_test!(aes128_test, "aes128", aes_armv8::Aes128);
new_test!(aes192_test, "aes192", aes_armv8::Aes192);
new_test!(aes256_test, "aes256", aes_armv8::Aes256);
