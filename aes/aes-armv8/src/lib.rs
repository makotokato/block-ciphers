//! AES block ciphers implementation using ARM Crypto Extension instruction set.
//!
//! This crate does not implement any software fallback and does not
//! automatically check cpuinfo, so if you are using this crate make sure to run
//! software on an appropriate hardware or to use software fallback
//! (e.g. from [`aes-soft`](https://crates.io/crates/aes-soft) crate) with
//! runtime detection of AES ARM crypto extension availability (e.g. by using
//! `/proc/cpuinfo`).
//!
//! When using this crate do not forget to enable `crypto` target feature,
//! otherwise you will get a compilation error. You can do it either by using
//! `RUSTFLAGS="-C target-feature=+crypto"` or by editing your `.cargo/config`.
//!
//! Ciphers functionality is accessed using `BlockCipher` trait from
//! [`block-cipher-trait`](https://docs.rs/block-cipher-trait) crate.
//!
//! # Usage example
//! ```
//! use aes_armv8::block_cipher_trait::generic_array::GenericArray;
//! use aes_armv8::block_cipher_trait::BlockCipher;
//! use aes_armv8::Aes128;
//!
//! let key = GenericArray::from_slice(&[0u8; 16]);
//! let mut block = GenericArray::clone_from_slice(&[0u8; 16]);
//! let mut block8 = GenericArray::clone_from_slice(&[block; 8]);
//! // Initialize cipher
//! let cipher = aes_armv8::Aes128::new(&key);
//!
//! let block_copy = block.clone();
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//!
//! // We can encrypt 8 blocks simultaneously using
//! // instruction-level parallelism
//! let block8_copy = block8.clone();
//! cipher.encrypt_blocks(&mut block8);
//! cipher.decrypt_blocks(&mut block8);
//! assert_eq!(block8, block8_copy);
//! ```
//!
//! # Runtime detection
//! If you plan to use AES with runtime detection (e.g. via
//! `is_aarch64_feature_detected!("crypto")`), then you'll need to enable `nocheck`
//! feature to disable compile-time target checks. Note that techincally
//! doing so will make API of this crate unsafe, so you MUST ensure that
//! this crate will be used in contexts with enabled necessary target features!
#![no_std]
#![feature(
  aarch64_target_feature,
  asm,
  stdsimd,
)]
pub extern crate block_cipher_trait;
#[macro_use]
extern crate opaque_debug;
#[cfg(not(feature = "nocheck"))]
mod target_checks;

mod expand;
mod impls;

pub use impls::{Aes128, Aes192, Aes256};
