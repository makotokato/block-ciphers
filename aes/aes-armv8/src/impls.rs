use block_cipher_trait::generic_array::typenum::{U11, U13, U15, U24, U32};
use block_cipher_trait::generic_array::typenum::{U16, U8};
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::BlockCipher;

use core::arch::aarch64::{
    uint8x16_t, vaesdq_u8, vaeseq_u8, vaesimcq_u8, vaesmcq_u8,
};
use core::mem;
use core::ptr;

use expand::expand_key;

type Block128 = GenericArray<u8, U16>;
type Block128x8 = GenericArray<GenericArray<u8, U16>, U8>;

#[inline]
pub unsafe fn veorq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let c;
    asm!("eor $0.16b, $1.16b, $2.16b" : "=w"(c) : "w"(a), "w"(b));
    c
}

#[inline]
pub unsafe fn vld1q_u8(mem_addr: *const uint8x16_t) -> uint8x16_t { *mem_addr }

#[inline]
pub unsafe fn vst1q_u8(mem: *mut uint8x16_t, value: uint8x16_t) {
    ptr::write(mem, value);
}

macro_rules! load8 {
    ($blocks:expr) => {
        [
            vld1q_u8($blocks[0].as_ptr() as *const uint8x16_t),
            vld1q_u8($blocks[1].as_ptr() as *const uint8x16_t),
            vld1q_u8($blocks[2].as_ptr() as *const uint8x16_t),
            vld1q_u8($blocks[3].as_ptr() as *const uint8x16_t),
            vld1q_u8($blocks[4].as_ptr() as *const uint8x16_t),
            vld1q_u8($blocks[5].as_ptr() as *const uint8x16_t),
            vld1q_u8($blocks[6].as_ptr() as *const uint8x16_t),
            vld1q_u8($blocks[7].as_ptr() as *const uint8x16_t),
        ]
    };
}

macro_rules! store8 {
    ($blocks:expr, $b:expr) => {
        vst1q_u8($blocks[0].as_ptr() as *mut uint8x16_t, $b[0]);
        vst1q_u8($blocks[1].as_ptr() as *mut uint8x16_t, $b[1]);
        vst1q_u8($blocks[2].as_ptr() as *mut uint8x16_t, $b[2]);
        vst1q_u8($blocks[3].as_ptr() as *mut uint8x16_t, $b[3]);
        vst1q_u8($blocks[4].as_ptr() as *mut uint8x16_t, $b[4]);
        vst1q_u8($blocks[5].as_ptr() as *mut uint8x16_t, $b[5]);
        vst1q_u8($blocks[6].as_ptr() as *mut uint8x16_t, $b[6]);
        vst1q_u8($blocks[7].as_ptr() as *mut uint8x16_t, $b[7]);
    };
}

macro_rules! eor8 {
    ($b:expr, $key:expr) => {
        $b[0] = veorq_u8($b[0], $key);
        $b[1] = veorq_u8($b[1], $key);
        $b[2] = veorq_u8($b[2], $key);
        $b[3] = veorq_u8($b[3], $key);
        $b[4] = veorq_u8($b[4], $key);
        $b[5] = veorq_u8($b[5], $key);
        $b[6] = veorq_u8($b[6], $key);
        $b[7] = veorq_u8($b[7], $key);
    };
}

macro_rules! aese8 {
    ($b:expr, $key:expr) => {
        $b[0] = vaeseq_u8($b[0], $key);
        $b[1] = vaeseq_u8($b[1], $key);
        $b[2] = vaeseq_u8($b[2], $key);
        $b[3] = vaeseq_u8($b[3], $key);
        $b[4] = vaeseq_u8($b[4], $key);
        $b[5] = vaeseq_u8($b[5], $key);
        $b[6] = vaeseq_u8($b[6], $key);
        $b[7] = vaeseq_u8($b[7], $key);
    };
}

macro_rules! aesd8 {
    ($b:expr, $key:expr) => {
        $b[0] = vaesdq_u8($b[0], $key);
        $b[1] = vaesdq_u8($b[1], $key);
        $b[2] = vaesdq_u8($b[2], $key);
        $b[3] = vaesdq_u8($b[3], $key);
        $b[4] = vaesdq_u8($b[4], $key);
        $b[5] = vaesdq_u8($b[5], $key);
        $b[6] = vaesdq_u8($b[6], $key);
        $b[7] = vaesdq_u8($b[7], $key);
    };
}

macro_rules! aesmc8 {
    ($b:expr) => {
        $b[0] = vaesmcq_u8($b[0]);
        $b[1] = vaesmcq_u8($b[1]);
        $b[2] = vaesmcq_u8($b[2]);
        $b[3] = vaesmcq_u8($b[3]);
        $b[4] = vaesmcq_u8($b[4]);
        $b[5] = vaesmcq_u8($b[5]);
        $b[6] = vaesmcq_u8($b[6]);
        $b[7] = vaesmcq_u8($b[7]);
    };
}

macro_rules! aesimc8 {
    ($b:expr) => {
        $b[0] = vaesimcq_u8($b[0]);
        $b[1] = vaesimcq_u8($b[1]);
        $b[2] = vaesimcq_u8($b[2]);
        $b[3] = vaesimcq_u8($b[3]);
        $b[4] = vaesimcq_u8($b[4]);
        $b[5] = vaesimcq_u8($b[5]);
        $b[6] = vaesimcq_u8($b[6]);
        $b[7] = vaesimcq_u8($b[7]);
    };
}

macro_rules! define_aes_impl {
    (
        $name:ident,
        $key_size:ty,
        $rounds:expr,
        $rounds2:ty,
        $doc:expr
    ) => {
        #[derive(Clone)]
        pub struct $name {
            encrypt_keys: [uint8x16_t; $rounds],
            decrypt_keys: [uint8x16_t; $rounds],
        }

        impl $name {
            unsafe fn encrypt(&self, mut block: uint8x16_t) -> uint8x16_t {
                let keys = self.encrypt_keys;
                for i in 0..($rounds - 2) {
                    block = vaeseq_u8(block, keys[i]);
                    block = vaesmcq_u8(block);
                }
                block = vaeseq_u8(block, keys[$rounds - 2]);
                veorq_u8(block, keys[$rounds - 1])
            }

            unsafe fn decrypt(&self, mut block: uint8x16_t) -> uint8x16_t {
                let keys = self.decrypt_keys;
                for i in (2..$rounds).rev() {
                    block = vaesdq_u8(block, keys[i]);
                    block = vaesimcq_u8(block);
                }
                block = vaesdq_u8(block, keys[1]);
                veorq_u8(block, keys[0])
            }

            unsafe fn encrypt8(
                &self,
                blocks: &mut Block128x8,
            ) -> [uint8x16_t; 8]
            {
                let keys = self.encrypt_keys;
                let mut b = load8!(blocks);
                for i in 0..($rounds - 2) {
                    aese8!(b, keys[i]);
                    aesmc8!(b);
                }
                aese8!(b, keys[$rounds - 2]);
                eor8!(b, keys[$rounds - 1]);
                b
            }

            unsafe fn decrypt8(
                &self,
                blocks: &mut Block128x8,
            ) -> [uint8x16_t; 8]
            {
                let keys = self.decrypt_keys;
                let mut b = load8!(blocks);
                for i in (2..$rounds).rev() {
                    aesd8!(b, keys[i]);
                    aesimc8!(b);
                }
                aesd8!(b, keys[1]);
                eor8!(b, keys[0]);
                b
            }
        }

        impl BlockCipher for $name {
            type KeySize = $key_size;
            type BlockSize = U16;
            type ParBlocks = U8;

            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                unsafe {
                    let key = mem::transmute(key);
                    let (ek, dk) = expand_key::<$key_size, $rounds2>(key);
                    Self {
                        encrypt_keys: mem::transmute(ek),
                        decrypt_keys: mem::transmute(dk),
                    }
                }
            }

            fn encrypt_block(&self, block: &mut Block128) {
                unsafe {
                    let b = vld1q_u8(block.as_ptr() as *const uint8x16_t);
                    let b = self.encrypt(b);
                    vst1q_u8(block.as_mut_ptr() as *mut uint8x16_t, b);
                }
            }

            fn decrypt_block(&self, block: &mut Block128) {
                unsafe {
                    let b = vld1q_u8(block.as_ptr() as *const uint8x16_t);
                    let b = self.decrypt(b);
                    vst1q_u8(block.as_mut_ptr() as *mut uint8x16_t, b);
                }
            }

            fn encrypt_blocks(&self, blocks: &mut Block128x8) {
                unsafe {
                    let b = self.encrypt8(blocks);
                    store8!(blocks, b);
                }
            }

            fn decrypt_blocks(&self, blocks: &mut Block128x8) {
                unsafe {
                    let b = self.decrypt8(blocks);
                    store8!(blocks, b);
                }
            }
        }

        impl_opaque_debug!($name);
    };
}

define_aes_impl!(Aes128, U16, 11, U11, "AES-128 block cipher instance");
define_aes_impl!(Aes192, U24, 13, U13, "AES-192 block cipher instance");
define_aes_impl!(Aes256, U32, 15, U15, "AES-256 block cipher instance");
