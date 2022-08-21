//! An Rust port of the C reference RC5 cipher implementation
//!
//! # Usage
//!
//! To use a cipher like the Rc5_32_12_16:
//!
//! ```rust
//! // Some test vectors
//! extern crate rc5_test;
//! use rc5_test::Rc5_32_12_16;
//!
//! let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
//! let pt  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
//! let ct  = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
//!
//! // Setup the cipher
//! let cipher = Rc5_32_12_16::setup(key);
//!
//! // Encrypt
//! let mut encrypted = Vec::new();
//! cipher.encrypt(&pt, &mut encrypted);
//! assert_eq!(&ct[..], &encrypted[..]);
//!
//! // Decrypt
//! let mut decrypted = Vec::new();
//! cipher.decrypt(&encrypted, &mut decrypted);
//! assert_eq!(&pt[..], &decrypted[..]);
//! ```
//!

use std::cmp::max;
use std::convert::TryInto;

/// Word type
type Word = u32;
/// Word size in bytes
const W_BYTES: usize = std::mem::size_of::<Word>();
/// Word size in bits
const W: Word = W_BYTES as Word * 8;
/// Number of rounds
const R: usize = 12;
/// Number of bytes in key
const B: usize = 16;
/// Number  words in key, ceil( key_bytes_num / word_bytes_num)
const C: usize = (B / W_BYTES) + if (B % W_BYTES) != 0 { 1 } else { 0 };
/// Size of table S = 2*(R+1) words
const T: usize = 2 * (R + 1);
/// Magic constant P
const P: Word = 0xb7e15163;
/// Magic constant Q
const Q: Word = 0x9e3779b9;

#[derive(Clone, Default)]
pub struct Rc5_32_12_16 {
    /// Expanded key table
    s_table: Vec<Word>, // TODO wrap in secrecy::Secret to avoid leaving copies in memory
}

impl Rc5_32_12_16 {
    /// Left rotation
    fn rotl(x: Word, y: Word) -> Word {
        x.wrapping_shl((y & (W - 1)) as u32) | x.wrapping_shr((W - (y & (W - 1))) as u32)
    }

    /// Right rotation
    fn rotr(x: Word, y: Word) -> Word {
        x.wrapping_shr((y & (W - 1)) as u32) | x.wrapping_shl((W - (y & (W - 1))) as u32)
    }

    /// Setup this cipher using a key
    pub fn setup(key: Vec<u8>) -> Self {
        assert_eq!(key.len(), B, "Wrong key size for algorithm");

        let mut state = Rc5_32_12_16::default();

        /* Initialize L, then S, then mix key into S */
        #[allow(non_snake_case)]
        let mut L: Vec<Word> = vec![0; C];
        for (i, key_byte) in key.iter().enumerate().rev() {
            L[i / W_BYTES] = (L[i / W_BYTES] << 8).wrapping_add(*key_byte as u32);
        }

        let mut last_s_value = P;
        state.s_table.push(last_s_value);
        for _ in 1..T {
            last_s_value = last_s_value.wrapping_add(Q);
            state.s_table.push(last_s_value);
        }

        let (mut a, mut b, mut i, mut j) = (0 as Word, 0 as Word, 0, 0);
        for _ in 0..3 * max(T, C) {
            a = Self::rotl(state.s_table[i].wrapping_add(a.wrapping_add(b)), 3);
            state.s_table[i] = a;

            let ab = a.wrapping_add(b);
            b = Self::rotl(L[j].wrapping_add(ab), ab);
            L[j] = b;

            i = (i + 1) % T;
            j = (j + 1) % C;
        }

        state
    }

    /// Converts a byte block to words
    fn convert_to_words(block: &[u8]) -> (Word, Word) {
        // Convert bytes to words
        (
            Word::from_le_bytes(block[..W_BYTES].try_into().unwrap()),
            Word::from_le_bytes(block[W_BYTES..].try_into().unwrap()),
        )
    }

    /// Writes words to a byte block
    fn convert_from_words(words: (Word, Word), block: &mut Vec<u8>) {
        block.clear();
        block.extend_from_slice(&Word::to_le_bytes(words.0));
        block.extend_from_slice(&Word::to_le_bytes(words.1));
    }

    /// This function returns a ciphertext given a plaintext.
    ///
    /// # Panics
    ///
    /// Panics if `plaintext.len() != W_DOUBLE_BYTES`
    ///
    pub fn encrypt(&self, plaintext: &[u8], ciphertext: &mut Vec<u8>) {
        let pt_words = Self::convert_to_words(plaintext);

        // Perform the encryption
        let mut a = pt_words.0.wrapping_add(self.s_table[0]);
        let mut b = pt_words.1.wrapping_add(self.s_table[1]);
        for i in 1..=R {
            a = Self::rotl(a ^ b, b).wrapping_add(self.s_table[2 * i]);
            b = Self::rotl(b ^ a, a).wrapping_add(self.s_table[2 * i + 1]);
        }

        // Convert words to bytes
        Self::convert_from_words((a, b), ciphertext);
    }

    /// This function returns a plaintext given a ciphertext.
    ///
    /// # Panics
    ///
    /// Panics if `ciphertext.len() != W_DOUBLE_BYTES`.
    ///
    pub fn decrypt(&self, ciphertext: &[u8], plaintext: &mut Vec<u8>) {
        let ct_words = Self::convert_to_words(ciphertext);

        // Perform the decryption
        let mut b = ct_words.1;
        let mut a = ct_words.0;
        for i in (1..=R).rev() {
            b = Self::rotr(b.wrapping_sub(self.s_table[2 * i + 1]), a) ^ a;
            a = Self::rotr(a.wrapping_sub(self.s_table[2 * i]), b) ^ b;
        }
        b = b.wrapping_sub(self.s_table[1]);
        a = a.wrapping_sub(self.s_table[0]);

        // Convert words to bytes
        Self::convert_from_words((a, b), plaintext);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_rc5_32_12_16_a() {
        let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let pt  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct  = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        let cipher = Rc5_32_12_16::setup(key);
        let mut res = Vec::with_capacity(pt.len());
        cipher.encrypt(&pt, &mut res);
        assert_eq!(&ct[..], &res[..]);
    }

    #[test]
    fn encode_rc5_32_12_16_b() {
        let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
        let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct  = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let cipher = Rc5_32_12_16::setup(key);
        let mut res = Vec::with_capacity(pt.len());
        cipher.encrypt(&pt, &mut res);
        assert_eq!(&ct[..], &res[..]);
    }

    #[test]
    fn decode_rc5_32_12_16_a() {
        let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let pt  = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let cipher = Rc5_32_12_16::setup(key);
        let mut res = Vec::with_capacity(pt.len());
        cipher.decrypt(&ct, &mut res);
        assert_eq!(&pt[..], &res[..]);
    }

    #[test]
    fn decode_rc5_32_12_16_b() {
        let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
        let pt  = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let cipher = Rc5_32_12_16::setup(key);
        let mut res = Vec::with_capacity(pt.len());
        cipher.decrypt(&ct, &mut res);
        assert_eq!(&pt[..], &res[..]);
    }
}
