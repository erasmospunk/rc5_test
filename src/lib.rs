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

#[macro_use]
mod macros;

rc5_impl!(Rc5_16_16_8, 16, 16, 8, "RC5_16_16_8 cipher");
rc5_impl!(Rc5_32_12_16, 32, 12, 16, "RC5_32_12_16 cipher");
rc5_impl!(Rc5_32_20_16, 32, 20, 16, "RC5_32_20_16 cipher");
rc5_impl!(Rc5_64_24_24, 64, 24, 24, "RC5_64_24_24 cipher");
