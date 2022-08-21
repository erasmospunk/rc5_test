macro_rules! rc5_impl {
    ($cipher_name:ident, 16, $num_rounds:literal, $key_size:literal, $doc:expr) => {
        rc5_impl!(
            $cipher_name,
            u16,
            $num_rounds,
            $key_size,
            0xB7E1,
            0x9E37,
            $doc
        );
    };

    ($cipher_name:ident, 32, $num_rounds:literal, $key_size:literal, $doc:expr) => {
        rc5_impl!(
            $cipher_name,
            u32,
            $num_rounds,
            $key_size,
            0xB7E15163,
            0x9E3779B9,
            $doc
        );
    };

    ($cipher_name:ident, 64, $num_rounds:literal, $key_size:literal, $doc:expr) => {
        rc5_impl!(
            $cipher_name,
            u64,
            $num_rounds,
            $key_size,
            0xB7E151628AED2A6B,
            0x9E3779B97F4A7C15,
            $doc
        );
    };

    ($cipher_name:ident, $word_type:ty, $num_rounds:literal, $key_size:literal, $p_value:literal,
    $q_value:literal, $doc:expr) => {
        #[allow(non_snake_case)]
        pub mod $cipher_name {
            use std::cmp::max;
            use std::convert::TryInto;

            pub fn setup(key: Vec<u8>) -> $cipher_name {
                $cipher_name::setup(key)
            }

            /// Word type
            type Word = $word_type;
            /// Word size in bytes
            const W_BYTES: usize = std::mem::size_of::<Word>();
            /// Word size in bits
            const W: Word = W_BYTES as Word * 8;
            /// Number of rounds
            const R: usize = $num_rounds;
            /// Number of bytes in key
            const B: usize = $key_size;
            /// Number  words in key, ceil( key_bytes_num / word_bytes_num)
            const C: usize = (B / W_BYTES) + if (B % W_BYTES) != 0 { 1 } else { 0 };
            /// Size of table S = 2*(R+1) words
            const T: usize = 2 * (R + 1);
            /// Magic constant P
            const P: Word = $p_value;
            /// Magic constant Q
            const Q: Word = $q_value;

            #[allow(non_camel_case_types)]
            #[derive(Clone, Default)]
            #[doc=$doc]
            pub struct $cipher_name {
                /// Expanded key table
                // TODO wrap in secrecy::Secret to avoid leaving copies in memory
                s_table: Vec<Word>,
            }

            impl $cipher_name {
                /// Left rotation
                fn rotl(x: Word, y: Word) -> Word {
                    x.wrapping_shl((y & (W - 1)) as u32)
                        | x.wrapping_shr((W - (y & (W - 1))) as u32)
                }

                /// Right rotation
                fn rotr(x: Word, y: Word) -> Word {
                    x.wrapping_shr((y & (W - 1)) as u32)
                        | x.wrapping_shl((W - (y & (W - 1))) as u32)
                }

                /// Setup this cipher using a key
                pub fn setup(key: Vec<u8>) -> Self {
                    assert_eq!(key.len(), B, "Wrong key size for algorithm");

                    let mut state = $cipher_name::default();

                    /* Initialize L, then S, then mix key into S */
                    #[allow(non_snake_case)]
                    let mut L: Vec<Word> = vec![0; C];
                    for (i, key_byte) in key.iter().enumerate().rev() {
                        L[i / W_BYTES] = (L[i / W_BYTES] << 8).wrapping_add(*key_byte as Word);
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
        }
    };
}
