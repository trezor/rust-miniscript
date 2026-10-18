// SPDX-License-Identifier: CC0-1.0

//! Descriptor checksum

/// Error validating descriptor checksum.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Error {
    /// Character outside of descriptor charset.
    InvalidCharacter {
        /// The character in question.
        ch: char,
        /// Its position in the string.
        pos: usize,
    },
}

/// Helper function for `FromStr` for various descriptor types.
/// NOTE: Checksum support was dropped (to remove bech32 dependency).
pub fn verify_ascii(s: &str) -> Result<&str, Error> {
    for (pos, ch) in s.char_indices() {
        if !(32..127).contains(&u32::from(ch)) || ch == '#' {
            return Err(Error::InvalidCharacter { ch, pos });
        }
    }
    // After this point we know we have ASCII and can stop using character methods.
    Ok(&s)
}
