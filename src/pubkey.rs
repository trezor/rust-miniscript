// SPDX-License-Identifier: CC0-1.0

//! Public key types
//!
//! With the `secp256k1` feature enabled (the default), this module simply re-exports the
//! [`bitcoin`] key types.
//!
//! Without it, the [`bitcoin`] key types are not available, and this module provides
//! `SerializedPublicKey` and `SerializedXOnlyPublicKey` instead. These keys are stored in
//! their serialized form and **are not validated to be points on the secp256k1 curve** (only
//! their length and prefix byte are checked). It is the caller's responsibility to only construct
//! them from valid public keys (e.g. derived using an external secp256k1 implementation).
//!
//! Only compressed (33-byte) ECDSA public keys are supported without `secp256k1`.
//!
//! The rest of the crate refers to `crate::pubkey::{PublicKey, XOnlyPublicKey, ...}`, so that it
//! compiles unmodified in both configurations.

#[cfg(feature = "secp256k1")]
pub(crate) use bitcoin::key::{FromSliceError, PublicKey, XOnlyPublicKey};
#[cfg(feature = "secp256k1")]
pub(crate) use bitcoin::secp256k1::Error as XOnlyFromSliceError;

#[cfg(not(feature = "secp256k1"))]
pub use self::serialized::{
    FromSliceError, SerializedPublicKey, SerializedXOnlyPublicKey, XOnlyFromSliceError,
};
#[cfg(not(feature = "secp256k1"))]
pub(crate) use self::serialized::{
    SerializedPublicKey as PublicKey,
    SerializedXOnlyPublicKey as XOnlyPublicKey,
};

// The helpers below wrap the few `bitcoin` APIs used by this crate which require `secp256k1`.

/// Converts a public key to an x-only public key (dropping the parity).
#[cfg(feature = "secp256k1")]
pub(crate) fn to_x_only(pk: PublicKey) -> XOnlyPublicKey { XOnlyPublicKey::from(pk.inner) }

/// Converts a public key to an x-only public key (dropping the parity).
#[cfg(not(feature = "secp256k1"))]
pub(crate) fn to_x_only(pk: PublicKey) -> XOnlyPublicKey { pk.x_only() }

/// Serializes a public key in the format used for sorting `sortedmulti()` keys.
#[cfg(feature = "secp256k1")]
pub(crate) fn sort_key(pk: &PublicKey) -> [u8; 33] { pk.inner.serialize() }

/// Serializes a public key in the format used for sorting `sortedmulti()` keys.
#[cfg(not(feature = "secp256k1"))]
pub(crate) fn sort_key(pk: &PublicKey) -> [u8; 33] { pk.serialize() }

/// Pushes a public key onto the script (same as `Builder::push_key`).
#[cfg(feature = "secp256k1")]
pub(crate) fn push_key(
    builder: bitcoin::script::Builder,
    pk: &PublicKey,
) -> bitcoin::script::Builder {
    builder.push_key(pk)
}

/// Pushes a public key onto the script (same as `Builder::push_key`).
#[cfg(not(feature = "secp256k1"))]
pub(crate) fn push_key(
    builder: bitcoin::script::Builder,
    pk: &PublicKey,
) -> bitcoin::script::Builder {
    builder.push_slice(pk.serialize())
}

#[cfg(not(feature = "secp256k1"))]
mod serialized {
use core::{fmt, str};

    use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
    use bitcoin::key::{PubkeyHash, WPubkeyHash};

    use crate::prelude::*;
    use crate::{hash256, MiniscriptKey, ToPublicKey};

    /// Error parsing a serialized public key.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum FromSliceError {
        /// Invalid length (only compressed keys are supported).
        InvalidLength(usize),
        /// Invalid prefix byte (must be `0x02` or `0x03`).
        InvalidPrefix(u8),
    }

    impl fmt::Display for FromSliceError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                Self::InvalidLength(n) => write!(f, "invalid public key length {}", n),
                Self::InvalidPrefix(b) => write!(f, "invalid public key prefix {:#04x}", b),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FromSliceError {}

    /// Error parsing a serialized x-only public key.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum XOnlyFromSliceError {
        /// Invalid length (must be 32 bytes).
        InvalidLength(usize),
    }

    impl fmt::Display for XOnlyFromSliceError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                Self::InvalidLength(n) => write!(f, "invalid x-only public key length {}", n),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for XOnlyFromSliceError {}

    /// A compressed ECDSA public key, in its 33-byte serialized form.
    ///
    /// **The key is not validated to be a point on the secp256k1 curve.**
    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SerializedPublicKey([u8; 33]);

    impl SerializedPublicKey {
        /// Constructs a key from its 33-byte serialization, checking the prefix byte.
        pub fn new(data: [u8; 33]) -> Result<Self, FromSliceError> {
            match data[0] {
                0x02 | 0x03 => Ok(Self(data)),
                b => Err(FromSliceError::InvalidPrefix(b)),
            }
        }

        /// Constructs a key from a 33-byte slice, checking the prefix byte.
        pub fn from_slice(data: &[u8]) -> Result<Self, FromSliceError> {
            let data = <[u8; 33]>::try_from(data)
                .map_err(|_| FromSliceError::InvalidLength(data.len()))?;
            Self::new(data)
        }

        /// Returns the 33-byte serialization of the key.
        pub fn serialize(&self) -> [u8; 33] { self.0 }

        /// Returns the serialization of the key as a vector.
        pub fn to_bytes(self) -> Vec<u8> { self.0.to_vec() }

        /// Returns the HASH160 of the serialized key.
        pub fn pubkey_hash(&self) -> PubkeyHash { PubkeyHash::hash(&self.0) }

        /// Returns the HASH160 of the serialized key.
        pub fn wpubkey_hash(&self) -> WPubkeyHash { WPubkeyHash::hash(&self.0) }

        /// Returns the x-only key (dropping the parity).
        pub fn x_only(&self) -> SerializedXOnlyPublicKey {
            let mut data = [0u8; 32];
            data.copy_from_slice(&self.0[1..]);
            SerializedXOnlyPublicKey(data)
        }
    }

    impl From<SerializedPublicKey> for PubkeyHash {
        fn from(pk: SerializedPublicKey) -> Self { pk.pubkey_hash() }
    }

    impl fmt::Debug for SerializedPublicKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
    }

    impl fmt::Display for SerializedPublicKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            self.0.iter().try_for_each(|b| write!(f, "{:02x}", b))
        }
    }

    impl str::FromStr for SerializedPublicKey {
        type Err = ();
        /// Parsing serialized keys are not supported.
        fn from_str(_: &str) -> Result<Self, Self::Err> {
            Err(())
        }
    }

    impl MiniscriptKey for SerializedPublicKey {
        type Sha256 = sha256::Hash;
        type Hash256 = hash256::Hash;
        type Ripemd160 = ripemd160::Hash;
        type Hash160 = hash160::Hash;
    }

    impl ToPublicKey for SerializedPublicKey {
        fn to_public_key(&self) -> SerializedPublicKey { *self }

        fn to_sha256(hash: &sha256::Hash) -> sha256::Hash { *hash }

        fn to_hash256(hash: &hash256::Hash) -> hash256::Hash { *hash }

        fn to_ripemd160(hash: &ripemd160::Hash) -> ripemd160::Hash { *hash }

        fn to_hash160(hash: &hash160::Hash) -> hash160::Hash { *hash }
    }

    /// An x-only (BIP-340) public key, in its 32-byte serialized form.
    ///
    /// **The key is not validated to be a point on the secp256k1 curve.**
    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SerializedXOnlyPublicKey([u8; 32]);

    impl SerializedXOnlyPublicKey {
        /// Constructs a key from its 32-byte serialization.
        pub fn new(data: [u8; 32]) -> Self { Self(data) }

        /// Constructs a key from a 32-byte slice.
        pub fn from_slice(data: &[u8]) -> Result<Self, XOnlyFromSliceError> {
            <[u8; 32]>::try_from(data)
                .map(Self)
                .map_err(|_| XOnlyFromSliceError::InvalidLength(data.len()))
        }

        /// Returns the 32-byte serialization of the key.
        pub fn serialize(&self) -> [u8; 32] { self.0 }
    }

    impl fmt::Debug for SerializedXOnlyPublicKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
    }

    impl fmt::Display for SerializedXOnlyPublicKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            self.0.iter().try_for_each(|b| write!(f, "{:02x}", b))
        }
    }

    impl str::FromStr for SerializedXOnlyPublicKey {
        type Err = ();
        /// Parsing serialized keys are not supported.
        fn from_str(_: &str) -> Result<Self, Self::Err> {
            Err(())
        }
    }

    impl MiniscriptKey for SerializedXOnlyPublicKey {
        type Sha256 = sha256::Hash;
        type Hash256 = hash256::Hash;
        type Ripemd160 = ripemd160::Hash;
        type Hash160 = hash160::Hash;

        fn is_x_only_key(&self) -> bool { true }
    }

    impl ToPublicKey for SerializedXOnlyPublicKey {
        fn to_public_key(&self) -> SerializedPublicKey {
            // This code should never be used, but is implemented for completeness
            // (same as for `bitcoin::secp256k1::XOnlyPublicKey`).
            let mut data = [0x02; 33];
            data[1..].copy_from_slice(&self.0);
            SerializedPublicKey(data)
        }

        fn to_x_only_pubkey(&self) -> SerializedXOnlyPublicKey { *self }

        fn to_sha256(hash: &sha256::Hash) -> sha256::Hash { *hash }

        fn to_hash256(hash: &hash256::Hash) -> hash256::Hash { *hash }

        fn to_ripemd160(hash: &ripemd160::Hash) -> ripemd160::Hash { *hash }

        fn to_hash160(hash: &hash160::Hash) -> hash160::Hash { *hash }
    }
}
