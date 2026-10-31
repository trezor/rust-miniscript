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
pub(crate) use bitcoin::key::{CompressedPublicKey, FromSliceError, PublicKey, XOnlyPublicKey};
#[cfg(feature = "secp256k1")]
pub(crate) use bitcoin::secp256k1::Error as XOnlyFromSliceError;

#[cfg(not(feature = "secp256k1"))]
pub use self::serialized::{
    FromSliceError, SerializedPublicKey, SerializedXOnlyPublicKey, XOnlyFromSliceError,
};
#[cfg(not(feature = "secp256k1"))]
pub(crate) use self::serialized::{
    SerializedPublicKey as PublicKey, SerializedPublicKey as CompressedPublicKey,
    SerializedXOnlyPublicKey as XOnlyPublicKey,
};

// The helpers below wrap the few `bitcoin` APIs used by this crate which require `secp256k1`.
//
// Note that they must not be implemented as extension traits with the same method names: if
// `bitcoin/secp256k1` is enabled by another crate (feature unification), the inherent `bitcoin`
// methods would take precedence over the extension traits.

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

/// Constructs a P2WPKH address (same as `Address::p2wpkh`).
#[cfg(feature = "secp256k1")]
pub(crate) fn p2wpkh(
    pk: &CompressedPublicKey,
    hrp: impl Into<bitcoin::address::KnownHrp>,
) -> bitcoin::Address {
    bitcoin::Address::p2wpkh(pk, hrp)
}

/// Constructs a P2WPKH address (same as `Address::p2wpkh`).
#[cfg(not(feature = "secp256k1"))]
pub(crate) fn p2wpkh(
    pk: &CompressedPublicKey,
    hrp: impl Into<bitcoin::address::KnownHrp>,
) -> bitcoin::Address {
    use bitcoin::hashes::Hash as _;
    use bitcoin::{WitnessProgram, WitnessVersion};

    let hash = pk.wpubkey_hash().to_byte_array();
    let program = WitnessProgram::new(WitnessVersion::V0, &hash)
        .expect("20-byte witness v0 program is valid");
    bitcoin::Address::from_witness_program(program, hrp)
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
        /// Invalid hex encoding.
        InvalidHex,
    }

    impl fmt::Display for FromSliceError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                Self::InvalidLength(n) => write!(f, "invalid public key length {}", n),
                Self::InvalidPrefix(b) => write!(f, "invalid public key prefix {:#04x}", b),
                Self::InvalidHex => f.write_str("invalid public key hex"),
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
        /// Invalid hex encoding.
        InvalidHex,
    }

    impl fmt::Display for XOnlyFromSliceError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                Self::InvalidLength(n) => write!(f, "invalid x-only public key length {}", n),
                Self::InvalidHex => f.write_str("invalid x-only public key hex"),
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
        type Err = FromSliceError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let data = hex::decode_to_array::<33>(s).map_err(|_| FromSliceError::InvalidHex)?;
            Self::new(data)
        }
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
        type Err = XOnlyFromSliceError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            hex::decode_to_array::<32>(s)
                .map(Self)
                .map_err(|_| XOnlyFromSliceError::InvalidHex)
        }
    }

    impl MiniscriptKey for SerializedPublicKey {
        type Sha256 = sha256::Hash;
        type Hash256 = hash256::Hash;
        type Ripemd160 = ripemd160::Hash;
        type Hash160 = hash160::Hash;
    }

    impl MiniscriptKey for SerializedXOnlyPublicKey {
        type Sha256 = sha256::Hash;
        type Hash256 = hash256::Hash;
        type Ripemd160 = ripemd160::Hash;
        type Hash160 = hash160::Hash;

        fn is_x_only_key(&self) -> bool { true }
    }

    impl ToPublicKey for SerializedPublicKey {
        fn to_public_key(&self) -> SerializedPublicKey { *self }

        fn to_sha256(hash: &sha256::Hash) -> sha256::Hash { *hash }

        fn to_hash256(hash: &hash256::Hash) -> hash256::Hash { *hash }

        fn to_ripemd160(hash: &ripemd160::Hash) -> ripemd160::Hash { *hash }

        fn to_hash160(hash: &hash160::Hash) -> hash160::Hash { *hash }
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

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::Network;

    use super::PublicKey;
    use crate::prelude::*;
    use crate::{AnalysisError, Descriptor, Error, Translator};

    // These tests run both with and without `secp256k1`, checking that the resulting
    // scripts and addresses are the same in both configurations.

    const K1: &str = "020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261";
    const K2: &str = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";
    const K3: &str = "03d008a849fbf474bd17e9d2c1a827077a468150e58221582ec3410ab309f5afe4";

    fn parse(desc: &str) -> Descriptor<PublicKey> {
        let desc = desc.replace("K1", K1).replace("K2", K2).replace("K3", K3);
        let desc = Descriptor::<PublicKey>::from_str(&desc).unwrap();
        desc.sanity_check().unwrap();
        desc
    }

    fn check(desc: &str, explicit_script: &str, script_pubkey: &str, address: Option<&str>) {
        let desc = parse(desc);
        assert_eq!(format!("{:x}", desc.explicit_script().unwrap()), explicit_script);
        assert_eq!(format!("{:x}", desc.script_pubkey()), script_pubkey);
        assert_eq!(
            desc.address(Network::Bitcoin).ok().map(|a| a.to_string()),
            address.map(String::from)
        );
    }

    #[test]
    fn scripts_and_addresses() {
        check(
            "wsh(or_d(pk(K1),and_v(v:pkh(K2),older(144))))",
            "21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261ac736476a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ad029000b268",
            "0020c424f102d151e64c3aa819464f3b6499bcb241c157457c31b0a93ee440319008",
            Some("bc1qcsj0zqk328nycw4gr9ry7wmynx7tyswp2azhcvds4ylwgsp3jqyq9asdf2"),
        );
        check(
            "wsh(multi(2,K3,K1,K2))",
            "522103d008a849fbf474bd17e9d2c1a827077a468150e58221582ec3410ab309f5afe421020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261210250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b235253ae",
            "002020b25f119168eae687fd2bb2049f00a3826c0fa1a9e8e59215e73bf6573942af",
            Some("bc1qyze97yv3dr4wdpla9weqf8cq5wpxcrap485wtys4uualv4eeg2hsltl3ra"),
        );
        check(
            "wsh(sortedmulti(2,K3,K1,K2))",
            "5221020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261210250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522103d008a849fbf474bd17e9d2c1a827077a468150e58221582ec3410ab309f5afe453ae",
            "0020cd6a2d214ef47101c052cc067c3aafb916d6b84a4190ba7f7ac1f2a76bfdb210",
            Some("bc1qe44z6g2w73csrszjesr8cw40hytddwz2gxgt5lm6c8e2w6lakggq5almct"),
        );
        check(
            "sh(wsh(sortedmulti(2,K3,K1,K2)))",
            "5221020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261210250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522103d008a849fbf474bd17e9d2c1a827077a468150e58221582ec3410ab309f5afe453ae",
            "a9143eb75d04d7b7a34970458887df29b9ba07369dd287",
            Some("37QdUkFWHQxgSHYnWvYTYUwvCUt9CjzugZ"),
        );
        check(
            "sh(wsh(or_d(pk(K1),pk(K2))))",
            "21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261ac7364210250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352ac68",
            "a914747d73e24e3b21388ed0daaf55fa909d2421a9e587",
            Some("3CJxbQBfWAe1ZkKiGQNEYrioV73ZwvBWns"),
        );
        check(
            "wpkh(K1)",
            "0014ef7ef02a1783c231039fd4f88594e9268bfbf2e4",
            "0014ef7ef02a1783c231039fd4f88594e9268bfbf2e4",
            Some("bc1qaal0q2shs0przqul6nugt98fy69lhuhydwh7tw"),
        );
        check(
            "sh(wpkh(K3))",
            "0014ab0e342451d9ab9f625ffa5dfc3bd946fc1013d8",
            "a9147da68d0d43bab7f2e37a6c93485712caaeeb3b5187",
            Some("3D9PugqvdDxvfT74q8wd3jtyoDSJPfQTUS"),
        );
        check(
            "pkh(K2)",
            "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac",
            "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac",
            Some("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"),
        );
        check(
            "pk(K3)",
            "2103d008a849fbf474bd17e9d2c1a827077a468150e58221582ec3410ab309f5afe4ac",
            "2103d008a849fbf474bd17e9d2c1a827077a468150e58221582ec3410ab309f5afe4ac",
            None,
        );
    }

    /// Translates `String` keys into concrete keys (e.g. derived by an external implementation).
    struct StrPkTranslator(Vec<(&'static str, &'static str)>);

    impl Translator<String> for StrPkTranslator {
        type TargetPk = PublicKey;
        type Error = ();

        fn pk(&mut self, pk: &String) -> Result<PublicKey, ()> {
            let (_, hex) = self.0.iter().find(|(name, _)| name == pk).ok_or(())?;
            Ok(PublicKey::from_str(hex).unwrap())
        }

        translate_hash_fail!(String, PublicKey, ());
    }

    #[test]
    fn translate_string_keys() {
        let desc =
            Descriptor::<String>::from_str("wsh(or_d(pk(A),and_v(v:pkh(B),older(144))))").unwrap();
        desc.sanity_check().unwrap();

        let mut t = StrPkTranslator(vec![("A", K1), ("B", K2)]);
        let desc = desc.translate_pk(&mut t).unwrap();
        desc.sanity_check().unwrap();
        assert_eq!(desc, parse("wsh(or_d(pk(K1),and_v(v:pkh(K2),older(144))))"));

        // Unknown key
        let mut t = StrPkTranslator(vec![("A", K1)]);
        let desc = Descriptor::<String>::from_str("wsh(or_d(pk(A),pk(C)))").unwrap();
        assert!(desc.translate_pk(&mut t).is_err());
    }

    #[test]
    fn repeated_keys_after_translation() {
        // Distinct abstract keys may be translated into the same concrete key, so the
        // translated descriptor must be checked again.
        let desc = Descriptor::<String>::from_str("wsh(or_d(pk(A),pk(B)))").unwrap();
        desc.sanity_check().unwrap();

        let mut t = StrPkTranslator(vec![("A", K1), ("B", K1)]);
        let desc = desc.translate_pk(&mut t).unwrap();
        match desc.sanity_check() {
            Err(Error::AnalysisError(AnalysisError::RepeatedPubkeys)) => {}
            res => panic!("unexpected result: {:?}", res),
        }
    }

    #[test]
    #[cfg(not(feature = "secp256k1"))]
    fn serialized_public_key() {
        use super::{FromSliceError, SerializedPublicKey, SerializedXOnlyPublicKey};

        let pk = SerializedPublicKey::from_str(K3).unwrap();
        assert_eq!(pk.to_string(), K3);
        assert_eq!(format!("{:?}", pk), K3);
        assert_eq!(SerializedPublicKey::from_slice(&pk.serialize()), Ok(pk));
        assert_eq!(pk.to_bytes(), pk.serialize().to_vec());
        assert_eq!(pk.x_only().to_string(), K3[2..]);
        assert_eq!(SerializedXOnlyPublicKey::from_str(&K3[2..]).unwrap(), pk.x_only());

        let mut data = pk.serialize();
        data[0] = 0x04;
        assert_eq!(SerializedPublicKey::new(data), Err(FromSliceError::InvalidPrefix(0x04)));
        assert_eq!(
            SerializedPublicKey::from_slice(&data[..32]),
            Err(FromSliceError::InvalidLength(32))
        );
        assert_eq!(SerializedPublicKey::from_str("02"), Err(FromSliceError::InvalidHex));
        // Uncompressed keys are not supported
        assert!(SerializedPublicKey::from_str("0400232a2acfc9b43fa89f1b4f608fde335d330d7114f70ea42bfb4a41db368a3e3be6934a4097dd25728438ef73debb1f2ffdb07fec0f18049df13bdc5285dc5b").is_err());
    }
}
