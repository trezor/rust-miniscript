// SPDX-License-Identifier: CC0-1.0

//! Public key types
//!
//! This module re-exports the [`bitcoin`] key types used by this crate, and wraps the few
//! [`bitcoin`] APIs that require them.
//!
//! The rest of the crate refers to `crate::pubkey::{PublicKey, XOnlyPublicKey, ...}`, so that
//! these types can be replaced when the `bitcoin/secp256k1` feature is disabled.

pub(crate) use bitcoin::key::{CompressedPublicKey, FromSliceError, PublicKey, XOnlyPublicKey};
pub(crate) use bitcoin::secp256k1::Error as XOnlyFromSliceError;

/// Converts a public key to an x-only public key (dropping the parity).
pub(crate) fn to_x_only(pk: PublicKey) -> XOnlyPublicKey { XOnlyPublicKey::from(pk.inner) }

/// Serializes a public key in the format used for sorting `sortedmulti()` keys.
pub(crate) fn sort_key(pk: &PublicKey) -> [u8; 33] { pk.inner.serialize() }

/// Pushes a public key onto the script (same as `Builder::push_key`).
pub(crate) fn push_key(
    builder: bitcoin::script::Builder,
    pk: &PublicKey,
) -> bitcoin::script::Builder {
    builder.push_key(pk)
}

/// Constructs a P2WPKH address (same as `Address::p2wpkh`).
pub(crate) fn p2wpkh(
    pk: &CompressedPublicKey,
    hrp: impl Into<bitcoin::address::KnownHrp>,
) -> bitcoin::Address {
    bitcoin::Address::p2wpkh(pk, hrp)
}
