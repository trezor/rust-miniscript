// SPDX-License-Identifier: CC0-1.0

//! # Output Descriptors
//!
//! Tools for representing Bitcoin output's scriptPubKeys as abstract spending
//! policies known as "output descriptors". These include a Miniscript which
//! describes the actual signing policy, as well as the blockchain format (P2SH,
//! Segwit v0, etc.)
//!
//! The format represents EC public keys abstractly to allow wallets to replace
//! these with BIP32 paths, pay-to-contract instructions, etc.
//!



mod segwitv0;
mod sortedmulti;

// Descriptor Exports
pub use self::segwitv0::{Wsh, WshInner};
pub use self::sortedmulti::SortedMultiVec;

pub mod checksum;
