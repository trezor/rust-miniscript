// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Miniscript and Output Descriptors
//!
//! ## Bitcoin Script
//!
//! In Bitcoin, spending policies are defined and enforced by means of a
//! stack-based programming language known as Bitcoin Script. While this
//! language appears to be designed with tractable analysis in mind (e.g.
//! there are no looping or jumping constructions), in practice this is
//! extremely difficult. As a result, typical wallet software supports only
//! a small set of script templates, cannot interoperate with other similar
//! software, and each wallet contains independently written ad-hoc manually
//! verified code to handle these templates. Users who require more complex
//! spending policies, or who want to combine signing infrastructure which
//! was not explicitly designed to work together, are simply out of luck.
//!
//! ## Miniscript
//!
//! Miniscript is an alternative to Bitcoin Script which eliminates these
//! problems. It can be efficiently and simply encoded as Script to ensure
//! that it works on the Bitcoin blockchain, but its design is very different.
//! Essentially, a Miniscript is a monotone function (tree of ANDs, ORs and
//! thresholds) of signature requirements, hash preimage requirements, and
//! timelocks.
//!
//! A [full description of Miniscript is available here](https://bitcoin.sipa.be/miniscript).
//!
//! Miniscript also admits a more human-readable encoding.
//!
//! ## Output Descriptors
//!
//! While spending policies in Bitcoin are entirely defined by Script; there
//! are multiple ways of embedding these Scripts in transaction outputs; for
//! example, P2SH or Segwit v0. These different embeddings are expressed by
//! *Output Descriptors*, [which are described here](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md).

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// Experimental features we need.
#![cfg_attr(bench, feature(test))]
// Coding conventions
#![warn(missing_docs)]
#![deny(unsafe_code)]
// Clippy lints that we have disabled
#![allow(clippy::iter_kv_map)] // https://github.com/rust-lang/rust-clippy/issues/11752
#![allow(clippy::manual_range_contains)] // I hate this lint -asp
#![allow(unexpected_cfgs)] // This one is just batshit.

#[cfg(target_pointer_width = "16")]
compile_error!(
    "rust-miniscript currently only supports architectures with pointers wider than 16 bits"
);

pub use bitcoin;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

mod blanket_traits;
pub mod descriptor;
mod error;
pub mod expression;
pub mod iter;
pub mod miniscript;
mod primitives;

mod util;

pub use crate::blanket_traits::FromStrKey;
pub use crate::error::ParseError;
pub use crate::expression::{ParseNumError, ParseThresholdError, ParseTreeError};
pub use crate::miniscript::analyzable::{AnalysisError, ExtParams};
pub use crate::miniscript::context::{ScriptContext, Segwitv0, SigType, Tap};
pub use crate::miniscript::decode::Terminal;
pub use crate::miniscript::Miniscript;
use crate::prelude::*;
pub use crate::primitives::absolute_locktime::{AbsLockTime, AbsLockTimeError};
pub use crate::primitives::relative_locktime::{RelLockTime, RelLockTimeError};
pub use crate::primitives::threshold::{Threshold, ThresholdError};

/// Public key trait which can be converted to Hash type
pub trait MiniscriptKey: Clone + Eq {
    /// Returns true if the pubkey is uncompressed. Defaults to `false`.
    fn is_uncompressed(&self) -> bool { false }

    /// Returns true if the pubkey is an x-only pubkey. Defaults to `false`.
    // This is required to know what in DescriptorPublicKey to know whether the inner
    // key in allowed in descriptor context
    fn is_x_only_key(&self) -> bool { false }

    /// Returns the number of different derivation paths in this key. Only >1 for keys
    /// in BIP389 multipath descriptors.
    fn num_der_paths(&self) -> usize { 0 }
}

impl MiniscriptKey for SerializedPublicKey {
}

impl MiniscriptKey for SerializedXOnlyPublicKey {
    fn is_x_only_key(&self) -> bool { true }
}

impl MiniscriptKey for String {
}

/// Compressed public key
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SerializedPublicKey([u8; 33]);

impl SerializedPublicKey {
    /// Create a new serialized public key.
    pub fn new(data: [u8; 33]) -> Self { Self(data) }
    
    /// Returns the serialized public key
    pub fn as_bytes(&self) -> [u8; 33] { self.0 }
}

/// X-only public key
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SerializedXOnlyPublicKey([u8; 32]);

impl SerializedXOnlyPublicKey {
    /// Returns the serialized x-only key
    pub fn as_bytes(&self) -> [u8; 32] { self.0 }
}
/// Trait describing public key types which can be converted to bitcoin pubkeys
pub trait ToPublicKey: MiniscriptKey {
    /// Converts an object to a public key
    fn to_public_key(&self) -> SerializedPublicKey;

    /// Convert an object to x-only pubkey
    fn to_x_only_pubkey(&self) -> SerializedXOnlyPublicKey {
        let pk = self.to_public_key();
        SerializedXOnlyPublicKey(pk.0[1..].try_into().unwrap())
    }
}

impl ToPublicKey for SerializedPublicKey {
    fn to_public_key(&self) -> SerializedPublicKey { *self }
}

impl ToPublicKey for SerializedXOnlyPublicKey {
    fn to_public_key(&self) -> SerializedPublicKey { unreachable!() }
    fn to_x_only_pubkey(&self) -> SerializedXOnlyPublicKey { *self }
}

/// Describes an object that can translate various keys and hashes from one key to the type
/// associated with the other key. Used by the [`TranslatePk`] trait to do the actual translations.
pub trait Translator<P: MiniscriptKey> {
    /// The public key (and associated hash types that this translator converts to.
    type TargetPk: MiniscriptKey;
    /// An error that may occur during translation.
    type Error;

    /// Translates keys.
    fn pk(&mut self, pk: &P) -> Result<Self::TargetPk, Self::Error>;
}

/// An enum for representing translation errors
pub enum TranslateErr<E> {
    /// Error inside in the underlying key translation
    TranslatorErr(E),
    /// Error in the final translated structure. In some cases, the translated
    /// structure might not be valid under the given context. For example, translating
    /// from string keys to x-only keys in wsh descriptors.
    OuterError(Error),
}

impl TranslateErr<core::convert::Infallible> {
    /// Remove the impossible "translator error" case and return a context error.
    ///
    /// When the translator error type is [`core::convert::Infallible`], which is
    /// impossible to construct, allows unwrapping the outer error without any
    /// panic paths.
    pub fn into_outer_err(self) -> Error {
        match self {
            Self::TranslatorErr(impossible) => match impossible {},
            Self::OuterError(e) => e,
        }
    }
}

impl TranslateErr<Error> {
    /// If we are doing a translation where our "outer error" is the generic
    /// Miniscript error, eliminate the `TranslateErr` type which is just noise.
    pub fn flatten(self) -> Error {
        match self {
            Self::TranslatorErr(e) => e,
            Self::OuterError(e) => e,
        }
    }
}

impl<E> From<E> for TranslateErr<E> {
    fn from(v: E) -> Self { Self::TranslatorErr(v) }
}

// Required for unwrap
/// Converts a descriptor using abstract keys to one using specific keys. Uses translator `t` to do
/// the actual translation function calls.
#[deprecated(since = "TBD", note = "This trait no longer needs to be imported.")]
pub trait TranslatePk<P, Q>
where
    P: MiniscriptKey,
    Q: MiniscriptKey,
{
}

/// Trait describing the ability to iterate over every key
pub trait ForEachKey<Pk: MiniscriptKey> {
    /// Run a predicate on every key in the descriptor, returning whether
    /// the predicate returned true for every key
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, pred: F) -> bool
    where
        Pk: 'a;

    /// Run a predicate on every key in the descriptor, returning whether
    /// the predicate returned true for any key
    fn for_any_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, mut pred: F) -> bool
    where
        Pk: 'a,
    {
        !self.for_each_key(|key| !pred(key))
    }
}

/// Miniscript

pub enum Error {
    /// While parsing backward, hit beginning of script
    UnexpectedStart,
    /// Got something we were not expecting
    Unexpected,
    /// Encountered a wrapping character that we don't recognize
    UnknownWrapper(char),
    /// Parsed a miniscript and the result was not of type T
    NonTopLevel,
    /// Parsed a miniscript but there were more script opcodes after it
    Trailing,
    /// General failure to satisfy
    CouldNotSatisfy,
    /// Typechecking failed
    TypeCheck,
    /// Forward script context related errors
    ContextError(miniscript::context::ScriptContextError),
    /// Recursion depth exceeded when parsing policy/miniscript from string
    MaxRecursiveDepthExceeded,
    /// Anything but c:pk(key) (P2PK), c:pk_h(key) (P2PKH), and thresh_m(k,...)
    /// up to n=3 is invalid by standardness (bare)
    NonStandardBareScript,
    /// Analysis Error
    AnalysisError(miniscript::analyzable::AnalysisError),
    /// Miniscript is equivalent to false. No possible satisfaction
    ImpossibleSatisfaction,
    /// Bare descriptors don't have any addresses
    BareDescriptorAddr,
    /// No script code for Tr descriptors
    TrNoScriptCode,
    /// At least two BIP389 key expressions in the descriptor contain tuples of
    /// derivation indexes of different lengths.
    MultipathDescLenMismatch,
    /// Invalid absolute locktime
    AbsoluteLockTime(AbsLockTimeError),
    /// Invalid absolute locktime
    RelativeLockTime(RelLockTimeError),
    /// Invalid threshold.
    Threshold(ThresholdError),
    /// Invalid threshold.
    ParseThreshold(ParseThresholdError),
    /// Invalid expression tree.
    Parse(ParseError),
}

#[doc(hidden)] // will be removed when we remove Error
impl From<ParseThresholdError> for Error {
    fn from(e: ParseThresholdError) -> Self { Self::ParseThreshold(e) }
}

// https://github.com/sipa/miniscript/pull/5 for discussion on this number
const MAX_RECURSION_DEPTH: u32 = 402;

#[doc(hidden)]
impl From<miniscript::types::Error> for Error {
    fn from(_e: miniscript::types::Error) -> Error { Error::TypeCheck }
}

#[doc(hidden)]
impl From<miniscript::context::ScriptContextError> for Error {
    fn from(e: miniscript::context::ScriptContextError) -> Error { Error::ContextError(e) }
}

#[doc(hidden)]
impl From<miniscript::analyzable::AnalysisError> for Error {
    fn from(e: miniscript::analyzable::AnalysisError) -> Error { Error::AnalysisError(e) }
}

/// The size of an encoding of a number in Script
pub fn script_num_size(n: usize) -> usize {
    match n {
        n if n <= 0x10 => 1,      // OP_n
        n if n < 0x80 => 2,       // OP_PUSH1 <n>
        n if n < 0x8000 => 3,     // OP_PUSH2 <n>
        n if n < 0x800000 => 4,   // OP_PUSH3 <n>
        n if n < 0x80000000 => 5, // OP_PUSH4 <n>
        _ => 6,                   // OP_PUSH5 <n>
    }
}

mod prelude {
    extern crate alloc;
    pub use alloc::{
        borrow::{ToOwned},
        boxed::Box,
        string::String,
        sync,
        vec::Vec,
    };
}
