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

use core::{hash, str};

use bitcoin::hashes::{hash160, Hash};

pub use crate::blanket_traits::FromStrKey;
pub use crate::error::ParseError;
pub use crate::expression::{ParseNumError, ParseThresholdError, ParseTreeError};
pub use crate::miniscript::analyzable::{AnalysisError, ExtParams};
pub use crate::miniscript::context::{ScriptContext, Segwitv0, SigType, Tap};
pub use crate::miniscript::decode::Terminal;
pub use crate::miniscript::{hash256, Miniscript};
use crate::prelude::*;
pub use crate::primitives::absolute_locktime::{AbsLockTime, AbsLockTimeError};
pub use crate::primitives::relative_locktime::{RelLockTime, RelLockTimeError};
pub use crate::primitives::threshold::{Threshold, ThresholdError};

/// Public key trait which can be converted to Hash type
pub trait MiniscriptKey: Clone + Eq + Ord + hash::Hash {
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

impl MiniscriptKey for bitcoin::secp256k1::PublicKey {
}

impl MiniscriptKey for bitcoin::PublicKey {
    /// Returns the compressed-ness of the underlying secp256k1 key.
    fn is_uncompressed(&self) -> bool { !self.compressed }
}

impl MiniscriptKey for bitcoin::secp256k1::XOnlyPublicKey {
    fn is_x_only_key(&self) -> bool { true }
}

impl MiniscriptKey for String {
}

/// Trait describing public key types which can be converted to bitcoin pubkeys
pub trait ToPublicKey: MiniscriptKey {
    /// Converts an object to a public key
    fn to_public_key(&self) -> bitcoin::PublicKey;

    /// Convert an object to x-only pubkey
    fn to_x_only_pubkey(&self) -> bitcoin::secp256k1::XOnlyPublicKey {
        let pk = self.to_public_key();
        bitcoin::secp256k1::XOnlyPublicKey::from(pk.inner)
    }

    /// Obtain the public key hash for this MiniscriptKey
    /// Expects an argument to specify the signature type.
    /// This would determine whether to serialize the key as 32 byte x-only pubkey
    /// or regular public key when computing the hash160
    fn to_pubkeyhash(&self, sig_type: SigType) -> hash160::Hash {
        match sig_type {
            SigType::Ecdsa => hash160::Hash::hash(&self.to_public_key().to_bytes()),
            SigType::Schnorr => hash160::Hash::hash(&self.to_x_only_pubkey().serialize()),
        }
    }
}

impl ToPublicKey for bitcoin::PublicKey {
    fn to_public_key(&self) -> bitcoin::PublicKey { *self }
}

impl ToPublicKey for bitcoin::secp256k1::XOnlyPublicKey {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        // This code should never be used.
        // But is implemented for completeness
        let mut data: Vec<u8> = vec![0x02];
        data.extend(self.serialize().iter());
        bitcoin::PublicKey::from_slice(&data)
            .expect("Failed to construct 33 Publickey from 0x02 appended x-only key")
    }

    fn to_x_only_pubkey(&self) -> bitcoin::secp256k1::XOnlyPublicKey { *self }
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
    /// Error when lexing a bitcoin Script.
    ScriptLexer(crate::miniscript::lex::Error),
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
    /// Could not satisfy a script (fragment) because of a missing signature
    MissingSig(bitcoin::PublicKey),
    /// General failure to satisfy
    CouldNotSatisfy,
    /// Typechecking failed
    TypeCheck,
    /// Forward-secp related errors
    Secp(bitcoin::secp256k1::Error),
    /// Forward script context related errors
    ContextError(miniscript::context::ScriptContextError),
    /// Tried to construct a Taproot tree which was too deep.
    TapTreeDepthError(crate::descriptor::TapTreeDepthError),
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
    /// PubKey invalid under current context
    PubKeyCtxError(miniscript::decode::KeyError, &'static str),
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
impl From<miniscript::lex::Error> for Error {
    fn from(e: miniscript::lex::Error) -> Error { Error::ScriptLexer(e) }
}

#[doc(hidden)]
impl From<miniscript::types::Error> for Error {
    fn from(_e: miniscript::types::Error) -> Error { Error::TypeCheck }
}

#[doc(hidden)]
impl From<crate::descriptor::TapTreeDepthError> for Error {
    fn from(e: crate::descriptor::TapTreeDepthError) -> Error { Error::TapTreeDepthError(e) }
}

#[doc(hidden)]
impl From<miniscript::context::ScriptContextError> for Error {
    fn from(e: miniscript::context::ScriptContextError) -> Error { Error::ContextError(e) }
}

#[doc(hidden)]
impl From<miniscript::analyzable::AnalysisError> for Error {
    fn from(e: miniscript::analyzable::AnalysisError) -> Error { Error::AnalysisError(e) }
}

#[doc(hidden)]
impl From<bitcoin::secp256k1::Error> for Error {
    fn from(e: bitcoin::secp256k1::Error) -> Error { Error::Secp(e) }
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

    // Mutex implementation from LDK
    // https://github.com/lightningdevkit/rust-lightning/blob/9bdce47f0e0516e37c89c09f1975dfc06b5870b1/lightning-invoice/src/sync.rs
    mod mutex {
        use core::cell::{RefCell, RefMut};
        use core::ops::{Deref, DerefMut};

        pub type LockResult<Guard> = Result<Guard, ()>;

        /// `Mutex` is not a real mutex as it cannot be used in a multi-threaded
        /// context. `Mutex` is a dummy implementation of [`std::sync::Mutex`]
        /// for `no_std` environments.
        pub struct Mutex<T: ?Sized> {
            inner: RefCell<T>,
        }

        #[must_use = "if unused the Mutex will immediately unlock"]
        pub struct MutexGuard<'a, T: ?Sized + 'a> {
            lock: RefMut<'a, T>,
        }

        impl<T: ?Sized> Deref for MutexGuard<'_, T> {
            type Target = T;

            fn deref(&self) -> &T { self.lock.deref() }
        }

        impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
            fn deref_mut(&mut self) -> &mut T { self.lock.deref_mut() }
        }

        impl<T> Mutex<T> {
            pub fn new(inner: T) -> Mutex<T> { Mutex { inner: RefCell::new(inner) } }

            pub fn lock(&self) -> LockResult<MutexGuard<'_, T>> {
                Ok(MutexGuard { lock: self.inner.borrow_mut() })
            }
        }
    }

    pub use mutex::Mutex;

}
