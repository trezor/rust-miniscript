// SPDX-License-Identifier: CC0-1.0

//! Script Decoder
//!
//! Functionality to parse a Bitcoin Script into a `Miniscript`
//!

use core::mem;

use sync::Arc;

use crate::iter::TreeLike;
use crate::miniscript::limits::{MAX_PUBKEYS_IN_CHECKSIGADD, MAX_PUBKEYS_PER_MULTISIG};
use crate::miniscript::ScriptContext;
use crate::prelude::*;
use crate::{
    AbsLockTime, Miniscript, MiniscriptKey, RelLockTime, Threshold, ToPublicKey,
};

/// Trait for parsing keys from byte slices
pub trait ParseableKey: Sized + ToPublicKey + private::Sealed {
    /// Parse a key from slice
    fn from_slice(sl: &[u8]) -> Result<Self, KeyError>;
}

impl ParseableKey for bitcoin::PublicKey {
    fn from_slice(sl: &[u8]) -> Result<Self, KeyError> {
        bitcoin::PublicKey::from_slice(sl).map_err(KeyError::Full)
    }
}

impl ParseableKey for bitcoin::secp256k1::XOnlyPublicKey {
    fn from_slice(sl: &[u8]) -> Result<Self, KeyError> {
        bitcoin::secp256k1::XOnlyPublicKey::from_slice(sl).map_err(KeyError::XOnly)
    }
}

/// Private Mod to prevent downstream from implementing this public trait
mod private {

    pub trait Sealed {}

    // Implement for those same types, but no others.
    impl Sealed for bitcoin::PublicKey {}
    impl Sealed for bitcoin::secp256k1::XOnlyPublicKey {}
}

/// All AST elements.
///
/// This variant is the inner Miniscript variant that allows the user to bypass some of the
/// miniscript rules. You should *never* construct `Terminal` directly. This is only exposed to
/// external users to allow matching on the [`Miniscript`].
///
/// The average user should always use the [`Descriptor`] APIs. Advanced users who want deal
/// with Miniscript ASTs should use the [`Miniscript`] APIs.
pub enum Terminal<Pk: MiniscriptKey, Ctx: ScriptContext> {
    /// `1`
    True,
    /// `0`
    False,
    // pubkey checks
    /// `<key>`
    PkK(Pk),
    /// `DUP HASH160 <keyhash> EQUALVERIFY`
    PkH(Pk),
    // timelocks
    /// `n CHECKLOCKTIMEVERIFY`
    After(AbsLockTime),
    /// `n CHECKSEQUENCEVERIFY`
    Older(RelLockTime),
    // Wrappers
    /// `TOALTSTACK [E] FROMALTSTACK`
    Alt(Arc<Miniscript<Pk, Ctx>>),
    /// `SWAP [E1]`
    Swap(Arc<Miniscript<Pk, Ctx>>),
    /// `[Kt]/[Ke] CHECKSIG`
    Check(Arc<Miniscript<Pk, Ctx>>),
    /// `DUP IF [V] ENDIF`
    DupIf(Arc<Miniscript<Pk, Ctx>>),
    /// `[T] VERIFY`
    Verify(Arc<Miniscript<Pk, Ctx>>),
    /// `SIZE 0NOTEQUAL IF [Fn] ENDIF`
    NonZero(Arc<Miniscript<Pk, Ctx>>),
    /// `[X] 0NOTEQUAL`
    ZeroNotEqual(Arc<Miniscript<Pk, Ctx>>),
    // Conjunctions
    /// `[V] [T]/[V]/[F]/[Kt]`
    AndV(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// `[E] [W] BOOLAND`
    AndB(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// `[various] NOTIF [various] ELSE [various] ENDIF`
    AndOr(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    // Disjunctions
    /// `[E] [W] BOOLOR`
    OrB(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// `[E] IFDUP NOTIF [T]/[E] ENDIF`
    OrD(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// `[E] NOTIF [V] ENDIF`
    OrC(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// `IF [various] ELSE [various] ENDIF`
    OrI(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    // Thresholds
    /// `[E] ([W] ADD)* k EQUAL`
    Thresh(Threshold<Arc<Miniscript<Pk, Ctx>>, 0>),
    /// `k (<key>)* n CHECKMULTISIG`
    Multi(Threshold<Pk, MAX_PUBKEYS_PER_MULTISIG>),
    /// `<key> CHECKSIG (<key> CHECKSIGADD)*(n-1) k NUMEQUAL`
    MultiA(Threshold<Pk, MAX_PUBKEYS_IN_CHECKSIGADD>),
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Clone for Terminal<Pk, Ctx> {
    /// We implement clone as a "deep clone" which reconstructs the entire tree.
    ///
    /// If users just want to clone Arcs they can use Arc::clone themselves.
    fn clone(&self) -> Self {
        match self {
            Terminal::PkK(ref p) => Terminal::PkK(p.clone()),
            Terminal::PkH(ref p) => Terminal::PkH(p.clone()),
            Terminal::After(ref n) => Terminal::After(*n),
            Terminal::Older(ref n) => Terminal::Older(*n),
            Terminal::True => Terminal::True,
            Terminal::False => Terminal::False,
            Terminal::Alt(ref sub) => Terminal::Alt(Arc::new(Miniscript::clone(sub))),
            Terminal::Swap(ref sub) => Terminal::Swap(Arc::new(Miniscript::clone(sub))),
            Terminal::Check(ref sub) => Terminal::Check(Arc::new(Miniscript::clone(sub))),
            Terminal::DupIf(ref sub) => Terminal::DupIf(Arc::new(Miniscript::clone(sub))),
            Terminal::Verify(ref sub) => Terminal::Verify(Arc::new(Miniscript::clone(sub))),
            Terminal::NonZero(ref sub) => Terminal::NonZero(Arc::new(Miniscript::clone(sub))),
            Terminal::ZeroNotEqual(ref sub) => {
                Terminal::ZeroNotEqual(Arc::new(Miniscript::clone(sub)))
            }
            Terminal::AndV(ref left, ref right) => Terminal::AndV(
                Arc::new(Miniscript::clone(left)),
                Arc::new(Miniscript::clone(right)),
            ),
            Terminal::AndB(ref left, ref right) => Terminal::AndB(
                Arc::new(Miniscript::clone(left)),
                Arc::new(Miniscript::clone(right)),
            ),
            Terminal::AndOr(ref a, ref b, ref c) => Terminal::AndOr(
                Arc::new(Miniscript::clone(a)),
                Arc::new(Miniscript::clone(b)),
                Arc::new(Miniscript::clone(c)),
            ),
            Terminal::OrB(ref left, ref right) => {
                Terminal::OrB(Arc::new(Miniscript::clone(left)), Arc::new(Miniscript::clone(right)))
            }
            Terminal::OrD(ref left, ref right) => {
                Terminal::OrD(Arc::new(Miniscript::clone(left)), Arc::new(Miniscript::clone(right)))
            }
            Terminal::OrC(ref left, ref right) => {
                Terminal::OrC(Arc::new(Miniscript::clone(left)), Arc::new(Miniscript::clone(right)))
            }
            Terminal::OrI(ref left, ref right) => {
                Terminal::OrI(Arc::new(Miniscript::clone(left)), Arc::new(Miniscript::clone(right)))
            }
            Terminal::Thresh(ref thresh) => {
                Terminal::Thresh(thresh.map_ref(|child| Arc::new(Miniscript::clone(child))))
            }
            Terminal::Multi(ref thresh) => Terminal::Multi(thresh.clone()),
            Terminal::MultiA(ref thresh) => Terminal::MultiA(thresh.clone()),
        }
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> PartialEq for Terminal<Pk, Ctx> {
    fn eq(&self, other: &Self) -> bool {
        for (me, you) in self.pre_order_iter().zip(other.pre_order_iter()) {
            match (me, you) {
                (Terminal::PkK(key1), Terminal::PkK(key2)) if key1 != key2 => return false,
                (Terminal::PkH(key1), Terminal::PkH(key2)) if key1 != key2 => return false,
                (Terminal::After(t1), Terminal::After(t2)) if t1 != t2 => return false,
                (Terminal::Older(t1), Terminal::Older(t2)) if t1 != t2 => return false,
                (Terminal::Multi(th1), Terminal::Multi(th2)) if th1 != th2 => return false,
                (Terminal::MultiA(th1), Terminal::MultiA(th2)) if th1 != th2 => return false,
                _ => {
                    if mem::discriminant(me) != mem::discriminant(you) {
                        return false;
                    }
                }
            }
        }
        true
    }
}
impl<Pk: MiniscriptKey, Ctx: ScriptContext> Eq for Terminal<Pk, Ctx> {}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> core::hash::Hash for Terminal<Pk, Ctx> {
    fn hash<H: core::hash::Hasher>(&self, hasher: &mut H) {
        for term in self.pre_order_iter() {
            mem::discriminant(term).hash(hasher);
            match term {
                Terminal::PkK(key) => key.hash(hasher),
                Terminal::PkH(key) => key.hash(hasher),
                Terminal::After(t) => t.hash(hasher),
                Terminal::Older(t) => t.hash(hasher),
                Terminal::Thresh(th) => {
                    th.k().hash(hasher);
                    th.n().hash(hasher);
                    // The actual children will be hashed when we iterate
                }
                Terminal::Multi(th) => th.hash(hasher),
                Terminal::MultiA(th) => th.hash(hasher),
                _ => {}
            }
        }
    }
}

/// Decoding error while parsing keys
#[derive(Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Bitcoin PublicKey parse error
    Full(bitcoin::key::FromSliceError),
    /// Xonly key parse Error
    XOnly(bitcoin::secp256k1::Error),
}
