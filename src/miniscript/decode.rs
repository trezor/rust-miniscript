// SPDX-License-Identifier: CC0-1.0

//! Script Decoder
//!
//! Functionality to parse a Bitcoin Script into a `Miniscript`
//!

use core::mem;

use sync::Arc;

use crate::iter::TreeLike;
use crate::miniscript::lex::{Token as Tk, TokenIter};
use crate::miniscript::limits::{MAX_PUBKEYS_IN_CHECKSIGADD, MAX_PUBKEYS_PER_MULTISIG};
use crate::miniscript::ScriptContext;
use crate::prelude::*;
use crate::{
    AbsLockTime, Error, Miniscript, MiniscriptKey, RelLockTime, Threshold, ToPublicKey,
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

#[derive(Copy, Clone)]
enum NonTerm {
    Expression,
    WExpression,
    Swap,
    MaybeAndV,
    Alt,
    Check,
    DupIf,
    Verify,
    NonZero,
    ZeroNotEqual,
    AndV,
    AndB,
    Tern,
    OrB,
    OrD,
    OrC,
    ThreshW { k: usize, n: usize },
    ThreshE { k: usize, n: usize },
    // could be or_d, or_c, or_i, d:, n:
    EndIf,
    // could be or_d, or_c
    EndIfNotIf,
    // could be or_i or tern
    EndIfElse,
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

macro_rules! match_token {
    // Base case
    ($tokens:expr => $sub:expr,) => { $sub };
    // Recursive case
    ($tokens:expr, $($first:pat $(,$rest:pat)* => $sub:expr,)*) => {
        match $tokens.next() {
            $(
                Some($first) => match_token!($tokens $(,$rest)* => $sub,),
            )*
            Some(_other) => return Err(Error::Unexpected),
            None => return Err(Error::UnexpectedStart),
        }
    };
}

///Vec representing terminals stack while decoding.
struct TerminalStack<Pk: MiniscriptKey, Ctx: ScriptContext>(Vec<Miniscript<Pk, Ctx>>);

impl<Pk: MiniscriptKey, Ctx: ScriptContext> TerminalStack<Pk, Ctx> {
    /// Wrapper around self.0.pop()
    fn pop(&mut self) -> Option<Miniscript<Pk, Ctx>> { self.0.pop() }

    /// Wrapper around self.0.push()
    fn push(&mut self, ms: Miniscript<Pk, Ctx>) { self.0.push(ms) }

    ///reduce, type check and push a 0-arg node
    fn reduce0(&mut self, ms: Terminal<Pk, Ctx>) -> Result<(), Error> {
        let ms = Miniscript::from_ast(ms)?;
        self.0.push(ms);
        Ok(())
    }

    ///reduce, type check and push a 1-arg node
    fn reduce1<F>(&mut self, wrap: F) -> Result<(), Error>
    where
        F: FnOnce(Arc<Miniscript<Pk, Ctx>>) -> Terminal<Pk, Ctx>,
    {
        let top = self.pop().unwrap();
        let wrapped_ms = wrap(Arc::new(top));

        self.reduce0(wrapped_ms)
    }

    ///reduce, type check and push a 2-arg node
    fn reduce2<F>(&mut self, wrap: F) -> Result<(), Error>
    where
        F: FnOnce(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>) -> Terminal<Pk, Ctx>,
    {
        let left = self.pop().unwrap();
        let right = self.pop().unwrap();

        let wrapped_ms = wrap(Arc::new(left), Arc::new(right));

        self.reduce0(wrapped_ms)
    }
}

/// Parse a script fragment into an `Miniscript`
#[allow(unreachable_patterns)]
pub fn decode<Ctx: ScriptContext>(
    tokens: &mut TokenIter,
) -> Result<Miniscript<Ctx::Key, Ctx>, Error> {
    let mut non_term = Vec::with_capacity(tokens.len());
    let mut term = TerminalStack(Vec::with_capacity(tokens.len()));

    // top level cannot be swap, must be B
    non_term.push(NonTerm::MaybeAndV);
    non_term.push(NonTerm::Expression);
    loop {
        match non_term.pop() {
            Some(NonTerm::Expression) => {
                match_token!(
                    tokens,
                    // checksig
                    Tk::CheckSig => {
                        non_term.push(NonTerm::Check);
                        non_term.push(NonTerm::Expression);
                    },
                    // pubkeyhash and [T] VERIFY and [T] 0NOTEQUAL
                    Tk::Verify => match_token!(
                        tokens,
                        Tk::Equal => match_token!(
                            tokens,
                            Tk::Num(k) => {
                                non_term.push(NonTerm::Verify);
                                non_term.push(NonTerm::ThreshW {
                                    k: k as usize,
                                    n: 0
                                });
                            },
                        ),
                        x => {
                            tokens.un_next(x);
                            non_term.push(NonTerm::Verify);
                            non_term.push(NonTerm::Expression);
                        },
                    ),
                    Tk::ZeroNotEqual => {
                        non_term.push(NonTerm::ZeroNotEqual);
                        non_term.push(NonTerm::Expression);
                    },
                    // timelocks
                    Tk::CheckSequenceVerify, Tk::Num(n)
                        => term.push(Miniscript::older(RelLockTime::from_consensus(n).map_err(Error::RelativeLockTime)?)),
                    Tk::CheckLockTimeVerify, Tk::Num(n)
                        => term.push(Miniscript::after(AbsLockTime::from_consensus(n).map_err(Error::AbsoluteLockTime)?)),
                    // most other fragments
                    Tk::Num(0) => term.push(Miniscript::FALSE),
                    Tk::Num(1) => term.push(Miniscript::TRUE),
                    Tk::EndIf => {
                        non_term.push(NonTerm::EndIf);
                        non_term.push(NonTerm::MaybeAndV);
                        non_term.push(NonTerm::Expression);
                    },
                    // boolean conjunctions and disjunctions
                    Tk::BoolAnd => {
                        non_term.push(NonTerm::AndB);
                        non_term.push(NonTerm::Expression);
                        non_term.push(NonTerm::WExpression);
                    },
                    Tk::BoolOr => {
                        non_term.push(NonTerm::OrB);
                        non_term.push(NonTerm::Expression);
                        non_term.push(NonTerm::WExpression);
                    },
                );
            }
            Some(NonTerm::MaybeAndV) => {
                // Handle `and_v` prefixing
                if is_and_v(tokens) {
                    non_term.push(NonTerm::AndV);
                    non_term.push(NonTerm::Expression);
                }
            }
            Some(NonTerm::Swap) => {
                // Handle `SWAP` prefixing
                match_token!(
                    tokens,
                    Tk::Swap => {},
                );
                term.reduce1(Terminal::Swap)?;
                // Swap must be always be terminating a NonTerm as it cannot be in and_v
            }
            Some(NonTerm::Alt) => {
                match_token!(
                    tokens,
                    Tk::ToAltStack => {},
                );
                term.reduce1(Terminal::Alt)?;
            }
            Some(NonTerm::Check) => term.reduce1(Terminal::Check)?,
            Some(NonTerm::DupIf) => term.reduce1(Terminal::DupIf)?,
            Some(NonTerm::Verify) => term.reduce1(Terminal::Verify)?,
            Some(NonTerm::NonZero) => term.reduce1(Terminal::NonZero)?,
            Some(NonTerm::ZeroNotEqual) => term.reduce1(Terminal::ZeroNotEqual)?,
            Some(NonTerm::AndV) => {
                if is_and_v(tokens) {
                    non_term.push(NonTerm::AndV);
                    non_term.push(NonTerm::MaybeAndV);
                } else {
                    term.reduce2(Terminal::AndV)?
                }
            }
            Some(NonTerm::AndB) => term.reduce2(Terminal::AndB)?,
            Some(NonTerm::OrB) => term.reduce2(Terminal::OrB)?,
            Some(NonTerm::OrC) => term.reduce2(Terminal::OrC)?,
            Some(NonTerm::OrD) => term.reduce2(Terminal::OrD)?,
            Some(NonTerm::Tern) => {
                let a = term.pop().unwrap();
                let b = term.pop().unwrap();
                let c = term.pop().unwrap();
                let wrapped_ms = Terminal::AndOr(Arc::new(a), Arc::new(c), Arc::new(b));

                term.0.push(Miniscript::from_ast(wrapped_ms)?);
            }
            Some(NonTerm::ThreshW { n, k }) => {
                match_token!(
                    tokens,
                    Tk::Add => {
                        non_term.push(NonTerm::ThreshW { n: n + 1, k });
                        non_term.push(NonTerm::WExpression);
                    },
                    x => {
                        tokens.un_next(x);
                        non_term.push(NonTerm::ThreshE { n: n + 1, k });
                        non_term.push(NonTerm::Expression);
                    },
                );
            }
            Some(NonTerm::ThreshE { n, k }) => {
                let mut subs = Vec::with_capacity(n);
                for _ in 0..n {
                    subs.push(Arc::new(term.pop().unwrap()));
                }
                term.reduce0(Terminal::Thresh(Threshold::new(k, subs).map_err(Error::Threshold)?))?;
            }
            Some(NonTerm::EndIf) => {
                match_token!(
                    tokens,
                    Tk::Else => {
                        non_term.push(NonTerm::EndIfElse);
                        non_term.push(NonTerm::MaybeAndV);
                        non_term.push(NonTerm::Expression);
                    },
                    Tk::If => match_token!(
                        tokens,
                        Tk::Dup => non_term.push(NonTerm::DupIf),
                        Tk::ZeroNotEqual, Tk::Size
                            => non_term.push(NonTerm::NonZero),
                    ),
                    Tk::NotIf => {
                        non_term.push(NonTerm::EndIfNotIf);
                    },
                );
            }
            Some(NonTerm::EndIfNotIf) => {
                match_token!(
                    tokens,
                    Tk::IfDup => non_term.push(NonTerm::OrD),
                    x => {
                        tokens.un_next(x);
                        non_term.push(NonTerm::OrC);
                    },
                );
                non_term.push(NonTerm::Expression);
            }
            Some(NonTerm::EndIfElse) => {
                match_token!(
                    tokens,
                    Tk::If => {
                        term.reduce2(Terminal::OrI)?;
                    },
                    Tk::NotIf => {
                        non_term.push(NonTerm::Tern);
                        non_term.push(NonTerm::Expression);
                    },
                );
            }
            Some(NonTerm::WExpression) => {
                // W expression must be either from swap or Fromaltstack
                match_token!(tokens,
                    Tk::FromAltStack => { non_term.push(NonTerm::Alt);},
                    tok => { tokens.un_next(tok); non_term.push(NonTerm::Swap);},);
                non_term.push(NonTerm::MaybeAndV);
                non_term.push(NonTerm::Expression);
            }
            None => {
                // Done :)
                break;
            }
        }
    }

    assert_eq!(non_term.len(), 0);
    assert_eq!(term.0.len(), 1);
    Ok(term.pop().unwrap())
}

fn is_and_v(tokens: &mut TokenIter) -> bool {
    !matches!(
        tokens.peek(),
        None | Some(&Tk::If)
            | Some(&Tk::NotIf)
            | Some(&Tk::Else)
            | Some(&Tk::ToAltStack)
            | Some(&Tk::Swap)
    )
}

/// Decoding error while parsing keys
#[derive(Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Bitcoin PublicKey parse error
    Full(bitcoin::key::FromSliceError),
    /// Xonly key parse Error
    XOnly(bitcoin::secp256k1::Error),
}
