// SPDX-License-Identifier: CC0-1.0

//! Abstract Syntax Tree
//!
//! Defines a variety of data structures for describing Miniscript, a subset of
//! Bitcoin Script which can be efficiently parsed and serialized from Script,
//! and from which it is easy to extract data needed to construct witnesses.
//!
//! Users of the library in general will only need to use the structures exposed
//! from the top level of this module; however for people wanting to do advanced
//! things, the submodules are public as well which provide visibility into the
//! components of the AST.
//!

use core::{hash, str};

use bitcoin::script;

use self::analyzable::ExtParams;
pub use self::context::Segwitv0;
use crate::iter::TreeLike;
use crate::prelude::*;
use crate::{script_num_size, TranslateErr};

pub mod analyzable;
pub mod astelem;
pub(crate) mod context;
pub mod decode;
pub mod iter;
pub mod lex;
pub mod limits;
pub mod types;

use sync::Arc;

use self::lex::{lex, TokenIter};
use crate::expression::{FromTree, TreeIterItem};
pub use crate::miniscript::context::ScriptContext;
use crate::miniscript::decode::Terminal;
use crate::{
    expression, Error, ForEachKey, FromStrKey, MiniscriptKey, ToPublicKey, Translator,
};

mod private {
    use core::marker::PhantomData;

    use super::limits::{MAX_PUBKEYS_IN_CHECKSIGADD, MAX_PUBKEYS_PER_MULTISIG};
    use super::types::{self, ExtData, Type};
    use crate::iter::TreeLike as _;
    pub use crate::miniscript::context::ScriptContext;
    use crate::prelude::sync::Arc;
    use crate::{AbsLockTime, Error, MiniscriptKey, RelLockTime, Terminal, MAX_RECURSION_DEPTH};

    /// The top-level miniscript abstract syntax tree (AST).
    pub struct Miniscript<Pk: MiniscriptKey, Ctx: ScriptContext> {
        /// A node in the AST.
        pub node: Terminal<Pk, Ctx>,
        /// The correctness and malleability type information for the AST node.
        pub ty: types::Type,
        /// Additional information helpful for extra analysis.
        pub ext: types::extra_props::ExtData,
        /// Context PhantomData. Only accessible inside this crate
        phantom: PhantomData<Ctx>,
    }

    impl<Pk: MiniscriptKey, Ctx: ScriptContext> Clone for Miniscript<Pk, Ctx> {
        /// We implement clone as a "deep clone" which reconstructs the entire tree.
        ///
        /// If users just want to clone Arcs they can use Arc::clone themselves.
        /// Note that if a Miniscript was constructed using shared Arcs, the result
        /// of calling `clone` will no longer have shared Arcs. So there is no
        /// pleasing everyone. But for the two common cases:
        ///
        /// * Users don't care about sharing at all, and they can call `Arc::clone`
        ///   on an `Arc<Miniscript>`.
        /// * Users want a deep copy which does not share any nodes with the original
        ///   (for example, because they have keys that have interior mutability),
        ///   and they can call `Miniscript::clone`.
        fn clone(&self) -> Self {
            let mut stack = vec![];
            for item in self.rtl_post_order_iter() {
                let new_term = match item.node.node {
                    Terminal::PkK(ref p) => Terminal::PkK(p.clone()),
                    Terminal::PkH(ref p) => Terminal::PkH(p.clone()),
                    Terminal::RawPkH(ref p) => Terminal::RawPkH(*p),
                    Terminal::After(ref n) => Terminal::After(*n),
                    Terminal::Older(ref n) => Terminal::Older(*n),
                    Terminal::Sha256(ref x) => Terminal::Sha256(x.clone()),
                    Terminal::Hash256(ref x) => Terminal::Hash256(x.clone()),
                    Terminal::Ripemd160(ref x) => Terminal::Ripemd160(x.clone()),
                    Terminal::Hash160(ref x) => Terminal::Hash160(x.clone()),
                    Terminal::True => Terminal::True,
                    Terminal::False => Terminal::False,
                    Terminal::Alt(..) => Terminal::Alt(stack.pop().unwrap()),
                    Terminal::Swap(..) => Terminal::Swap(stack.pop().unwrap()),
                    Terminal::Check(..) => Terminal::Check(stack.pop().unwrap()),
                    Terminal::DupIf(..) => Terminal::DupIf(stack.pop().unwrap()),
                    Terminal::Verify(..) => Terminal::Verify(stack.pop().unwrap()),
                    Terminal::NonZero(..) => Terminal::NonZero(stack.pop().unwrap()),
                    Terminal::ZeroNotEqual(..) => Terminal::ZeroNotEqual(stack.pop().unwrap()),
                    Terminal::AndV(..) => {
                        Terminal::AndV(stack.pop().unwrap(), stack.pop().unwrap())
                    }
                    Terminal::AndB(..) => {
                        Terminal::AndB(stack.pop().unwrap(), stack.pop().unwrap())
                    }
                    Terminal::AndOr(..) => Terminal::AndOr(
                        stack.pop().unwrap(),
                        stack.pop().unwrap(),
                        stack.pop().unwrap(),
                    ),
                    Terminal::OrB(..) => Terminal::OrB(stack.pop().unwrap(), stack.pop().unwrap()),
                    Terminal::OrD(..) => Terminal::OrD(stack.pop().unwrap(), stack.pop().unwrap()),
                    Terminal::OrC(..) => Terminal::OrC(stack.pop().unwrap(), stack.pop().unwrap()),
                    Terminal::OrI(..) => Terminal::OrI(stack.pop().unwrap(), stack.pop().unwrap()),
                    Terminal::Thresh(ref thresh) => {
                        Terminal::Thresh(thresh.map_ref(|_| stack.pop().unwrap()))
                    }
                    Terminal::Multi(ref thresh) => Terminal::Multi(thresh.clone()),
                    Terminal::MultiA(ref thresh) => Terminal::MultiA(thresh.clone()),
                };

                stack.push(Arc::new(Miniscript {
                    node: new_term,
                    ty: item.node.ty,
                    ext: item.node.ext,
                    phantom: PhantomData,
                }));
            }

            assert_eq!(stack.len(), 1);
            Arc::try_unwrap(stack.pop().unwrap_or_else(|| unreachable!())).unwrap_or_else(|_| unreachable!())
        }
    }

    impl<Pk: MiniscriptKey, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
        /// The `1` combinator.
        pub const TRUE: Self = Miniscript {
            node: Terminal::True,
            ty: types::Type::TRUE,
            ext: types::extra_props::ExtData::TRUE,
            phantom: PhantomData,
        };

        /// The `0` combinator.
        pub const FALSE: Self = Miniscript {
            node: Terminal::False,
            ty: types::Type::FALSE,
            ext: types::extra_props::ExtData::FALSE,
            phantom: PhantomData,
        };

        /// The `pk` combinator, which is an alias for `c:pk_k`.
        pub fn pk(pk: Pk) -> Self {
            let inner = Arc::new(Self::pk_k(pk));
            Self {
                ty: types::Type::cast_check(inner.ty).unwrap_or_else(|_| unreachable!()),
                ext: types::extra_props::ExtData::cast_check(inner.ext),
                node: Terminal::Check(inner),
                phantom: PhantomData,
            }
        }

        /// The `pkh` combinator, which is an alias for `c:pk_h`.
        pub fn pkh(pk: Pk) -> Self {
            let inner = Arc::new(Self::pk_h(pk));
            Self {
                ty: types::Type::cast_check(inner.ty).unwrap_or_else(|_| unreachable!()),
                ext: types::extra_props::ExtData::cast_check(inner.ext),
                node: Terminal::Check(inner),
                phantom: PhantomData,
            }
        }

        /// The `pk_k` combinator.
        pub fn pk_k(pk: Pk) -> Self {
            Self {
                ext: types::extra_props::ExtData::pk_k::<_, Ctx>(&pk),
                node: Terminal::PkK(pk),
                ty: types::Type::pk_k(),
                phantom: PhantomData,
            }
        }

        /// The `pk_h` combinator.
        pub fn pk_h(pk: Pk) -> Self {
            Self {
                ext: types::extra_props::ExtData::pk_h::<_, Ctx>(Some(&pk)),
                node: Terminal::PkH(pk),
                ty: types::Type::pk_h(),
                phantom: PhantomData,
            }
        }

        /// The `expr_raw_pkh` combinator.
        pub fn expr_raw_pkh(hash: bitcoin::hashes::hash160::Hash) -> Self {
            Self {
                node: Terminal::RawPkH(hash),
                ty: types::Type::pk_h(),
                ext: types::extra_props::ExtData::pk_h::<Pk, Ctx>(None),
                phantom: PhantomData,
            }
        }

        /// The `after` combinator.
        pub fn after(time: AbsLockTime) -> Self {
            Self {
                node: Terminal::After(time),
                ty: types::Type::time(),
                ext: types::extra_props::ExtData::after(time),
                phantom: PhantomData,
            }
        }

        /// The `older` combinator.
        pub fn older(time: RelLockTime) -> Self {
            Self {
                node: Terminal::Older(time),
                ty: types::Type::time(),
                ext: types::extra_props::ExtData::older(time),
                phantom: PhantomData,
            }
        }

        /// The `sha256` combinator.
        pub const fn sha256(hash: Pk::Sha256) -> Self {
            Self {
                node: Terminal::Sha256(hash),
                ty: types::Type::hash(),
                ext: types::extra_props::ExtData::sha256(),
                phantom: PhantomData,
            }
        }

        /// The `hash256` combinator.
        pub const fn hash256(hash: Pk::Hash256) -> Self {
            Self {
                node: Terminal::Hash256(hash),
                ty: types::Type::hash(),
                ext: types::extra_props::ExtData::hash256(),
                phantom: PhantomData,
            }
        }

        /// The `ripemd160` combinator.
        pub const fn ripemd160(hash: Pk::Ripemd160) -> Self {
            Self {
                node: Terminal::Ripemd160(hash),
                ty: types::Type::hash(),
                ext: types::extra_props::ExtData::ripemd160(),
                phantom: PhantomData,
            }
        }

        /// The `hash160` combinator.
        pub const fn hash160(hash: Pk::Hash160) -> Self {
            Self {
                node: Terminal::Hash160(hash),
                ty: types::Type::hash(),
                ext: types::extra_props::ExtData::hash160(),
                phantom: PhantomData,
            }
        }

        // non-const because Thresh::n is not because Vec::len is not (needs Rust 1.87)
        /// The `multi` combinator.
        pub fn multi(thresh: crate::Threshold<Pk, MAX_PUBKEYS_PER_MULTISIG>) -> Self {
            Self {
                ty: types::Type::multi(),
                ext: types::extra_props::ExtData::multi(&thresh),
                node: Terminal::Multi(thresh),
                phantom: PhantomData,
            }
        }

        // non-const because Thresh::n is not because Vec::len is not
        /// The `multi` combinator.
        pub fn multi_a(thresh: crate::Threshold<Pk, MAX_PUBKEYS_IN_CHECKSIGADD>) -> Self {
            Self {
                ty: types::Type::multi_a(),
                ext: types::extra_props::ExtData::multi_a(thresh.k(), thresh.n()),
                node: Terminal::MultiA(thresh),
                phantom: PhantomData,
            }
        }

        /// Add type information(Type and Extdata) to Miniscript based on
        /// `AstElem` fragment. Dependent on display and clone because of Error
        /// Display code of type_check.
        pub fn from_ast(t: Terminal<Pk, Ctx>) -> Result<Miniscript<Pk, Ctx>, Error> {
            let res = Miniscript {
                ty: Type::type_check(&t)?,
                ext: ExtData::type_check(&t),
                node: t,
                phantom: PhantomData,
            };
            // TODO: This recursion depth is based on segwitv0.
            // We can relax this in tapscript, but this should be good for almost
            // all practical cases and we can revisit this if needed.
            // casting to u32 is safe because tree_height will never go more than u32::MAX
            if (res.ext.tree_height as u32) > MAX_RECURSION_DEPTH {
                return Err(Error::MaxRecursiveDepthExceeded);
            }
            Ctx::check_global_validity(&res)?;
            Ok(res)
        }

        /// Create a new `Miniscript` from a `Terminal` node and a `Type` annotation
        /// This does not check the typing rules. The user is responsible for ensuring
        /// that the type provided is correct.
        ///
        /// You should almost always use `Miniscript::from_ast` instead of this function.
        pub fn from_components_unchecked(
            node: Terminal<Pk, Ctx>,
            ty: types::Type,
            ext: types::extra_props::ExtData,
        ) -> Miniscript<Pk, Ctx> {
            Miniscript { node, ty, ext, phantom: PhantomData }
        }
    }
}

pub use private::Miniscript;

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
    /// Extracts the `AstElem` representing the root of the miniscript
    pub fn into_inner(self) -> Terminal<Pk, Ctx> { self.node }

    /// Get a reference to the inner `AstElem` representing the root of miniscript
    pub fn as_inner(&self) -> &Terminal<Pk, Ctx> { &self.node }

    /// Encode as a Bitcoin script
    pub fn encode(&self) -> script::ScriptBuf
    where
        Pk: ToPublicKey,
    {
        self.node.encode(script::Builder::new()).into_script()
    }

    /// Size, in bytes of the script-pubkey. If this Miniscript is used outside
    /// of segwit (e.g. in a bare or P2SH descriptor), this quantity should be
    /// multiplied by 4 to compute the weight.
    ///
    /// In general, it is not recommended to use this function directly, but
    /// to instead call the corresponding function on a `Descriptor`, which
    /// will handle the segwit/non-segwit technicalities for you.
    pub fn script_size(&self) -> usize {
        use Terminal::*;

        let mut len = 0;
        for ms in self.pre_order_iter() {
            len += match ms.node {
                AndV(..) => 0,
                True | False | Swap(..) | Check(..) | ZeroNotEqual(..) | AndB(..) | OrB(..) => 1,
                Alt(..) | OrC(..) => 2,
                DupIf(..) | AndOr(..) | OrD(..) | OrI(..) => 3,
                NonZero(..) => 4,
                PkH(..) | RawPkH(..) => 24,
                Ripemd160(..) | Hash160(..) => 21 + 6,
                Sha256(..) | Hash256(..) => 33 + 6,

                Terminal::PkK(ref pk) => Ctx::pk_len(pk),
                Terminal::After(n) => script_num_size(n.to_consensus_u32() as usize) + 1,
                Terminal::Older(n) => script_num_size(n.to_consensus_u32() as usize) + 1,
                Terminal::Verify(ref sub) => usize::from(!sub.ext.has_free_verify),
                Terminal::Thresh(ref thresh) => {
                    script_num_size(thresh.k()) // k
                        + 1 // EQUAL
                        + thresh.n() // ADD
                        - 1 // no ADD on first element
                }
                Terminal::Multi(ref thresh) => {
                    script_num_size(thresh.k())
                        + 1
                        + script_num_size(thresh.n())
                        + thresh.iter().map(|pk| Ctx::pk_len(pk)).sum::<usize>()
                }
                Terminal::MultiA(ref thresh) => {
                    script_num_size(thresh.k())
                        + 1 // NUMEQUAL
                        + thresh.iter().map(|pk| Ctx::pk_len(pk)).sum::<usize>() // n keys
                        + thresh.n() // n times CHECKSIGADD
                }
            }
        }
        len
    }

    /// Maximum number of witness elements used to satisfy the Miniscript
    /// fragment, including the witness script itself. Used to estimate
    /// the weight of the `VarInt` that specifies this number in a serialized
    /// transaction.
    ///
    /// This function may returns Error when the Miniscript is
    /// impossible to satisfy
    pub fn max_satisfaction_witness_elements(&self) -> Result<usize, Error> {
        self.ext
            .sat_data
            .map(|data| data.max_witness_stack_count + 1)
            .ok_or(Error::ImpossibleSatisfaction)
    }
}

impl<Ctx: ScriptContext> Miniscript<Ctx::Key, Ctx> {
    /// Attempt to decode a Miniscript from Script, checking only for consensus compatibility,
    /// and no other checks.
    ///
    /// It may make sense to use this method when parsing Script that is already
    /// embedded in the chain. While it is inadvisable to use insane Miniscripts,
    /// once it's on the chain you don't have much choice anymore.
    pub fn decode_consensus(script: &script::Script) -> Result<Miniscript<Ctx::Key, Ctx>, Error> {
        Miniscript::decode_with_ext(script, &ExtParams::allow_all())
    }

    /// Attempt to decode a Miniscript from Script, specifying which validation parameters to apply.
    pub fn decode_with_ext(
        script: &script::Script,
        ext: &ExtParams,
    ) -> Result<Miniscript<Ctx::Key, Ctx>, Error> {
        let tokens = lex(script)?;
        let mut iter = TokenIter::new(tokens);

        let top = decode::decode(&mut iter)?;
        Ctx::check_global_validity(&top)?;
        let type_check = types::Type::type_check(&top.node)?;
        if type_check.corr.base != types::Base::B {
            return Err(Error::NonTopLevel);
        };
        if let Some(_leading) = iter.next() {
            Err(Error::Trailing)
        } else {
            top.ext_check(ext)?;
            Ok(top)
        }
    }

    /// Attempt to parse a Script into Miniscript representation.
    ///
    /// This function will fail parsing for scripts that do not clear the
    /// [`Miniscript::sanity_check`] checks. Use [`Miniscript::decode_consensus`] to
    /// parse such scripts.
    pub fn decode(script: &script::Script) -> Result<Miniscript<Ctx::Key, Ctx>, Error> {
        let ms = Self::decode_with_ext(script, &ExtParams::sane())?;
        Ok(ms)
    }
}

/// `PartialEq` of `Miniscript` must depend only on node and not the type information.
///
/// The type information and extra properties are implied by the AST.
impl<Pk: MiniscriptKey, Ctx: ScriptContext> PartialEq for Miniscript<Pk, Ctx> {
    fn eq(&self, other: &Miniscript<Pk, Ctx>) -> bool { self.node.eq(&other.node) }
}

/// `Eq` of `Miniscript` must depend only on node and not the type information.
///
/// The type information and extra properties are implied by the AST.
impl<Pk: MiniscriptKey, Ctx: ScriptContext> Eq for Miniscript<Pk, Ctx> {}

/// `Hash` of `Miniscript` must depend only on node and not the type information.
///
/// The type information and extra properties are implied by the AST.
impl<Pk: MiniscriptKey, Ctx: ScriptContext> hash::Hash for Miniscript<Pk, Ctx> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) { self.node.hash(state); }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> ForEachKey<Pk> for Miniscript<Pk, Ctx> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, mut pred: F) -> bool {
        for ms in self.pre_order_iter() {
            match ms.node {
                Terminal::PkK(ref p) => {
                    if !pred(p) {
                        return false;
                    }
                }
                Terminal::PkH(ref p) => {
                    if !pred(p) {
                        return false;
                    }
                }
                // These branches cannot be combined since technically the two `thresh`es
                // have different types (have different maximum values).
                Terminal::Multi(ref thresh) => {
                    if !thresh.iter().all(&mut pred) {
                        return false;
                    }
                }
                Terminal::MultiA(ref thresh) => {
                    if !thresh.iter().all(&mut pred) {
                        return false;
                    }
                }
                _ => {}
            }
        }
        true
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
    /// Translates a struct from one generic to another where the translation
    /// for Pk is provided by [`Translator`]
    pub fn translate_pk<T>(
        &self,
        t: &mut T,
    ) -> Result<Miniscript<T::TargetPk, Ctx>, TranslateErr<T::Error>>
    where
        T: Translator<Pk>,
    {
        self.translate_pk_ctx(t)
    }

    pub(super) fn translate_pk_ctx<CtxQ, T>(
        &self,
        t: &mut T,
    ) -> Result<Miniscript<T::TargetPk, CtxQ>, TranslateErr<T::Error>>
    where
        CtxQ: ScriptContext,
        T: Translator<Pk>,
    {
        let mut translated = vec![];
        for data in self.rtl_post_order_iter() {
            let new_term = match data.node.node {
                Terminal::PkK(ref p) => Terminal::PkK(t.pk(p)?),
                Terminal::PkH(ref p) => Terminal::PkH(t.pk(p)?),
                Terminal::RawPkH(ref p) => Terminal::RawPkH(*p),
                Terminal::After(n) => Terminal::After(n),
                Terminal::Older(n) => Terminal::Older(n),
                Terminal::Sha256(ref x) => Terminal::Sha256(t.sha256(x)?),
                Terminal::Hash256(ref x) => Terminal::Hash256(t.hash256(x)?),
                Terminal::Ripemd160(ref x) => Terminal::Ripemd160(t.ripemd160(x)?),
                Terminal::Hash160(ref x) => Terminal::Hash160(t.hash160(x)?),
                Terminal::True => Terminal::True,
                Terminal::False => Terminal::False,
                Terminal::Alt(..) => Terminal::Alt(translated.pop().unwrap()),
                Terminal::Swap(..) => Terminal::Swap(translated.pop().unwrap()),
                Terminal::Check(..) => Terminal::Check(translated.pop().unwrap()),
                Terminal::DupIf(..) => Terminal::DupIf(translated.pop().unwrap()),
                Terminal::Verify(..) => Terminal::Verify(translated.pop().unwrap()),
                Terminal::NonZero(..) => Terminal::NonZero(translated.pop().unwrap()),
                Terminal::ZeroNotEqual(..) => Terminal::ZeroNotEqual(translated.pop().unwrap()),
                Terminal::AndV(..) => {
                    Terminal::AndV(translated.pop().unwrap(), translated.pop().unwrap())
                }
                Terminal::AndB(..) => {
                    Terminal::AndB(translated.pop().unwrap(), translated.pop().unwrap())
                }
                Terminal::AndOr(..) => Terminal::AndOr(
                    translated.pop().unwrap(),
                    translated.pop().unwrap(),
                    translated.pop().unwrap(),
                ),
                Terminal::OrB(..) => {
                    Terminal::OrB(translated.pop().unwrap(), translated.pop().unwrap())
                }
                Terminal::OrD(..) => {
                    Terminal::OrD(translated.pop().unwrap(), translated.pop().unwrap())
                }
                Terminal::OrC(..) => {
                    Terminal::OrC(translated.pop().unwrap(), translated.pop().unwrap())
                }
                Terminal::OrI(..) => {
                    Terminal::OrI(translated.pop().unwrap(), translated.pop().unwrap())
                }
                Terminal::Thresh(ref thresh) => {
                    Terminal::Thresh(thresh.map_ref(|_| translated.pop().unwrap()))
                }
                Terminal::Multi(ref thresh) => Terminal::Multi(thresh.translate_ref(|k| t.pk(k))?),
                Terminal::MultiA(ref thresh) => {
                    Terminal::MultiA(thresh.translate_ref(|k| t.pk(k))?)
                }
            };
            let new_ms = Miniscript::from_ast(new_term).map_err(TranslateErr::OuterError)?;
            translated.push(Arc::new(new_ms));
        }

        let res = translated.pop().unwrap_or_else(|| unreachable!());
        Ok(Arc::try_unwrap(res).unwrap_or_else(|_| unreachable!()))
    }
}

impl<Pk: FromStrKey, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
    /// Attempt to parse an insane(scripts don't clear sanity checks)
    /// from string into a Miniscript representation.
    /// Use this to parse scripts with repeated pubkeys, timelock mixing, malleable
    /// scripts without sig or scripts that can exceed resource limits.
    /// Some of the analysis guarantees of miniscript are lost when dealing with
    /// insane scripts. In general, in a multi-party setting users should only
    /// accept sane scripts.
    pub fn from_str_insane(s: &str) -> Result<Miniscript<Pk, Ctx>, Error> {
        Miniscript::from_str_ext(s, &ExtParams::insane())
    }

    /// Attempt to parse an Miniscripts that don't follow the spec.
    /// Use this to parse scripts with repeated pubkeys, timelock mixing, malleable
    /// scripts, raw pubkey hashes without sig or scripts that can exceed resource limits.
    ///
    /// Use [`ExtParams`] builder to specify the types of non-sane rules to allow while parsing.
    pub fn from_str_ext(s: &str, ext: &ExtParams) -> Result<Miniscript<Pk, Ctx>, Error> {
        // This checks for invalid ASCII chars
        let top = expression::Tree::from_str(s)?;
        let ms: Miniscript<Pk, Ctx> = expression::FromTree::from_tree(top.root())?;
        ms.ext_check(ext)?;

        if ms.ty.corr.base != types::Base::B {
            Err(Error::NonTopLevel)
        } else {
            Ok(ms)
        }
    }
}

impl<Pk: FromStrKey, Ctx: ScriptContext> FromTree for Arc<Miniscript<Pk, Ctx>> {
    fn from_tree(root: TreeIterItem) -> Result<Self, Error> {
        Miniscript::from_tree(root).map(Arc::new)
    }
}

impl<Pk: FromStrKey, Ctx: ScriptContext> FromTree for Miniscript<Pk, Ctx> {
    fn from_tree(root: TreeIterItem) -> Result<Self, Error> {
        #[allow(clippy::type_complexity)]
        fn binary<Pk: MiniscriptKey, Ctx: ScriptContext>(
            node: expression::TreeIterItem,
            stack: &mut Vec<Arc<Miniscript<Pk, Ctx>>>,
            name: &'static str,
            termfn: fn(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>) -> Terminal<Pk, Ctx>,
        ) -> Result<Miniscript<Pk, Ctx>, Error> {
            node.verify_n_children(name, 2..=2)
                .map_err(From::from)
                .map_err(Error::Parse)?;
            Miniscript::from_ast(termfn(stack.pop().unwrap(), stack.pop().unwrap()))
        }
        root.verify_no_curly_braces()
            .map_err(From::from)
            .map_err(Error::Parse)?;

        let mut stack = Vec::with_capacity(128);
        for (n, node) in root.pre_order_iter().enumerate().rev() {
            // Before doing anything else, check if this is the inner value of a terminal.
            // In that case, just skip the node. Conveniently, there are no combinators
            // in Miniscript that have a single child that these might be confused with.
            // (Well, there are, but they're all serialized as wrappers.)
            //
            // We also skip all the children of multi/multi_a and the first child of thresh
            // (which will be the k value, not a real child).
            //
            // We do not do this check on the root node, because its parent might be wsh or
            // sh or something, and actually these ARE single-child combinators, but we don't
            // want to skip their children.
            if n > 0 && node.n_children() == 0 {
                let parent = node.parent().unwrap();
                if parent.n_children() == 1 {
                    continue;
                }

                let (_, parent_name) = parent
                    .name_separated(':')
                    .map_err(From::from)
                    .map_err(Error::Parse)?;

                if parent_name == "multi" || parent_name == "multi_a" {
                    continue;
                }
                if parent_name == "thresh" && node.is_first_child() {
                    continue;
                }
            }

            let (frag_wrap, frag_name) = node
                .name_separated(':')
                .map_err(From::from)
                .map_err(Error::Parse)?;

            // "pk" and "pkh" are aliases for "c:pk_k" and "c:pk_h" respectively.
            let new = match frag_name {
                "expr_raw_pkh" => node
                    .verify_terminal_parent("expr_raw_pkh", "public key hash")
                    .map(Miniscript::expr_raw_pkh)
                    .map_err(Error::Parse),
                "pk" => node
                    .verify_terminal_parent("pk", "public key")
                    .map(Miniscript::pk)
                    .map_err(Error::Parse),
                "pkh" => node
                    .verify_terminal_parent("pkh", "public key")
                    .map(Miniscript::pkh)
                    .map_err(Error::Parse),
                "pk_k" => node
                    .verify_terminal_parent("pk_k", "public key")
                    .map(Miniscript::pk_k)
                    .map_err(Error::Parse),
                "pk_h" => node
                    .verify_terminal_parent("pk_h", "public key")
                    .map(Miniscript::pk_h)
                    .map_err(Error::Parse),
                "after" => node
                    .verify_after()
                    .map(Miniscript::after)
                    .map_err(Error::Parse),
                "older" => node
                    .verify_older()
                    .map(Miniscript::older)
                    .map_err(Error::Parse),
                "sha256" => node
                    .verify_terminal_parent("sha256", "hash")
                    .map(Miniscript::sha256)
                    .map_err(Error::Parse),
                "hash256" => node
                    .verify_terminal_parent("hash256", "hash")
                    .map(Miniscript::hash256)
                    .map_err(Error::Parse),
                "ripemd160" => node
                    .verify_terminal_parent("ripemd160", "hash")
                    .map(Miniscript::ripemd160)
                    .map_err(Error::Parse),
                "hash160" => node
                    .verify_terminal_parent("hash160", "hash")
                    .map(Miniscript::hash160)
                    .map_err(Error::Parse),
                "1" => {
                    node.verify_n_children("1", 0..=0)
                        .map_err(From::from)
                        .map_err(Error::Parse)?;
                    Ok(Miniscript::TRUE)
                }
                "0" => {
                    node.verify_n_children("0", 0..=0)
                        .map_err(From::from)
                        .map_err(Error::Parse)?;
                    Ok(Miniscript::FALSE)
                }
                "and_v" => binary(node, &mut stack, "and_v", Terminal::AndV),
                "and_b" => binary(node, &mut stack, "and_b", Terminal::AndB),
                "and_n" => binary(node, &mut stack, "and_n", |x, y| {
                    Terminal::AndOr(x, y, Arc::new(Miniscript::FALSE))
                }),
                "andor" => {
                    node.verify_n_children("andor", 3..=3)
                        .map_err(From::from)
                        .map_err(Error::Parse)?;
                    Miniscript::from_ast(Terminal::AndOr(
                        stack.pop().unwrap(),
                        stack.pop().unwrap(),
                        stack.pop().unwrap(),
                    ))
                }
                "or_b" => binary(node, &mut stack, "or_b", Terminal::OrB),
                "or_d" => binary(node, &mut stack, "or_d", Terminal::OrD),
                "or_c" => binary(node, &mut stack, "or_c", Terminal::OrC),
                "or_i" => binary(node, &mut stack, "or_i", Terminal::OrI),
                "thresh" => node
                    .verify_threshold(|_| Ok(stack.pop().unwrap()))
                    .map(Terminal::Thresh)
                    .and_then(Miniscript::from_ast),
                "multi" => node
                    .verify_threshold(|sub| sub.verify_terminal("public_key").map_err(Error::Parse))
                    .map(Terminal::Multi)
                    .and_then(Miniscript::from_ast),
                "multi_a" => node
                    .verify_threshold(|sub| sub.verify_terminal("public_key").map_err(Error::Parse))
                    .map(Terminal::MultiA)
                    .and_then(Miniscript::from_ast),
                x => {
                    Err(Error::Parse(crate::ParseError::Tree(crate::ParseTreeError::UnknownName {
                        name: x.to_owned(),
                    })))
                }
            }?;

            let mut new = Arc::new(new);
            if let Some(frag_wrap) = frag_wrap {
                // ":node()" is not valid syntax
                if frag_wrap.is_empty() {
                    return Err(Error::Parse(crate::ParseError::Tree(
                        crate::ParseTreeError::UnknownName { name: node.name().to_owned() },
                    )));
                }

                for ch in frag_wrap.bytes().rev() {
                    let term = match ch {
                        b'a' => Terminal::Alt(new),
                        b's' => Terminal::Swap(new),
                        b'c' => Terminal::Check(new),
                        b'd' => Terminal::DupIf(new),
                        b'v' => Terminal::Verify(new),
                        b'j' => Terminal::NonZero(new),
                        b'n' => Terminal::ZeroNotEqual(new),
                        b't' => Terminal::AndV(new, Arc::new(Miniscript::TRUE)),
                        b'u' => Terminal::OrI(new, Arc::new(Miniscript::FALSE)),
                        b'l' => Terminal::OrI(Arc::new(Miniscript::FALSE), new),
                        x => return Err(Error::UnknownWrapper(x.into())),
                    };
                    new = Arc::new(Miniscript::from_ast(term)?);
                }
            }

            stack.push(new);
        }

        assert_eq!(stack.len(), 1);
        let ret = stack.pop().unwrap_or_else(|| unreachable!());
        // Iterate through every node to check global validity. It is definitely not sufficient
        // to check only the root, since this will fail to notice illegal xonly keys at the
        // leaves. But probably checking every single node is overkill. This may be worth
        // optimizing.
        for node in ret.pre_order_iter() {
            Ctx::check_global_validity(node)?;
        }
        Ok(Arc::try_unwrap(ret).unwrap_or_else(|_| unreachable!()))
    }
}

impl<Pk: FromStrKey, Ctx: ScriptContext> str::FromStr for Miniscript<Pk, Ctx> {
    type Err = Error;
    /// Parse a Miniscript from string and perform sanity checks
    /// See [Miniscript::from_str_insane] to parse scripts from string that
    /// do not clear the [Miniscript::sanity_check] checks.
    fn from_str(s: &str) -> Result<Miniscript<Pk, Ctx>, Error> {
        let ms = Self::from_str_ext(s, &ExtParams::sane())?;
        Ok(ms)
    }
}

/// Provides a Double SHA256 `Hash` type that displays forwards.
pub mod hash256 {
    use bitcoin::hashes::{hash_newtype, sha256d};

    hash_newtype! {
        /// A hash256 of preimage.
        #[hash_newtype(forward)]
        pub struct Hash(sha256d::Hash);
    }
}
