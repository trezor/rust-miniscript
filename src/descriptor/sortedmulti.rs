// SPDX-License-Identifier: CC0-1.0

//! # Sorted Multi
//!
//! Implementation of sorted multi primitive for descriptors
//!

use core::marker::PhantomData;

use bitcoin::script;

use crate::blanket_traits::FromStrKey;
use crate::miniscript::context::ScriptContext;
use crate::miniscript::decode::Terminal;
use crate::miniscript::limits::MAX_PUBKEYS_PER_MULTISIG;
use crate::{
    expression, Error, ForEachKey, Miniscript, MiniscriptKey,
    Threshold, ToPublicKey, TranslateErr, Translator,
};

/// Contents of a "sortedmulti" descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SortedMultiVec<Pk: MiniscriptKey, Ctx: ScriptContext> {
    inner: Threshold<Pk, MAX_PUBKEYS_PER_MULTISIG>,
    /// The current ScriptContext for sortedmulti
    phantom: PhantomData<Ctx>,
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> SortedMultiVec<Pk, Ctx> {
    fn constructor_check(mut self) -> Result<Self, Error> {
        let ms = Miniscript::<Pk, Ctx>::multi(self.inner);
        // Check the limits before creating a new SortedMultiVec
        // For example, under p2sh context the scriptlen can only be
        // upto 520 bytes.
        Ctx::check_local_validity(&ms)?;
        if let Terminal::Multi(inner) = ms.node {
            self.inner = inner;
            Ok(self)
        } else {
            unreachable!()
        }
    }

    /// Create a new instance of `SortedMultiVec` given a list of keys and the threshold
    ///
    /// Internally checks all the applicable size limits and pubkey types limitations according to the current `Ctx`.
    pub fn new(thresh: Threshold<Pk, MAX_PUBKEYS_PER_MULTISIG>) -> Result<Self, Error> {
        let ret = Self { inner: thresh, phantom: PhantomData };
        ret.constructor_check()
    }

    /// Parse an expression tree into a SortedMultiVec
    pub fn from_tree(tree: expression::TreeIterItem) -> Result<Self, Error>
    where
        Pk: FromStrKey,
    {
        tree.verify_toplevel("sortedmulti", 1..)
            .map_err(From::from)
            .map_err(Error::Parse)?;

        let ret = Self {
            inner: tree
                .verify_threshold(|sub| sub.verify_terminal("public_key").map_err(Error::Parse))?,
            phantom: PhantomData,
        };
        ret.constructor_check()
    }

    /// This will panic if fpk returns an uncompressed key when
    /// converting to a Segwit descriptor. To prevent this panic, ensure
    /// fpk returns an error in this case instead.
    pub fn translate_pk<T>(
        &self,
        t: &mut T,
    ) -> Result<SortedMultiVec<T::TargetPk, Ctx>, TranslateErr<T::Error>>
    where
        T: Translator<Pk>,
    {
        let ret = SortedMultiVec {
            inner: self.inner.translate_ref(|pk| t.pk(pk))?,
            phantom: PhantomData,
        };
        ret.constructor_check().map_err(TranslateErr::OuterError)
    }

    /// The threshold value for the multisig.
    pub fn k(&self) -> usize { self.inner.k() }

    /// The number of keys in the multisig.
    pub fn n(&self) -> usize { self.inner.n() }

    /// Accessor for the public keys in the multisig.
    ///
    /// The keys in this structure might **not** be sorted. In general, they cannot be
    /// sorted until they are converted to consensus-encoded public keys, which may not
    /// be possible (for example for BIP32 paths with unfilled wildcards).
    pub fn pks(&self) -> &[Pk] { self.inner.data() }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> ForEachKey<Pk> for SortedMultiVec<Pk, Ctx> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, pred: F) -> bool {
        self.pks().iter().all(pred)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> SortedMultiVec<Pk, Ctx> {
    /// utility function to sanity a sorted multi vec
    pub fn sanity_check(&self) -> Result<(), Error> {
        let ms: Miniscript<Pk, Ctx> =
            Miniscript::from_ast(Terminal::Multi(self.inner.clone())).unwrap_or_else(|_| panic!("Must typecheck"));
        ms.sanity_check().map_err(From::from)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> SortedMultiVec<Pk, Ctx> {
    /// Create Terminal::Multi containing sorted pubkeys
    pub fn sorted_node(&self) -> Terminal<Pk, Ctx>
    where
        Pk: ToPublicKey,
    {
        let mut thresh = self.inner.clone();
        // Sort pubkeys lexicographically according to BIP 67
        thresh.data_mut().sort_by(|a, b| {
            a.to_public_key()
                .inner
                .serialize()
                .partial_cmp(&b.to_public_key().inner.serialize())
                .unwrap()
        });
        Terminal::Multi(thresh)
    }

    /// Encode as a Bitcoin script
    pub fn encode(&self) -> script::ScriptBuf
    where
        Pk: ToPublicKey,
    {
        self.sorted_node()
            .encode(script::Builder::new())
            .into_script()
    }
}
