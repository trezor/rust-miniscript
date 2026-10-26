// SPDX-License-Identifier: CC0-1.0

//! # Segwit Output Descriptors
//!
//! Implementation of Segwit Descriptors. Contains the implementation
//! of wsh, wpkh and sortedmulti inside wsh.


use bitcoin::ScriptBuf;

use super::SortedMultiVec;
use crate::expression::{self, FromTree};
use crate::miniscript::context::ScriptContext;
use crate::miniscript::limits::MAX_PUBKEYS_PER_MULTISIG;
use crate::{
    Error, ForEachKey, FromStrKey, Miniscript, MiniscriptKey, Segwitv0, Threshold,
    ToPublicKey, TranslateErr, Translator,
};
/// A Segwitv0 wsh descriptor
#[derive(Eq, PartialEq)]
pub struct Wsh<Pk: MiniscriptKey> {
    /// underlying miniscript
    inner: WshInner<Pk>,
}

impl<Pk: MiniscriptKey> Wsh<Pk> {
    /// Get the Inner
    pub fn into_inner(self) -> WshInner<Pk> { self.inner }

    /// Get a reference to inner
    pub fn as_inner(&self) -> &WshInner<Pk> { &self.inner }

    /// Create a new wsh descriptor
    pub fn new(ms: Miniscript<Pk, Segwitv0>) -> Result<Self, Error> {
        // do the top-level checks
        Segwitv0::top_level_checks(&ms)?;
        Ok(Self { inner: WshInner::Ms(ms) })
    }

    /// Create a new sortedmulti wsh descriptor
    pub fn new_sortedmulti(thresh: Threshold<Pk, MAX_PUBKEYS_PER_MULTISIG>) -> Result<Self, Error> {
        // The context checks will be carried out inside new function for
        // sortedMultiVec
        Ok(Self { inner: WshInner::SortedMulti(SortedMultiVec::new(thresh)?) })
    }

    /// Checks whether the descriptor is safe.
    pub fn sanity_check(&self) -> Result<(), Error> {
        match self.inner {
            WshInner::SortedMulti(ref smv) => smv.sanity_check()?,
            WshInner::Ms(ref ms) => ms.sanity_check()?,
        }
        Ok(())
    }

    /// Converts the keys in a script from one type to another.
    pub fn translate_pk<T>(&self, t: &mut T) -> Result<Wsh<T::TargetPk>, TranslateErr<T::Error>>
    where
        T: Translator<Pk>,
    {
        let inner = match self.inner {
            WshInner::SortedMulti(ref smv) => WshInner::SortedMulti(smv.translate_pk(t)?),
            WshInner::Ms(ref ms) => WshInner::Ms(ms.translate_pk(t)?),
        };
        Ok(Wsh { inner })
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Wsh<Pk> {
    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn script_pubkey(&self) -> ScriptBuf { self.inner_script().to_p2wsh() }

    /// Obtains the underlying miniscript for this descriptor.
    pub fn inner_script(&self) -> ScriptBuf {
        match self.inner {
            WshInner::SortedMulti(ref smv) => smv.encode(),
            WshInner::Ms(ref ms) => ms.encode(),
        }
    }

    /// Obtains the pre bip-340 signature script code for this descriptor.
    pub fn ecdsa_sighash_script_code(&self) -> ScriptBuf { self.inner_script() }
}

/// Wsh Inner
#[derive(Eq, PartialEq)]
pub enum WshInner<Pk: MiniscriptKey> {
    /// Sorted Multi
    SortedMulti(SortedMultiVec<Pk, Segwitv0>),
    /// Wsh Miniscript
    Ms(Miniscript<Pk, Segwitv0>),
}

impl<Pk: FromStrKey> crate::expression::FromTree for Wsh<Pk> {
    fn from_tree(top: expression::TreeIterItem) -> Result<Self, Error> {
        let top = top
            .verify_toplevel("wsh", 1..=1)
            .map_err(From::from)
            .map_err(Error::Parse)?;

        if top.name() == "sortedmulti" {
            return Ok(Wsh { inner: WshInner::SortedMulti(SortedMultiVec::from_tree(top)?) });
        }
        let sub = Miniscript::from_tree(top)?;
        Segwitv0::top_level_checks(&sub)?;
        Ok(Wsh { inner: WshInner::Ms(sub) })
    }
}

impl<Pk: FromStrKey> core::str::FromStr for Wsh<Pk> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let top = expression::Tree::from_str(s)?;
        Wsh::<Pk>::from_tree(top.root())
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for Wsh<Pk> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, pred: F) -> bool {
        match self.inner {
            WshInner::SortedMulti(ref smv) => smv.for_each_key(pred),
            WshInner::Ms(ref ms) => ms.for_each_key(pred),
        }
    }
}
