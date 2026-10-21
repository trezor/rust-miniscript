// SPDX-License-Identifier: CC0-1.0

use bitcoin::{opcodes, ScriptBuf};
use sync::Arc;

use crate::expression::{self, FromTree};
use crate::miniscript::Miniscript;
use crate::prelude::*;
use crate::{
    Error, ForEachKey, FromStrKey, MiniscriptKey, ParseError, ScriptContext, Tap,
    ToPublicKey, TranslateErr, Translator,
};

mod spend_info;
mod taptree;

pub use self::spend_info::{TrSpendInfo, TrSpendInfoIter, TrSpendInfoIterItem};
pub use self::taptree::{TapTree, TapTreeDepthError, TapTreeIter, TapTreeIterItem};

/// A taproot descriptor
pub struct Tr<Pk: MiniscriptKey> {
    /// A taproot internal key
    internal_key: Pk,
    /// Optional Taproot Tree with spending conditions
    tree: Option<TapTree<Pk>>,
    /// Optional spending information associated with the descriptor
    /// This will be [`None`] when the descriptor is not derived.
    /// This information will be cached automatically when it is required
    //
    // The inner `Arc` here is because Rust does not allow us to return a reference
    // to the contents of the `Option` from inside a `MutexGuard`. There is no outer
    // `Arc` because when this structure is cloned, we create a whole new mutex.
    spend_info: Mutex<Option<Arc<TrSpendInfo<Pk>>>>,
}

impl<Pk: MiniscriptKey> Clone for Tr<Pk> {
    fn clone(&self) -> Self {
        // When cloning, construct a new Mutex so that distinct clones don't
        // cause blocking between each other. We clone only the internal `Arc`,
        // so the clone is always cheap (in both time and space)
        Self {
            internal_key: self.internal_key.clone(),
            tree: self.tree.clone(),
            spend_info: Mutex::new(
                self.spend_info
                    .lock()
                    .expect("Lock poisoned")
                    .as_ref()
                    .map(Arc::clone),
            ),
        }
    }
}

impl<Pk: MiniscriptKey> PartialEq for Tr<Pk> {
    fn eq(&self, other: &Self) -> bool {
        self.internal_key == other.internal_key && self.tree == other.tree
    }
}

impl<Pk: MiniscriptKey> Eq for Tr<Pk> {}

impl<Pk: MiniscriptKey> Tr<Pk> {
    /// Create a new [`Tr`] descriptor from internal key and [`TapTree`]
    pub fn new(internal_key: Pk, tree: Option<TapTree<Pk>>) -> Result<Self, Error> {
        Tap::check_pk(&internal_key)?;
        Ok(Self { internal_key, tree, spend_info: Mutex::new(None) })
    }

    /// Obtain the internal key of [`Tr`] descriptor
    pub fn internal_key(&self) -> &Pk { &self.internal_key }

    /// Obtain the [`TapTree`] of the [`Tr`] descriptor
    pub fn tap_tree(&self) -> Option<&TapTree<Pk>> { self.tree.as_ref() }

    /// Iterates over all the leaves of the tree in depth-first preorder.
    ///
    /// The yielded elements include the Miniscript for each leave as well as its depth
    /// in the tree, which is the data required by PSBT (BIP 371).
    pub fn leaves(&self) -> TapTreeIter<'_, Pk> {
        match self.tree {
            Some(ref t) => t.leaves(),
            None => TapTreeIter::empty(),
        }
    }

    /// Obtain the spending information for this [`Tr`].
    ///
    /// The first time this method is called, it computes the full Taproot Merkle tree of
    /// all branches as well as the output key which appears on-chain. This is fairly
    /// expensive since it requires hashing every branch and then doing an elliptic curve
    /// operation. The result is cached and reused on subsequent calls.
    ///
    /// This data is needed to compute the Taproot output, so this method is implicitly
    /// called through [`Self::script_pubkey`], [`Self::address`], etc. It is also needed
    /// to compute the hash needed to sign the output.
    pub fn spend_info(&self) -> Arc<TrSpendInfo<Pk>>
    where
        Pk: ToPublicKey,
    {
        let mut lock = self.spend_info.lock().unwrap();
        match *lock {
            Some(ref res) => Arc::clone(res),
            None => {
                let arc = Arc::new(TrSpendInfo::from_tr(self));
                *lock = Some(Arc::clone(&arc));
                arc
            }
        }
    }

    /// Checks whether the descriptor is safe.
    pub fn sanity_check(&self) -> Result<(), Error> {
        for leaf in self.leaves() {
            leaf.miniscript().sanity_check()?;
        }
        Ok(())
    }

    /// Converts keys from one type of public key to another.
    pub fn translate_pk<T>(
        &self,
        translate: &mut T,
    ) -> Result<Tr<T::TargetPk>, TranslateErr<T::Error>>
    where
        T: Translator<Pk>,
    {
        let tree = match &self.tree {
            Some(tree) => Some(tree.translate_pk(translate)?),
            None => None,
        };
        let translate_desc =
            Tr::new(translate.pk(&self.internal_key)?, tree).map_err(TranslateErr::OuterError)?;
        Ok(translate_desc)
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Tr<Pk> {
    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn script_pubkey(&self) -> ScriptBuf {
        let output_key = self.spend_info().output_key();
        let builder = bitcoin::blockdata::script::Builder::new();
        builder
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .push_slice(output_key.serialize())
            .into_script()
    }
}

impl<Pk: FromStrKey> core::str::FromStr for Tr<Pk> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let expr_tree = expression::Tree::from_str(s)?;
        Self::from_tree(expr_tree.root())
    }
}

impl<Pk: FromStrKey> crate::expression::FromTree for Tr<Pk> {
    fn from_tree(root: expression::TreeIterItem) -> Result<Self, Error> {
        use crate::expression::{Parens, ParseTreeError};

        root.verify_toplevel("tr", 1..=2)
            .map_err(From::from)
            .map_err(Error::Parse)?;

        let mut root_children = root.children();
        let internal_key: Pk = root_children
            .next()
            .unwrap() // `verify_toplevel` above checked that first child existed
            .verify_terminal("internal key")
            .map_err(Error::Parse)?;

        let tap_tree = match root_children.next() {
            None => return Tr::new(internal_key, None),
            Some(tree) => tree,
        };

        let mut tree_builder = taptree::TapTreeBuilder::new();
        let mut tap_tree_iter = tap_tree.pre_order_iter();
        // while let construction needed because we modify the iterator inside the loop
        // (by calling skip_descendants to skip over the contents of the tapscripts).
        while let Some(node) = tap_tree_iter.next() {
            if node.parens() == Parens::Curly {
                if !node.name().is_empty() {
                    return Err(Error::Parse(ParseError::Tree(ParseTreeError::IncorrectName {
                        actual: node.name().to_owned(),
                        expected: "",
                    })));
                }
                node.verify_n_children("taptree branch", 2..=2)
                    .map_err(From::from)
                    .map_err(Error::Parse)?;
                tree_builder.push_inner_node()?;
            } else {
                let script = Miniscript::from_tree(node)?;
                // FIXME hack for https://github.com/rust-bitcoin/rust-miniscript/issues/734
                if script.ty.corr.base != crate::miniscript::types::Base::B {
                    return Err(Error::NonTopLevel);
                };

                tree_builder.push_leaf(script);
                tap_tree_iter.skip_descendants();
            }
        }
        Tr::new(internal_key, Some(tree_builder.finalize()))
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for Tr<Pk> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, mut pred: F) -> bool {
        let script_keys_res = self
            .leaves()
            .all(|leaf| leaf.miniscript().for_each_key(&mut pred));
        script_keys_res && pred(&self.internal_key)
    }
}
