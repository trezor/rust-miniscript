// Written in 2022 by Dr Maxim Orlovsky <orlovsky@pandoracore.com>
// SPDX-License-Identifier: CC0-1.0

//! Miniscript Iterators
//!
//! Iterators for Miniscript with special functions for iterating
//! over Public Keys, Public Key Hashes or both.
use core::ops::Deref;

use sync::Arc;

use super::decode::Terminal;
use super::{Miniscript, MiniscriptKey, ScriptContext};
use crate::prelude::*;

/// Iterator-related extensions for [Miniscript]
impl<Pk: MiniscriptKey, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
    /// Creates a new [Iter] iterator that will iterate over all [Miniscript] items within
    /// AST by traversing its branches. For the specific algorithm please see
    /// [Iter::next] function.
    pub fn iter(&self) -> Iter<'_, Pk, Ctx> { Iter::new(self) }

    /// Creates a new [PkIter] iterator that will iterate over all plain public keys (and not
    /// key hash values) present in [Miniscript] items within AST by traversing all its branches.
    /// For the specific algorithm please see [PkIter::next] function.
    pub fn iter_pk(&self) -> PkIter<'_, Pk, Ctx> { PkIter::new(self) }

    /// Enumerates all child nodes of the current AST node (`self`) and returns a `Vec` referencing
    /// them.
    pub fn branches(&self) -> Vec<&Miniscript<Pk, Ctx>> {
        match self.node {
            Terminal::PkK(_) | Terminal::PkH(_) | Terminal::RawPkH(_) | Terminal::Multi(_) => {
                vec![]
            }

            Terminal::Alt(ref node)
            | Terminal::Swap(ref node)
            | Terminal::Check(ref node)
            | Terminal::DupIf(ref node)
            | Terminal::Verify(ref node)
            | Terminal::NonZero(ref node)
            | Terminal::ZeroNotEqual(ref node) => vec![node],

            Terminal::AndV(ref node1, ref node2)
            | Terminal::AndB(ref node1, ref node2)
            | Terminal::OrB(ref node1, ref node2)
            | Terminal::OrD(ref node1, ref node2)
            | Terminal::OrC(ref node1, ref node2)
            | Terminal::OrI(ref node1, ref node2) => vec![node1, node2],

            Terminal::AndOr(ref node1, ref node2, ref node3) => vec![node1, node2, node3],

            Terminal::Thresh(ref thresh) => thresh.iter().map(Arc::deref).collect(),

            _ => vec![],
        }
    }

    /// Returns child node with given index, if any
    pub fn get_nth_child(&self, n: usize) -> Option<&Miniscript<Pk, Ctx>> {
        match (n, &self.node) {
            (0, Terminal::Alt(node))
            | (0, Terminal::Swap(node))
            | (0, Terminal::Check(node))
            | (0, Terminal::DupIf(node))
            | (0, Terminal::Verify(node))
            | (0, Terminal::NonZero(node))
            | (0, Terminal::ZeroNotEqual(node))
            | (0, Terminal::AndV(node, _))
            | (0, Terminal::AndB(node, _))
            | (0, Terminal::OrB(node, _))
            | (0, Terminal::OrD(node, _))
            | (0, Terminal::OrC(node, _))
            | (0, Terminal::OrI(node, _))
            | (1, Terminal::AndV(_, node))
            | (1, Terminal::AndB(_, node))
            | (1, Terminal::OrB(_, node))
            | (1, Terminal::OrD(_, node))
            | (1, Terminal::OrC(_, node))
            | (1, Terminal::OrI(_, node))
            | (0, Terminal::AndOr(node, _, _))
            | (1, Terminal::AndOr(_, node, _))
            | (2, Terminal::AndOr(_, _, node)) => Some(node),

            (n, Terminal::Thresh(thresh)) => thresh.data().get(n).map(|x| &**x),

            _ => None,
        }
    }

    /// Returns `Option::Some` with cloned n'th public key from the current miniscript item,
    /// if any. Otherwise returns `Option::None`.
    ///
    /// NB: The function analyzes only single miniscript item and not any of its descendants in AST.
    pub fn get_nth_pk(&self, n: usize) -> Option<Pk> {
        match (&self.node, n) {
            (Terminal::PkK(key), 0) | (Terminal::PkH(key), 0) => Some(key.clone()),
            (Terminal::Multi(thresh), _) => thresh.data().get(n).cloned(),
            (Terminal::MultiA(thresh), _) => thresh.data().get(n).cloned(),
            _ => None,
        }
    }
}

/// Iterator for traversing all [Miniscript] miniscript AST references starting from some specific
/// node which constructs the iterator via [Miniscript::iter] method.
pub struct Iter<'a, Pk: MiniscriptKey, Ctx: ScriptContext> {
    next: Option<&'a Miniscript<Pk, Ctx>>,
    // Here we store vec of path elements, where each element is a tuple, consisting of:
    // 1. Miniscript node on the path
    // 2. Index of the current branch
    path: Vec<(&'a Miniscript<Pk, Ctx>, usize)>,
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> Iter<'a, Pk, Ctx> {
    fn new(miniscript: &'a Miniscript<Pk, Ctx>) -> Self {
        Iter { next: Some(miniscript), path: vec![] }
    }
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> Iterator for Iter<'a, Pk, Ctx> {
    type Item = &'a Miniscript<Pk, Ctx>;

    /// First, the function returns `self`, then the first child of the self (if any),
    /// then proceeds to the child of the child — down to a leaf of the tree in its first branch.
    /// When the leaf is reached, it goes in the reverse direction on the same branch until it
    /// founds a first branching node that had more than a single branch and returns it, traversing
    /// it with the same algorithm again.
    ///
    /// For example, for the given AST
    /// ```text
    /// A --+--> B -----> C --+--> D -----> E
    ///     |                 |
    ///     |                 +--> F
    ///     |                 |
    ///     |                 +--> G --+--> H
    ///     |                          |
    ///     |                          +--> I -----> J
    ///     +--> K
    /// ```
    /// `Iter::next()` will iterate over the nodes in the following order:
    /// `A > B > C > D > E > F > G > H > I > J > K`
    ///
    /// To enumerate the branches iterator uses [Miniscript::branches] function.
    fn next(&mut self) -> Option<Self::Item> {
        let mut curr = self.next;
        if curr.is_none() {
            while let Some((node, child)) = self.path.pop() {
                curr = node.get_nth_child(child);
                if curr.is_some() {
                    self.path.push((node, child + 1));
                    break;
                }
            }
        }
        if let Some(node) = curr {
            self.next = node.get_nth_child(0);
            self.path.push((node, 1));
        }
        curr
    }
}

/// Iterator for traversing all [MiniscriptKey]'s in AST starting from some specific node which
/// constructs the iterator via [Miniscript::iter_pk] method.
pub struct PkIter<'a, Pk: MiniscriptKey, Ctx: ScriptContext> {
    node_iter: Iter<'a, Pk, Ctx>,
    curr_node: Option<&'a Miniscript<Pk, Ctx>>,
    key_index: usize,
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> PkIter<'a, Pk, Ctx> {
    fn new(miniscript: &'a Miniscript<Pk, Ctx>) -> Self {
        let mut iter = Iter::new(miniscript);
        PkIter { curr_node: iter.next(), node_iter: iter, key_index: 0 }
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Iterator for PkIter<'_, Pk, Ctx> {
    type Item = Pk;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.curr_node {
                None => break None,
                Some(node) => match node.get_nth_pk(self.key_index) {
                    None => {
                        self.curr_node = self.node_iter.next();
                        self.key_index = 0;
                        continue;
                    }
                    Some(pk) => {
                        self.key_index += 1;
                        break Some(pk);
                    }
                },
            }
        }
    }
}
