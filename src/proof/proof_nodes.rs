use crate::{HashMap, Nibbles};
use core::ops::Deref;

#[allow(unused_imports)]
use alloc::vec::Vec;

/// A wrapper struct for trie node key to RLP encoded trie node.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ProofNodes<T>(HashMap<Nibbles, T>);

impl<T> Default for ProofNodes<T> {
    fn default() -> Self {
        Self(HashMap::default())
    }
}

impl<T> Deref for ProofNodes<T> {
    type Target = HashMap<Nibbles, T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> FromIterator<(Nibbles, T)> for ProofNodes<T> {
    fn from_iter<I: IntoIterator<Item = (Nibbles, T)>>(iter: I) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl<T> Extend<(Nibbles, T)> for ProofNodes<T> {
    fn extend<I: IntoIterator<Item = (Nibbles, T)>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

impl<T: Clone> ProofNodes<T> {
    /// Return iterator over proof nodes that match the target.
    pub fn matching_nodes_iter<'a>(
        &'a self,
        target: &'a Nibbles,
    ) -> impl Iterator<Item = (&'a Nibbles, &'a T)> {
        self.0.iter().filter(|(key, _)| target.starts_with(key))
    }

    /// Return the vec of proof nodes that match the target.
    pub fn matching_nodes(&self, target: &Nibbles) -> Vec<(Nibbles, T)> {
        self.matching_nodes_iter(target).map(|(key, node)| (key.clone(), node.clone())).collect()
    }

    /// Return the sorted vec of proof nodes that match the target.
    pub fn matching_nodes_sorted(&self, target: &Nibbles) -> Vec<(Nibbles, T)> {
        let mut nodes = self.matching_nodes(target);
        nodes.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        nodes
    }

    /// Insert the RLP encoded trie node at key.
    pub fn insert(&mut self, key: Nibbles, node: T) -> Option<T> {
        self.0.insert(key, node)
    }

    /// Return the sorted vec of all proof nodes.
    pub fn nodes_sorted(&self) -> Vec<(Nibbles, T)> {
        let mut nodes = Vec::from_iter(self.0.iter().map(|(k, v)| (k.clone(), v.clone())));
        nodes.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        nodes
    }

    /// Convert into sorted vec of all proof nodes.
    pub fn into_nodes_sorted(self) -> Vec<(Nibbles, T)> {
        let mut nodes = Vec::from_iter(self.0);
        nodes.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        nodes
    }

    /// Convert wrapper struct into inner map.
    pub fn into_inner(self) -> HashMap<Nibbles, T> {
        self.0
    }

    /// Extends with the elements of another `ProofNodes`.
    pub fn extend_from(&mut self, other: Self) {
        self.extend(other.0);
    }
}
