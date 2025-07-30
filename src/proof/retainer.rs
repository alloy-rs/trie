use crate::{Nibbles, TrieMask, proof::ProofNodes};
use alloy_primitives::Bytes;
use alloy_rlp::EMPTY_STRING_CODE;

use alloc::vec::Vec;

/// Tracks various datapoints related to already-seen proofs which may or may not have been
/// retained in the outer [`ProofRetainer`].
///
/// "target" refers those paths/proofs which are retained by the [`ProofRetainer`], as determined
/// by its `target` field.
#[derive(Default, Clone, Debug)]
struct SeenProofs {
    last_target_leaf_path: Nibbles,
    last_nontarget_path: Nibbles,
    last_nontarget_proof: Vec<u8>,
}

impl SeenProofs {
    /// Stores the path of the most recently seen target leaf.
    fn retain_target_leaf(&mut self, path: &Nibbles) {
        self.last_target_leaf_path = *path;
    }

    /// Stores the path and proof of the most recently seen path/proof which were not retained.
    fn retain_nontarget(&mut self, path: &Nibbles, proof: &[u8]) {
        self.last_nontarget_path = *path;
        self.last_nontarget_proof.clear();
        self.last_nontarget_proof.extend(proof);
    }

    /// Checks if a branch node is parent to both last target leaf and last non-target node.
    fn branch_is_parent(&self, path: &Nibbles) -> bool {
        self.last_target_leaf_path.len() == path.len() + 1
            && self.last_nontarget_path.len() == path.len() + 1
            && self.last_target_leaf_path.starts_with(path)
            && self.last_nontarget_path.starts_with(path)
    }

    /// Checks if an extension node is parent to the last non-target node.
    fn extension_child_is_nontarget(&self, path: &Nibbles, short_key: &Nibbles) -> bool {
        path.len() + short_key.len() == self.last_nontarget_path.len()
            && self.last_nontarget_path.starts_with(path)
            && self.last_nontarget_path.ends_with(short_key)
    }
}

/// Proof retainer is used to store proofs during merkle trie construction.
/// It is intended to be used within the [`HashBuilder`](crate::HashBuilder).
#[derive(Default, Clone, Debug)]
pub struct ProofRetainer {
    /// The nibbles of the target trie keys to retain proofs for.
    targets: Vec<Nibbles>,
    /// The map retained trie node keys to RLP serialized trie nodes.
    proof_nodes: ProofNodes,
    /// Tracks data related to previously seen proofs; required for certain edge-cases where we
    /// want to keep proofs for nodes which aren't in the target set.
    seen_proofs: Option<SeenProofs>,
}

impl FromIterator<Nibbles> for ProofRetainer {
    fn from_iter<T: IntoIterator<Item = Nibbles>>(iter: T) -> Self {
        Self::new(FromIterator::from_iter(iter))
    }
}

impl ProofRetainer {
    /// Create new retainer with target nibbles.
    pub fn new(targets: Vec<Nibbles>) -> Self {
        Self { targets, ..Default::default() }
    }

    /// Configures the retainer to retain proofs for certain nodes which would otherwise fall
    /// outside the target set, when those nodes might be required for performing leaf
    /// addition/removal.
    pub fn with_leaf_additions_removals(mut self, keep: bool) -> Self {
        self.seen_proofs = keep.then(Default::default);
        self
    }

    /// Returns `true` if the given prefix matches the retainer target.
    pub fn matches(&self, prefix: &Nibbles) -> bool {
        prefix.is_empty() || self.targets.iter().any(|target| target.starts_with(prefix))
    }

    /// Returns all collected proofs.
    pub fn into_proof_nodes(self) -> ProofNodes {
        self.proof_nodes
    }

    /// Retain the proof if the key matches any of the targets.
    ///
    /// Usage of this method should be replaced with usage of the following methods, each dependent
    /// on the node-type whose proof being retained:
    /// - `retain_empty_root_proof`
    /// - `retain_leaf_proof`
    /// - `retain_extension_proof`
    /// - `retain_branch_proof`
    #[deprecated]
    pub fn retain(&mut self, prefix: &Nibbles, proof: &[u8]) {
        if self.matches(prefix) {
            self.retain_unchecked(*prefix, Bytes::copy_from_slice(proof));
        }
    }

    /// Retain the proof with no checks being performed.
    fn retain_unchecked(&mut self, prefix: Nibbles, proof: Bytes) {
        tracing::trace!(
            target: "trie::proof_retainer",
            path = ?prefix,
            proof = alloy_primitives::hex::encode(&proof),
            "Retaining proof",
        );
        self.proof_nodes.insert(prefix, proof);
    }

    /// Retains a proof for an empty root.
    pub fn retain_empty_root_proof(&mut self) {
        self.retain_unchecked(Nibbles::default(), [EMPTY_STRING_CODE].into())
    }

    /// Retains a proof for a leaf node.
    pub fn retain_leaf_proof(&mut self, prefix: &Nibbles, proof: &[u8]) {
        let is_target = if self.matches(prefix) {
            self.retain_unchecked(*prefix, Bytes::copy_from_slice(proof));
            true
        } else {
            false
        };

        if let Some(seen_proofs) = self.seen_proofs.as_mut() {
            if is_target {
                seen_proofs.retain_target_leaf(prefix);
            } else {
                seen_proofs.retain_nontarget(prefix, proof);
            }
        }
    }

    /// Retains a proof for an extension node.
    pub fn retain_extension_proof(&mut self, prefix: &Nibbles, short_key: &Nibbles, proof: &[u8]) {
        if self.matches(prefix) {
            self.retain_unchecked(*prefix, Bytes::copy_from_slice(proof));

            // When a new leaf is being added to a trie, it can happen that an extension node's
            // path is a prefix of the new leaf's, but the extension child's path is not. In
            // this case a new branch node is created; the new leaf is one child, the previous
            // branch node is its other, and the extension node is its parent.
            //
            //            Before │ After
            //                   │
            //   ┌───────────┐   │    ┌───────────┐
            //   │ Extension │   │    │ Extension │
            //   └─────┬─────┘   │    └─────┬─────┘
            //         │         │          │
            //         │         │    ┌─────┴──────┐
            //         │         │    │ New Branch │
            //         │         │    └─────┬───┬──┘
            //         │         │          │   └─────┐
            //   ┌─────┴────┐    │    ┌─────┴────┐  ┌─┴────────┐
            //   │  Branch  │    │    │  Branch  │  │ New Leaf │
            //   └──────────┘    │    └──────────┘  └──────────┘
            //
            // In this case the new leaf's proof will be retained, as will the extension's because
            // its path is a prefix of the leaf's. But the old branch's proof won't necessarily be
            // retained, as its path is not a prefix of the leaf's. In order to support this case
            // retain the proof for non-target children of target extensions.
            //
            if let Some(seen_proofs) = self.seen_proofs.as_ref() {
                if seen_proofs.extension_child_is_nontarget(prefix, short_key) {
                    self.retain_unchecked(
                        seen_proofs.last_nontarget_path,
                        Bytes::copy_from_slice(&seen_proofs.last_nontarget_proof),
                    );
                }
            }
        } else if let Some(seen_proofs) = self.seen_proofs.as_mut() {
            seen_proofs.retain_nontarget(prefix, proof);
        }
    }

    /// Retains a proof for a branch node.
    pub fn retain_branch_proof(&mut self, prefix: &Nibbles, state_mask: TrieMask, proof: &[u8]) {
        if self.matches(prefix) {
            self.retain_unchecked(*prefix, Bytes::copy_from_slice(proof));

            // When removing a leaf node from the trie, and the leaf node's branch only has one
            // other child, that branch gets "collapsed" into its parent branch/extension, i.e. it
            // is deleted and the remaining child is adopted by its grandparent.
            //
            //                           Before │ After
            //                                  │
            //   ┌───────────────┐              │    ┌───────────────┐
            //   │  Grandparent  │              │    │  Grandparent  │
            //   │  Branch       │              │    │  Branch       │
            //   └──┬───┬───┬────┘              │    └──┬───┬───┬────┘
            //      :   :   │                   │       :   :   │
            //              │                   │               │
            //   ┌──────────┴──────┐            │               │
            //   │  Parent Branch  │            │               │
            //   └──────────┬──┬───┘            │               │
            //              │  └─────┐          │               │
            //   ┌──────────┴─────┐ ┌┴─────┐    │    ┌──────────┴─────┐
            //   │  Child Branch  │ │ Leaf │    │    │  Child Branch  │
            //   └──┬───┬───┬─────┘ └──────┘    │    └────────────────┘
            //      :   :   :                   │
            //
            // The adopted child can also be a leaf or extension, which can affect what happens to
            // the grandparent, so it must have a proof in order to perform a collapse. The proof
            // of the removed leaf will always be retained, but it can happen that the remaining
            // child will not be in the `changes` set and so would not be retained.
            //
            // To get around this we check here if the branch node has only two children, and if
            // those children are respectively a retained leaf and an unretained child of any type.
            // If so we retain the previously-unretained child, in case the leaf ends up getting
            // removed.
            //
            if let Some(seen_proofs) = self.seen_proofs.as_ref() {
                if state_mask.count_ones() == 2 && seen_proofs.branch_is_parent(prefix) {
                    self.retain_unchecked(
                        seen_proofs.last_nontarget_path,
                        Bytes::copy_from_slice(&seen_proofs.last_nontarget_proof),
                    );
                }
            }
        } else if let Some(seen_proofs) = self.seen_proofs.as_mut() {
            seen_proofs.retain_nontarget(prefix, proof);
        }
    }
}
