use crate::{Nibbles, TrieMask, proof::ProofNodes};
use alloy_primitives::{B256, Bytes};
use alloy_rlp::EMPTY_STRING_CODE;

use alloc::vec::Vec;

/// Tracks various datapoints related to already-seen proofs which may or may not have been
/// retained in the outer [`ProofRetainer`].
///
/// "target" refers those paths/proofs which are retained by the [`ProofRetainer`], as determined
/// by its `target` field.
#[derive(Clone, Debug)]
struct SeenProofs {
    last_nontarget_path: Nibbles,
    last_nontarget_proof: Vec<u8>,
    /// Tracks a mask for each branch node, with a bit set for children which are a target.
    /// Branches are indexed by their path length.
    branch_target_masks: Vec<TrieMask>,
}

impl Default for SeenProofs {
    fn default() -> Self {
        Self {
            last_nontarget_path: Default::default(),
            last_nontarget_proof: Default::default(),
            branch_target_masks: Vec::with_capacity(B256::ZERO.len() * 8),
        }
    }
}

impl SeenProofs {
    /// Stores the path and proof of the most recently seen path/proof which were not retained.
    fn retain_nontarget(&mut self, path: &Nibbles, proof: &[u8]) {
        self.last_nontarget_path = *path;
        self.last_nontarget_proof.clear();
        self.last_nontarget_proof.extend(proof);
    }

    /// Checks if an extension node is parent to the last non-target node.
    fn extension_child_is_nontarget(&self, path: &Nibbles, short_key: &Nibbles) -> bool {
        path.len() + short_key.len() == self.last_nontarget_path.len()
            && self.last_nontarget_path.starts_with(path)
            && self.last_nontarget_path.ends_with(short_key)
    }

    /// Returns mutable reference to the target mask for the branch at the given index, where the
    /// index is equivalent to the branch path's length.
    fn branch_target_mask_mut(&mut self, branch_idx: usize) -> &mut TrieMask {
        // Ensure the `branch_target_masks` Vec has been extended far enough so that this
        // branch index has a mask to work with.
        if self.branch_target_masks.len() <= branch_idx {
            self.branch_target_masks.resize(branch_idx + 1, TrieMask::default());
        }
        &mut self.branch_target_masks[branch_idx]
    }

    /// When passed the path of a node whose parent is a branch, this marks the bit for the child
    /// on that branch's mask.
    ///
    /// When passed the path of a node whose parent is _not_ a branch, this marks the bit in the
    /// corresponding mask anyway, but because there won't be a branch at that index the mask will
    /// be discarded.
    fn set_branch_child_target_bit(&mut self, path: &Nibbles) {
        let branch_idx = path.len() - 1;
        let child_bit = path.last().expect("root node cannot be a branch child");
        self.branch_target_mask_mut(branch_idx).set_bit(child_bit);
    }

    /// Removes the target mask for the branch of the given index, as well as all masks with a
    /// larger index.
    fn take_branch_target_mask(&mut self, branch_idx: usize) -> TrieMask {
        // There are cases where a branch will be a target but none of its children will be, e.g.
        // when a child is leaf which will be created
        if let Some(mask) = self.branch_target_masks.get(branch_idx).copied() {
            self.branch_target_masks.truncate(branch_idx);
            mask
        } else {
            TrieMask::default()
        }
    }
}

/// Proof retainer is used to store proofs during merkle trie construction.
/// It is intended to be used within the [`HashBuilder`](crate::HashBuilder).
///
/// When using the `retain_leaf_proof`, `retain_extension_proof`, and `retain_branch_proof`
/// methods, it is required that the calls are ordered such that proofs of parent nodes are
/// retained after their children.
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
        tracing::trace!(
            target: "trie::proof_retainer",
            ?targets,
            "Initializing",
        );
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
    fn retain_unchecked(&mut self, path: Nibbles, proof: Bytes) {
        tracing::trace!(
            target: "trie::proof_retainer",
            path = ?path,
            proof = alloy_primitives::hex::encode(&proof),
            "Retaining proof",
        );
        self.proof_nodes.insert(path, proof);
    }

    /// Retains a proof for an empty root.
    pub fn retain_empty_root_proof(&mut self) {
        self.retain_unchecked(Nibbles::default(), [EMPTY_STRING_CODE].into())
    }

    /// Retains a proof for a leaf node.
    pub fn retain_leaf_proof(&mut self, path: &Nibbles, proof: &[u8]) {
        let is_target = if self.matches(path) {
            self.retain_unchecked(*path, Bytes::copy_from_slice(proof));
            true
        } else {
            false
        };

        if let Some(seen_proofs) = self.seen_proofs.as_mut() {
            if is_target && !path.is_empty() {
                seen_proofs.set_branch_child_target_bit(path);
            } else {
                seen_proofs.retain_nontarget(path, proof);
            }
        }
    }

    /// Retains a proof for an extension node.
    pub fn retain_extension_proof(&mut self, path: &Nibbles, short_key: &Nibbles, proof: &[u8]) {
        if self.matches(path) {
            self.retain_unchecked(*path, Bytes::copy_from_slice(proof));

            if let Some(seen_proofs) = self.seen_proofs.as_mut() {
                if !path.is_empty() {
                    seen_proofs.set_branch_child_target_bit(path);
                }

                // When a new leaf is being added to a trie, it can happen that an extension node's
                // path is a path of the new leaf's, but the extension child's path is not. In this
                // case a new branch node is created; the new leaf is one child, the previous
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
                // In this case the new leaf's proof will be retained, as will the extension's
                // because its path is a path of the leaf's. But the old branch's proof won't
                // necessarily be retained, as its path is not a path of the leaf's. In order to
                // support this case retain the proof for non-target children of target extensions.
                //
                if seen_proofs.extension_child_is_nontarget(path, short_key) {
                    let last_nontarget_path = seen_proofs.last_nontarget_path;
                    let last_nontarget_proof =
                        Bytes::copy_from_slice(&seen_proofs.last_nontarget_proof);
                    self.retain_unchecked(last_nontarget_path, last_nontarget_proof);
                }
            }
        } else if let Some(seen_proofs) = self.seen_proofs.as_mut() {
            seen_proofs.retain_nontarget(path, proof);
        }
    }

    /// Retains a proof for a branch node.
    pub fn retain_branch_proof(&mut self, path: &Nibbles, state_mask: TrieMask, proof: &[u8]) {
        if self.matches(path) {
            self.retain_unchecked(*path, Bytes::copy_from_slice(proof));

            if let Some(seen_proofs) = self.seen_proofs.as_mut() {
                // Don't set branch target bit if this is the root, it has no parent
                if !path.is_empty() {
                    seen_proofs.set_branch_child_target_bit(path);
                }

                // Calculate non-target children for the next step
                let target_mask = seen_proofs.take_branch_target_mask(path.len());

                debug_assert_eq!(
                    state_mask | target_mask,
                    state_mask,
                    "target mask {target_mask:?} of {path:?} has extra bits set"
                );

                let nontarget_mask = !target_mask & state_mask;

                // When we remove all but one child from a branch, that branch gets "collapsed"
                // into its parent branch/extension, i.e. it is deleted and the remaining child is
                // adopted by its grandparent.
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
                //   └──┬───┬───┬─────┘ └──────┘    │    └──┬───┬───┬─────┘
                //      :   :   :                   │       :   :   :
                //
                // The adopted child can also be a leaf or extension, which can affect what happens
                // to the grandparent, so to perform a collapse we must retain a proof of the
                // adopted child.
                //
                // The proofs of the removed children will always be retained, but it can happen
                // that the remaining child will not be in the `target` set and so would not be
                // retained.
                //
                // The `target` set does not give us fine-grained context on whether nodes will be
                // removed or simply changed, so we have to be over-eager in retaining proofs and
                // always assume that if all children but one are targets, then we need to keep the
                // remaining non-target.
                if nontarget_mask.count_ones() == 1 {
                    let last_nontarget_path = seen_proofs.last_nontarget_path;
                    let last_nontarget_proof =
                        Bytes::copy_from_slice(&seen_proofs.last_nontarget_proof);
                    self.retain_unchecked(last_nontarget_path, last_nontarget_proof);
                }
            }
        } else if let Some(seen_proofs) = self.seen_proofs.as_mut() {
            seen_proofs.retain_nontarget(path, proof);
        }
    }
}
