use crate::{Nibbles, TrieMask};

/// Used by the [`crate::proof::ProofRetainer`] to determine which nodes may be ancestors of newly
/// added or removed leaves. This information allows for generation of more complete proofs which
/// include the nodes necessary for adding and removing leaves from the trie.
pub trait AddedRemovedKeys {
    /// Returns true if the given path prefix is the prefix of an added key.
    ///
    /// True should be returned optimistically; if a prefix only has the possibility of being added
    /// it is better to return true for it. This may result in more proofs than necessary being
    /// returned, but that's better than a missing proof.
    fn is_prefix_added(&self, prefix: &Nibbles) -> bool;

    /// Returns a mask containing a bit set for each child of the branch which may be considered
    /// removed.
    ///
    /// Bits should be set optimistically; if a child only has the possibility of being removed it
    /// is better to return a bit for it. Extra bits on the mask may result in more proofs than
    /// necessary being returned, but that's better than a missing proof.
    fn get_removed_mask(&self, branch_path: &Nibbles) -> TrieMask;
}

/// An implementation of [`AddedRemovedKeys`] which assumes no added or removed keys.
#[derive(Debug, Copy, Clone, Default)]
pub struct EmptyAddedRemovedKeys;

impl AddedRemovedKeys for EmptyAddedRemovedKeys {
    fn is_prefix_added(&self, _prefix: &Nibbles) -> bool {
        false
    }

    fn get_removed_mask(&self, _branch_path: &Nibbles) -> TrieMask {
        TrieMask::default()
    }
}
