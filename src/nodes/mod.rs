//! Various branch nodes produced by the hash builder.

use alloy_primitives::{keccak256, B256};
use alloy_rlp::EMPTY_STRING_CODE;
use core::ops::Range;
use nybbles::Nibbles;

#[allow(unused_imports)]
use alloc::vec::Vec;

mod branch;
pub use branch::{BranchNode, BranchNodeCompact};

mod extension;
pub use extension::{ExtensionNode, ExtensionNodeRef};

mod leaf;
pub use leaf::{LeafNode, LeafNodeRef};

/// The range of valid child indexes.
pub const CHILD_INDEX_RANGE: Range<u8> = 0..16;

/// Given an RLP encoded node, returns either RLP(node) or RLP(keccak(RLP(node)))
#[inline]
fn rlp_node(rlp: &[u8]) -> Vec<u8> {
    if rlp.len() < B256::len_bytes() {
        rlp.to_vec()
    } else {
        word_rlp(&keccak256(rlp))
    }
}

/// Optimization for quick encoding of a 32-byte word as RLP.
// TODO: this could return [u8; 33] but Vec is needed everywhere this function is used
#[inline]
pub fn word_rlp(word: &B256) -> Vec<u8> {
    // Gets optimized to alloc + write directly into it: https://godbolt.org/z/rfWGG6ebq
    let mut arr = [0; 33];
    arr[0] = EMPTY_STRING_CODE + 32;
    arr[1..].copy_from_slice(word.as_slice());
    arr.to_vec()
}

/// Unpack node path to nibbles.
///
/// NOTE: The first nibble should be less than or equal to `0xf` if provided.
/// If first nibble is greater than `0xf`, the method will not panic, but initialize invalid nibbles
/// instead.
///
/// ## Arguments
///
/// `first` - first nibble of the path if it is odd
/// `rest` - rest of the nibbles packed
pub(crate) fn unpack_path_to_nibbles(first: Option<u8>, rest: &[u8]) -> Nibbles {
    let is_odd = first.is_some();
    let len = rest.len() * 2 + is_odd as usize;
    let mut nibbles = Vec::with_capacity(len);
    unsafe {
        let ptr: *mut u8 = nibbles.as_mut_ptr();
        let rest = rest.iter().copied().flat_map(|b| [b >> 4, b & 0x0f]);
        for (i, nibble) in first.into_iter().chain(rest).enumerate() {
            ptr.add(i).write(nibble)
        }
        nibbles.set_len(len);
    }
    Nibbles::from_vec_unchecked(nibbles)
}
