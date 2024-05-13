//! Various branch nodes produced by the hash builder.

use alloy_primitives::{keccak256, Bytes, B256};
use alloy_rlp::{length_of_length, Buf, Decodable, Encodable, Header, EMPTY_STRING_CODE};
use core::ops::Range;
use nybbles::Nibbles;

#[allow(unused_imports)]
use alloc::vec::Vec;

mod branch;
pub use branch::{BranchNode, BranchNodeCompact, BranchNodeRef};

mod extension;
pub use extension::{ExtensionNode, ExtensionNodeRef};

mod leaf;
pub use leaf::{LeafNode, LeafNodeRef};

/// The range of valid child indexes.
pub const CHILD_INDEX_RANGE: Range<u8> = 0..16;

/// Enum representing an MPR trie node.
#[derive(PartialEq, Eq, Debug)]
pub enum TrieNode {
    /// Variant representing a [BranchNode].
    Branch(BranchNode),
    /// Variant representing a [ExtensionNode].
    Extension(ExtensionNode),
    /// Variant representing a [LeafNode].
    Leaf(LeafNode),
}

impl Encodable for TrieNode {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Branch(branch) => branch.encode(out),
            Self::Extension(extension) => extension.encode(out),
            Self::Leaf(leaf) => leaf.encode(out),
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::Branch(branch) => branch.length(),
            Self::Extension(extension) => extension.length(),
            Self::Leaf(leaf) => leaf.length(),
        }
    }
}

impl Decodable for TrieNode {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut bytes = Header::decode_bytes(buf, true)?;

        let mut items = vec![];
        while !bytes.is_empty() {
            // Decode header without advancing.
            let Header { payload_length, .. } = Header::decode(&mut &bytes[..])?;
            let len = if payload_length == 1 {
                1 // If payload length is 1 byte, than there is no header
            } else {
                payload_length + length_of_length(payload_length)
            };
            items.push(bytes[..len].to_vec());
            bytes.advance(len);
        }

        if items.len() == 17 {
            let mut branch = BranchNode::default();
            for (idx, item) in items.into_iter().enumerate() {
                if idx == 16 {
                    if item != [EMPTY_STRING_CODE] {
                        return Err(alloy_rlp::Error::Custom(
                            "branch node values are not supported",
                        ));
                    }
                } else if item != [EMPTY_STRING_CODE] {
                    branch.stack.push(item);
                    branch.state_mask.set_bit(idx as u8);
                }
            }
            return Ok(Self::Branch(branch));
        }

        if items.len() == 2 {
            let key = items.remove(0);

            let encoded_key = Bytes::decode(&mut &key[..])?;
            if encoded_key.is_empty() {
                return Err(alloy_rlp::Error::Custom("trie node key empty"));
            }

            let key_flag = encoded_key[0] & 0xf0;
            // Retrieve first byte. If it's [Some], then the nibbles are odd.
            let first = match key_flag {
                0x10 | 0x30 => Some(encoded_key[0] & 0x0f),
                0x00 | 0x20 => None,
                _ => return Err(alloy_rlp::Error::Custom("node is not extension or leaf")),
            };

            let key = unpack_path_to_nibbles(first, &encoded_key[1..]);
            let node = if key_flag == 0x20 || key_flag == 0x30 {
                Self::Leaf(LeafNode::new(key, Bytes::decode(&mut &items.remove(0)[..])?.to_vec()))
            } else {
                Self::Extension(ExtensionNode::new(key, items.remove(0)))
            };
            return Ok(node);
        }

        Err(alloy_rlp::Error::Custom("invalid number of items in the list"))
    }
}

impl TrieNode {
    /// RLP encodes the node and returns either RLP(Node) or RLP(keccak(RLP(node))).
    pub fn rlp(&self, buf: &mut Vec<u8>) -> Vec<u8> {
        self.encode(buf);
        rlp_node(buf)
    }
}

/// Given an RLP encoded node, returns either RLP(node) or RLP(keccak(RLP(node)))
#[inline]
pub(crate) fn rlp_node(rlp: &[u8]) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrieMask;
    use alloy_primitives::hex;

    #[test]
    fn rlp_trie_node_roundtrip() {
        // leaf
        let leaf = TrieNode::Leaf(LeafNode::new(
            Nibbles::from_nibbles_unchecked(hex!("0604060f")),
            hex!("76657262").to_vec(),
        ));
        let rlp = leaf.rlp(&mut vec![]);
        assert_eq!(rlp, hex!("c98320646f8476657262"));
        assert_eq!(TrieNode::decode(&mut &rlp[..]).unwrap(), leaf);

        // extension
        let mut child = vec![];
        hex!("76657262").to_vec().as_slice().encode(&mut child);
        let extension = TrieNode::Extension(ExtensionNode::new(
            Nibbles::from_nibbles_unchecked(hex!("0604060f")),
            child,
        ));
        let rlp = extension.rlp(&mut vec![]);
        assert_eq!(rlp, hex!("c98300646f8476657262"));
        assert_eq!(TrieNode::decode(&mut &rlp[..]).unwrap(), extension);

        // branch
        let branch = TrieNode::Branch(BranchNode::new(
            core::iter::repeat(word_rlp(&B256::repeat_byte(23))).take(16).collect(),
            TrieMask::new(u16::MAX),
        ));
        let mut rlp = vec![];
        let rlp_node = branch.rlp(&mut rlp);
        assert_eq!(
            rlp_node,
            hex!("a0bed74980bbe29d9c4439c10e9c451e29b306fe74bcf9795ecf0ebbd92a220513")
        );
        assert_eq!(rlp, hex!("f90211a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a01717171717171717171717171717171717171717171717171717171717171717a0171717171717171717171717171717171717171717171717171717171717171780"));
        assert_eq!(TrieNode::decode(&mut &rlp[..]).unwrap(), branch);
    }
}
