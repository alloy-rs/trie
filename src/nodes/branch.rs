use super::{super::TrieMask, rlp_node, CHILD_INDEX_RANGE};
use alloy_primitives::{hex, B256};
use alloy_rlp::{length_of_length, Buf, BufMut, Decodable, Encodable, Header, EMPTY_STRING_CODE};
use core::fmt;

#[allow(unused_imports)]
use alloc::vec::Vec;

/// A branch node in an Merkle Patricia Trie is a 17-element array consisting of 16 slots that
/// correspond to each hexadecimal character and an additional slot for a value. We do exclude
/// the node value since all paths have a fixed size.
#[derive(PartialEq, Eq, Default)]
pub struct BranchNode {
    /// The collection of RLP encoded children.
    pub stack: Vec<Vec<u8>>,
    /// The bitmask indicating the presence of children at the respective nibble positions
    pub state_mask: TrieMask,
}

impl fmt::Debug for BranchNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BranchNode")
            .field("stack", &self.stack.iter().map(hex::encode).collect::<Vec<_>>())
            .field("state_mask", &self.state_mask)
            .field("first_child_index", &self.as_ref().first_child_index())
            .finish()
    }
}

impl Encodable for BranchNode {
    fn encode(&self, out: &mut dyn BufMut) {
        self.as_ref().encode(out)
    }

    fn length(&self) -> usize {
        self.as_ref().length()
    }
}

impl Decodable for BranchNode {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut bytes = Header::decode_bytes(buf, true)?;

        let mut stack = Vec::new();
        let mut state_mask = TrieMask::default();
        for index in CHILD_INDEX_RANGE {
            // The buffer must contain empty string code for value.
            if bytes.len() <= 1 {
                return Err(alloy_rlp::Error::InputTooShort);
            }

            if bytes[0] == EMPTY_STRING_CODE {
                bytes.advance(1);
                continue;
            }

            if bytes.len() < 32 {
                return Err(alloy_rlp::Error::InputTooShort);
            }

            state_mask.set_bit(index);
            stack.push(Vec::from(&bytes[..32]));
            bytes.advance(32);
        }

        // Consume empty string code for branch node value.
        bytes.advance(1);

        Ok(Self { stack, state_mask })
    }
}

impl BranchNode {
    /// Creates a new branch node with the given stack and state mask.
    pub fn new(stack: Vec<Vec<u8>>, state_mask: TrieMask) -> Self {
        Self { stack, state_mask }
    }
    /// Return branch node as [BranchNodeRef].
    pub fn as_ref(&self) -> BranchNodeRef<'_> {
        BranchNodeRef::new(&self.stack, &self.state_mask)
    }
}

/// A reference to [BranchNode] and its state mask.
/// NOTE: The stack may contain more items that specified in the state mask.
#[derive(Clone)]
pub struct BranchNodeRef<'a> {
    /// Reference to the collection of RLP encoded nodes.
    /// NOTE: The referenced stack might have more items than the number of children
    /// for this node. We should only ever access items starting from
    /// [BranchNodeRef::first_child_index].
    pub stack: &'a [Vec<u8>],
    /// Reference to bitmask indicating the presence of children at
    /// the respective nibble positions.
    pub state_mask: &'a TrieMask,
}

impl fmt::Debug for BranchNodeRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BranchNodeRef")
            .field("stack", &self.stack.iter().map(hex::encode).collect::<Vec<_>>())
            .field("state_mask", &self.state_mask)
            .field("first_child_index", &self.first_child_index())
            .finish()
    }
}

/// Implementation of RLP encoding for branch node in Ethereum Merkle Patricia Trie.
/// Encode it as a 17-element list consisting of 16 slots that correspond to
/// each child of the node (0-f) and an additional slot for a value.
impl Encodable for BranchNodeRef<'_> {
    fn encode(&self, out: &mut dyn BufMut) {
        Header { list: true, payload_length: self.rlp_payload_length() }.encode(out);

        // Extend the RLP buffer with the present children
        let mut stack_ptr = self.first_child_index();
        for index in CHILD_INDEX_RANGE {
            if self.state_mask.is_bit_set(index) {
                out.put_slice(&self.stack[stack_ptr]);
                // Advance the pointer to the next child.
                stack_ptr += 1;
            } else {
                out.put_u8(EMPTY_STRING_CODE)
            }
        }

        out.put_u8(EMPTY_STRING_CODE);
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_payload_length();
        payload_length + length_of_length(payload_length)
    }
}

impl<'a> BranchNodeRef<'a> {
    /// Create a new branch node from the stack of nodes.
    pub const fn new(stack: &'a [Vec<u8>], state_mask: &'a TrieMask) -> Self {
        Self { stack, state_mask }
    }

    /// Returns the stack index of the first child for this node.
    ///
    /// # Panics
    ///
    /// If the stack length is less than number of children specified in state mask.
    /// Means that the node is in inconsistent state.
    pub fn first_child_index(&self) -> usize {
        self.stack.len().checked_sub(self.state_mask.count_ones() as usize).unwrap()
    }

    /// Given the hash and state mask of children present, return an iterator over the stack items
    /// that match the mask.
    pub fn children(&self, hash_mask: TrieMask) -> Vec<B256> {
        let mut stack_ptr = self.first_child_index();
        let mut children = Vec::with_capacity(hash_mask.count_ones() as usize);
        for index in CHILD_INDEX_RANGE {
            if self.state_mask.is_bit_set(index) {
                if hash_mask.is_bit_set(index) {
                    children.push(B256::from_slice(&self.stack[stack_ptr][1..]));
                }
                stack_ptr += 1;
            }
        }
        children
    }

    /// Returns the RLP encoding of the branch node given the state mask of children present.
    pub fn rlp(&self, out: &mut Vec<u8>) -> Vec<u8> {
        self.encode(out);
        rlp_node(out)
    }

    /// Returns the length of RLP encoded fields of branch node.
    fn rlp_payload_length(&self) -> usize {
        let mut payload_length = 1;

        let mut stack_ptr = self.first_child_index();
        for digit in CHILD_INDEX_RANGE {
            if self.state_mask.is_bit_set(digit) {
                payload_length += self.stack[stack_ptr].len();
                // Advance the pointer to the next child.
                stack_ptr += 1;
            } else {
                payload_length += 1;
            }
        }
        payload_length
    }
}

/// A struct representing a branch node in an Ethereum trie.
///
/// A branch node can have up to 16 children, each corresponding to one of the possible nibble
/// values (0 to 15) in the trie's path.
///
/// The masks in a BranchNode are used to efficiently represent and manage information about the
/// presence and types of its children. They are bitmasks, where each bit corresponds to a nibble
/// (half-byte, or 4 bits) value from 0 to 15.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BranchNodeCompact {
    /// The bitmask indicating the presence of children at the respective nibble positions in the
    /// trie. If the bit at position i (counting from the right) is set (1), it indicates that a
    /// child exists for the nibble value i. If the bit is unset (0), it means there is no child
    /// for that nibble value.
    pub state_mask: TrieMask,
    /// The bitmask representing the internal (unhashed) children at the
    /// respective nibble positions in the trie. If the bit at position `i` (counting from the
    /// right) is set (1) and also present in the state_mask, it indicates that the
    /// corresponding child at the nibble value `i` is an internal child. If the bit is unset
    /// (0), it means the child is not an internal child.
    pub tree_mask: TrieMask,
    /// The bitmask representing the hashed children at the respective nibble
    /// positions in the trie. If the bit at position `i` (counting from the right) is set (1) and
    /// also present in the state_mask, it indicates that the corresponding child at the nibble
    /// value `i` is a hashed child. If the bit is unset (0), it means the child is not a
    /// hashed child.
    pub hash_mask: TrieMask,
    /// Collection of hashes associated with the children of the branch node.
    /// Each child hash is calculated by hashing two consecutive sub-branch roots.
    pub hashes: Vec<B256>,
    /// An optional root hash of the subtree rooted at this branch node.
    pub root_hash: Option<B256>,
}

impl BranchNodeCompact {
    /// Creates a new [BranchNodeCompact] from the given parameters.
    pub fn new(
        state_mask: impl Into<TrieMask>,
        tree_mask: impl Into<TrieMask>,
        hash_mask: impl Into<TrieMask>,
        hashes: Vec<B256>,
        root_hash: Option<B256>,
    ) -> Self {
        let (state_mask, tree_mask, hash_mask) =
            (state_mask.into(), tree_mask.into(), hash_mask.into());
        assert!(tree_mask.is_subset_of(state_mask));
        assert!(hash_mask.is_subset_of(state_mask));
        assert_eq!(hash_mask.count_ones() as usize, hashes.len());
        Self { state_mask, tree_mask, hash_mask, hashes, root_hash }
    }

    /// Returns the hash associated with the given nibble.
    pub fn hash_for_nibble(&self, nibble: u8) -> B256 {
        let mask = *TrieMask::from_nibble(nibble) - 1;
        let index = (*self.hash_mask & mask).count_ones();
        self.hashes[index as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlp_branch_node_roundtrip() {
        let empty = BranchNode::default();
        let mut buf = vec![];
        empty.encode(&mut buf);
        assert_eq!(BranchNode::decode(&mut &buf[..]).unwrap(), empty);

        let sparse_node = BranchNode::new(vec![vec![1; 32], vec![2; 32]], TrieMask::new(0b1000100));
        let mut buf = vec![];
        sparse_node.encode(&mut buf);
        assert_eq!(BranchNode::decode(&mut &buf[..]).unwrap(), sparse_node);

        let full = BranchNode::new(
            core::iter::repeat(vec![0x23; 32]).take(16).collect(),
            TrieMask::new(u16::MAX),
        );
        let mut buf = vec![];
        full.encode(&mut buf);
        assert_eq!(BranchNode::decode(&mut &buf[..]).unwrap(), full);
    }
}
