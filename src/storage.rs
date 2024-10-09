use bytes::Buf;
use reth_codecs::Compact;
use revm_primitives::B256;
use serde::{Deserialize, Serialize};

use crate::{BranchNodeCompact, StoredNibblesSubKey, TrieMask};

/// Account storage trie node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct StorageTrieEntry {
    /// The nibbles of the intermediate node
    pub nibbles: StoredNibblesSubKey,
    /// Encoded node.
    pub node: BranchNodeCompact,
}

impl Compact for TrieMask {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        buf.put_u16(self.get());
        2
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let mask = buf.get_u16();
        (Self::new(mask), buf)
    }
}


impl Compact for BranchNodeCompact {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let mut buf_size = 0;

        buf_size += self.state_mask.to_compact(buf);
        buf_size += self.tree_mask.to_compact(buf);
        buf_size += self.hash_mask.to_compact(buf);

        if let Some(root_hash) = self.root_hash {
            buf_size += B256::len_bytes();
            buf.put_slice(root_hash.as_slice());
        }

        for hash in &self.hashes {
            buf_size += B256::len_bytes();
            buf.put_slice(hash.as_slice());
        }

        buf_size
    }

    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let hash_len = B256::len_bytes();

        // Assert the buffer is long enough to contain the masks and the hashes.
        assert_eq!(buf.len() % hash_len, 6);

        // Consume the masks.
        let (state_mask, buf) = TrieMask::from_compact(buf, 0);
        let (tree_mask, buf) = TrieMask::from_compact(buf, 0);
        let (hash_mask, buf) = TrieMask::from_compact(buf, 0);

        let mut buf = buf;
        let mut num_hashes = buf.len() / hash_len;
        let mut root_hash = None;

        // Check if the root hash is present
        if hash_mask.count_ones() as usize + 1 == num_hashes {
            root_hash = Some(B256::from_slice(&buf[..hash_len]));
            buf.advance(hash_len);
            num_hashes -= 1;
        }

        // Consume all remaining hashes.
        let mut hashes = Vec::<B256>::with_capacity(num_hashes);
        for _ in 0..num_hashes {
            hashes.push(B256::from_slice(&buf[..hash_len]));
            buf.advance(hash_len);
        }

        (Self::new(state_mask, tree_mask, hash_mask, hashes, root_hash), buf)
    }
}


impl Compact for StorageTrieEntry {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let nibbles_len = self.nibbles.to_compact(buf);
        let node_len = self.node.to_compact(buf);
        nibbles_len + node_len
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (nibbles, buf) = StoredNibblesSubKey::from_compact(buf, 33);
        let (node, buf) = BranchNodeCompact::from_compact(buf, len - 33);
        let this = Self { nibbles, node };
        (this, buf)
    }
}

