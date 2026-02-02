use alloy_primitives::{B256, hex, keccak256};
use alloy_rlp::EMPTY_STRING_CODE;
use arrayvec::ArrayVec;
use core::fmt;

const MAX: usize = 33;

/// An RLP-encoded node.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RlpNode(ArrayVec<u8, MAX>);

impl alloy_rlp::Decodable for RlpNode {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = alloy_rlp::Header::decode_bytes(buf, false)?;
        Self::from_raw_rlp(bytes)
    }
}

impl core::ops::Deref for RlpNode {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for RlpNode {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for RlpNode {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RlpNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RlpNode({})", hex::encode_prefixed(&self.0))
    }
}

impl RlpNode {
    /// Creates a new RLP-encoded node from the given data.
    ///
    /// Returns `None` if the data is too large (greater than 33 bytes).
    #[inline]
    pub fn from_raw(data: &[u8]) -> Option<Self> {
        let mut arr = ArrayVec::new();
        arr.try_extend_from_slice(data).ok()?;
        Some(Self(arr))
    }

    /// Creates a new RLP-encoded node from the given data.
    #[inline]
    pub fn from_raw_rlp(data: &[u8]) -> alloy_rlp::Result<Self> {
        Self::from_raw(data).ok_or(alloy_rlp::Error::Custom("RLP node too large"))
    }

    /// Given an RLP-encoded node, returns it either as `rlp(node)` or `rlp(keccak(rlp(node)))`.
    #[doc(alias = "rlp_node")]
    #[inline]
    pub fn from_rlp(rlp: &[u8]) -> Self {
        if rlp.len() < 32 {
            // SAFETY: `rlp` is less than max capacity (33).
            unsafe { Self::from_raw(rlp).unwrap_unchecked() }
        } else {
            Self::word_rlp(&keccak256(rlp))
        }
    }

    /// RLP-encodes the given word and returns it as a new RLP node.
    #[inline]
    pub fn word_rlp(word: &B256) -> Self {
        let mut arr = [0u8; 33];
        arr[0] = EMPTY_STRING_CODE + 32;
        arr[1..].copy_from_slice(word.as_slice());
        Self(ArrayVec::from(arr))
    }

    /// Returns true if this is an RLP-encoded hash.
    #[inline]
    pub fn is_hash(&self) -> bool {
        self.len() == B256::len_bytes() + 1
    }

    /// Returns the RLP-encoded node as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns hash if this is an RLP-encoded hash
    #[inline]
    pub fn as_hash(&self) -> Option<B256> {
        if self.is_hash() { Some(B256::from_slice(&self.0[1..])) } else { None }
    }
}

#[cfg(feature = "arbitrary")]
impl<'u> arbitrary::Arbitrary<'u> for RlpNode {
    fn arbitrary(g: &mut arbitrary::Unstructured<'u>) -> arbitrary::Result<Self> {
        let len = g.int_in_range(0..=MAX)?;
        let mut arr = ArrayVec::new();
        arr.try_extend_from_slice(g.bytes(len)?).unwrap();
        Ok(Self(arr))
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for RlpNode {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;
        proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=MAX)
            .prop_map(|vec| Self::from_raw(&vec).unwrap())
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::Decodable;

    #[test]
    fn test_rlp_node_from_raw() {
        let data = [1u8, 2, 3, 4, 5];
        let node = RlpNode::from_raw(&data).unwrap();
        assert_eq!(node.as_slice(), &data);

        let empty = RlpNode::from_raw(&[]).unwrap();
        assert!(empty.as_slice().is_empty());
    }

    #[test]
    fn test_rlp_node_from_raw_too_large() {
        let data = [0u8; 34];
        assert!(RlpNode::from_raw(&data).is_none());
    }

    #[test]
    fn test_rlp_node_from_raw_max_len_ok() {
        let data = [0xab_u8; 33];
        let node = RlpNode::from_raw(&data).unwrap();
        assert_eq!(node.as_slice(), &data);
        assert_eq!(node.len(), 33);
    }

    #[test]
    fn test_rlp_node_from_raw_rlp() {
        let data = [1u8, 2, 3];
        let node = RlpNode::from_raw_rlp(&data).unwrap();
        assert_eq!(node.as_slice(), &data);
    }

    #[test]
    fn test_rlp_node_from_raw_rlp_too_large() {
        let data = [0u8; 34];
        assert!(RlpNode::from_raw_rlp(&data).is_err());
    }

    #[test]
    fn test_rlp_node_from_rlp_short() {
        let short_rlp = [0x80u8, 0x01, 0x02];
        let node = RlpNode::from_rlp(&short_rlp);
        assert_eq!(node.as_slice(), &short_rlp);
    }

    #[test]
    fn test_rlp_node_from_rlp_long() {
        let long_rlp = [0u8; 32];
        let node = RlpNode::from_rlp(&long_rlp);
        assert!(node.is_hash());
        assert_eq!(node.len(), 33);

        // Verify it equals word_rlp(keccak256(rlp))
        let expected = RlpNode::word_rlp(&keccak256(long_rlp));
        assert_eq!(node.as_slice(), expected.as_slice());
        assert_eq!(node.as_hash(), expected.as_hash());
    }

    #[test]
    fn test_rlp_node_from_rlp_len_31_inline() {
        let rlp = [0x11u8; 31];
        let node = RlpNode::from_rlp(&rlp);
        assert!(!node.is_hash());
        assert_eq!(node.as_slice(), &rlp);
    }

    #[test]
    fn test_rlp_node_word_rlp() {
        let hash = B256::repeat_byte(0xab);
        let node = RlpNode::word_rlp(&hash);
        assert!(node.is_hash());
        assert_eq!(node.len(), 33);
        assert_eq!(node[0], EMPTY_STRING_CODE + 32);
        assert_eq!(&node[1..], hash.as_slice());
    }

    #[test]
    fn test_rlp_node_is_hash() {
        let hash = B256::repeat_byte(0xcd);
        let node = RlpNode::word_rlp(&hash);
        assert!(node.is_hash());

        let short = RlpNode::from_raw(&[1, 2, 3]).unwrap();
        assert!(!short.is_hash());
    }

    #[test]
    fn test_rlp_node_as_hash() {
        let hash = B256::repeat_byte(0xef);
        let node = RlpNode::word_rlp(&hash);
        assert_eq!(node.as_hash(), Some(hash));

        let short = RlpNode::from_raw(&[1, 2, 3]).unwrap();
        assert_eq!(short.as_hash(), None);
    }

    #[test]
    fn test_rlp_node_default() {
        let node = RlpNode::default();
        assert!(node.as_slice().is_empty());
    }

    #[test]
    fn test_rlp_node_debug() {
        let node = RlpNode::from_raw(&[0xab, 0xcd]).unwrap();
        let debug_str = format!("{:?}", node);
        assert!(debug_str.contains("RlpNode"));
        assert!(debug_str.contains("abcd"));
    }

    #[test]
    fn test_rlp_node_clone_and_eq() {
        let node1 = RlpNode::from_raw(&[1, 2, 3]).unwrap();
        let node2 = node1.clone();
        assert_eq!(node1, node2);
    }

    #[test]
    fn test_rlp_node_deref() {
        let data = [1u8, 2, 3];
        let node = RlpNode::from_raw(&data).unwrap();
        let slice: &[u8] = &node;
        assert_eq!(slice, &data);
    }

    #[test]
    fn test_rlp_node_deref_mut() {
        let mut node = RlpNode::from_raw(&[1, 2, 3]).unwrap();
        node[0] = 5;
        assert_eq!(node.as_slice(), &[5, 2, 3]);
    }

    #[test]
    fn test_rlp_node_as_ref() {
        let data = [1u8, 2, 3];
        let node = RlpNode::from_raw(&data).unwrap();
        let as_ref: &[u8] = node.as_ref();
        assert_eq!(as_ref, &data);
    }

    #[test]
    fn test_rlp_node_decodable() {
        let hash = B256::repeat_byte(0x42);
        let node = RlpNode::word_rlp(&hash);
        let encoded = alloy_rlp::encode(&node[..]);
        let decoded = RlpNode::decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.as_slice(), node.as_slice());
    }

    #[test]
    fn test_rlp_node_decode_oversized_fails() {
        // Construct RLP-encoded bytestring of 34 bytes (too large for RlpNode)
        let data = [0xab_u8; 34];
        let encoded = alloy_rlp::encode(&data[..]);
        let result = RlpNode::decode(&mut &encoded[..]);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_rlp_node_properties() {
        use proptest::prelude::*;

        proptest!(|(node: RlpNode)| {
            // is_hash should only be true for 33-byte nodes
            prop_assert_eq!(node.is_hash(), node.len() == B256::len_bytes() + 1);

            // as_hash should return Some only when is_hash is true
            if node.is_hash() {
                prop_assert!(node.as_hash().is_some());
            } else {
                prop_assert!(node.as_hash().is_none());
            }

            // as_slice and deref should be consistent
            prop_assert_eq!(node.as_slice(), &*node);
        });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_word_rlp_roundtrip() {
        use proptest::prelude::*;

        proptest!(|(hash: [u8; 32])| {
            let hash = B256::from(hash);
            let node = RlpNode::word_rlp(&hash);
            prop_assert!(node.is_hash());
            prop_assert_eq!(node.as_hash(), Some(hash));
        });
    }
}
