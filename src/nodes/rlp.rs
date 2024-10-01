use alloy_primitives::{hex, keccak256, B256};
use alloy_rlp::EMPTY_STRING_CODE;
use arrayvec::ArrayVec;
use core::fmt;

/// An RLP-encoded node.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RlpNode(ArrayVec<u8, 33>);

impl alloy_rlp::Decodable for RlpNode {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = alloy_rlp::Header::decode_bytes(buf, false)?;
        Self::from_raw(bytes).ok_or_else(|| alloy_rlp::Error::Custom("RLP node too large"))
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
        Self::from_raw(data).ok_or_else(|| alloy_rlp::Error::Custom("RLP node too large"))
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
        let mut arr = ArrayVec::new();
        arr.push(EMPTY_STRING_CODE + 32);
        arr.try_extend_from_slice(word.as_slice()).unwrap();
        Self(arr)
    }

    /// Returns the RLP-encoded node as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}
