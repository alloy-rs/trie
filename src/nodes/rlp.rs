use alloy_primitives::{B256, hex, keccak256};
use alloy_rlp::EMPTY_STRING_CODE;
use core::fmt;
use core::mem::MaybeUninit;

const MAX: usize = 33;

/// An RLP-encoded node.
///
/// Internally stores a `u8` length and a `[MaybeUninit<u8>; 33]` buffer,
/// avoiding `ArrayVec`'s `u32` length overhead.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "SerdeBuf", into = "SerdeBuf"))]
pub struct RlpNode {
    len: u8,
    buf: [MaybeUninit<u8>; MAX],
}

impl Copy for RlpNode {}

impl Clone for RlpNode {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl Default for RlpNode {
    #[inline]
    fn default() -> Self {
        Self { len: 0, buf: [MaybeUninit::uninit(); MAX] }
    }
}

impl PartialEq for RlpNode {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for RlpNode {}

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
        self.as_slice()
    }
}

impl core::ops::DerefMut for RlpNode {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl AsRef<[u8]> for RlpNode {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for RlpNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RlpNode({})", hex::encode_prefixed(self.as_slice()))
    }
}

impl RlpNode {
    /// Creates a new RLP-encoded node from the given data.
    ///
    /// Returns `None` if the data is too large (greater than 33 bytes).
    #[inline]
    pub const fn from_raw(data: &[u8]) -> Option<Self> {
        let len = data.len();
        if len > MAX {
            return None;
        }
        let mut buf = [MaybeUninit::uninit(); MAX];
        // SAFETY: `len <= MAX`, so `data` fits in `buf`.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf.as_mut_ptr().cast(), len);
        }
        Some(Self { len: len as u8, buf })
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
    pub const fn word_rlp(word: &B256) -> Self {
        let mut buf = [MaybeUninit::uninit(); MAX];
        buf[0] = MaybeUninit::new(EMPTY_STRING_CODE + 32);
        // SAFETY: Writing 32 bytes at offset 1 within a 33-byte buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                word.as_slice().as_ptr(),
                buf.as_mut_ptr().add(1).cast(),
                32,
            );
        }
        Self { len: MAX as u8, buf }
    }

    /// Returns true if this is an RLP-encoded hash.
    #[inline]
    pub fn is_hash(&self) -> bool {
        self.len() == B256::len_bytes() + 1
    }

    /// Returns the RLP-encoded node as a slice.
    #[inline]
    pub const fn as_slice(&self) -> &[u8] {
        // SAFETY: `self.buf[..self.len]` is always initialized.
        unsafe { core::slice::from_raw_parts(self.buf.as_ptr().cast(), self.len as usize) }
    }

    /// Returns the RLP-encoded node as a mutable slice.
    #[inline]
    pub const fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `self.buf[..self.len]` is always initialized.
        unsafe { core::slice::from_raw_parts_mut(self.buf.as_mut_ptr().cast(), self.len as usize) }
    }

    /// Returns hash if this is an RLP-encoded hash
    #[inline]
    pub fn as_hash(&self) -> Option<B256> {
        if self.is_hash() {
            Some(B256::from_slice(&self.as_slice()[1..]))
        } else {
            None
        }
    }
}

// Serde helper: serialize/deserialize as a byte vec.
#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SerdeBuf(Vec<u8>);

#[cfg(feature = "serde")]
impl From<SerdeBuf> for RlpNode {
    fn from(buf: SerdeBuf) -> Self {
        Self::from_raw(&buf.0).expect("deserialized RlpNode too large")
    }
}

#[cfg(feature = "serde")]
impl From<RlpNode> for SerdeBuf {
    fn from(node: RlpNode) -> Self {
        Self(node.as_slice().to_vec())
    }
}

#[cfg(feature = "arbitrary")]
impl<'u> arbitrary::Arbitrary<'u> for RlpNode {
    fn arbitrary(g: &mut arbitrary::Unstructured<'u>) -> arbitrary::Result<Self> {
        let len = g.int_in_range(0..=MAX)?;
        Ok(Self::from_raw(g.bytes(len)?).unwrap())
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
