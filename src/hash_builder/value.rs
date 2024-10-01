use alloc::vec::Vec;
use alloy_primitives::{hex, B256};
use core::fmt;

/// Hash builder value.
///
/// Stores [`HashBuilderValueRef`] efficiently by reusing resources.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(derive_arbitrary::Arbitrary, proptest_derive::Arbitrary))]
pub struct HashBuilderValue {
    /// Stores the bytes of either the leaf node value or the hash of adjacent nodes.
    buf: Vec<u8>,
    /// The kind of value that is stored in `buf`.
    kind: HashBuilderValueKind,
}

impl Default for HashBuilderValue {
    fn default() -> Self {
        Self { buf: Vec::with_capacity(128), kind: HashBuilderValueKind::default() }
    }
}

impl fmt::Debug for HashBuilderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl HashBuilderValue {
    /// Creates a new empty value.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the value as a reference.
    #[inline]
    pub fn as_ref(&self) -> HashBuilderValueRef<'_> {
        match self.kind {
            HashBuilderValueKind::Bytes => HashBuilderValueRef::Bytes(&self.buf),
            HashBuilderValueKind::Hash => {
                debug_assert_eq!(self.buf.len(), 32);
                HashBuilderValueRef::Hash(unsafe { self.buf[..].try_into().unwrap_unchecked() })
            }
        }
    }

    /// Returns the value as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Returns the kind of the value.
    pub fn kind(&self) -> HashBuilderValueKind {
        self.kind
    }

    /// Like `set_from_ref`, but takes ownership of the bytes.
    pub fn set_bytes_owned(&mut self, bytes: Vec<u8>) {
        self.buf = bytes;
        self.kind = HashBuilderValueKind::Bytes;
    }

    /// Sets the value from the given bytes.
    #[inline]
    pub fn set_from_ref(&mut self, value: HashBuilderValueRef<'_>) {
        self.buf.clear();
        self.buf.extend_from_slice(value.as_slice());
        self.kind = value.kind();
    }

    /// Clears the value.
    #[inline]
    pub fn clear(&mut self) {
        self.buf.clear();
        self.kind = HashBuilderValueKind::default();
    }
}

/// The kind of the current hash builder value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(derive_arbitrary::Arbitrary, proptest_derive::Arbitrary))]
pub enum HashBuilderValueKind {
    /// Value of the leaf node.
    #[default]
    Bytes,
    /// Hash of adjacent nodes.
    Hash,
}

/// Hash builder value reference.
pub enum HashBuilderValueRef<'a> {
    /// Value of the leaf node.
    Bytes(&'a [u8]),
    /// Hash of adjacent nodes.
    Hash(&'a B256),
}

impl<'a> HashBuilderValueRef<'a> {
    /// Returns the value as a slice.
    pub const fn as_slice(&self) -> &'a [u8] {
        match *self {
            HashBuilderValueRef::Bytes(bytes) => bytes,
            HashBuilderValueRef::Hash(hash) => hash.as_slice(),
        }
    }

    /// Returns the kind of the value.
    pub const fn kind(&self) -> HashBuilderValueKind {
        match *self {
            HashBuilderValueRef::Bytes(_) => HashBuilderValueKind::Bytes,
            HashBuilderValueRef::Hash(_) => HashBuilderValueKind::Hash,
        }
    }
}

impl fmt::Debug for HashBuilderValueRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            HashBuilderValueRef::Bytes(_) => "Bytes",
            HashBuilderValueRef::Hash(_) => "Hash",
        };
        let slice = hex::encode_prefixed(self.as_slice());
        write!(f, "{name}({slice})")
    }
}
