use alloc::vec::Vec;
use alloy_primitives::{hex, B256};
use core::fmt;

/// The input of the hash builder.
///
/// Stores [`HashBuilderInputRef`] efficiently by reusing resources.
#[derive(Clone)]
pub struct HashBuilderInput {
    /// Stores the bytes of either the leaf node value or the hash of adjacent nodes.
    buf: Vec<u8>,
    /// The kind of the current hash builder input.
    kind: HashBuilderInputKind,
}

impl Default for HashBuilderInput {
    fn default() -> Self {
        Self { buf: Vec::with_capacity(128), kind: HashBuilderInputKind::default() }
    }
}

impl fmt::Debug for HashBuilderInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl HashBuilderInput {
    /// Returns the input as a reference.
    #[inline]
    pub fn as_ref(&self) -> HashBuilderInputRef<'_> {
        match self.kind {
            HashBuilderInputKind::Bytes => HashBuilderInputRef::Bytes(&self.buf),
            HashBuilderInputKind::Hash => {
                debug_assert_eq!(self.buf.len(), 32);
                HashBuilderInputRef::Hash(unsafe { self.buf[..].try_into().unwrap_unchecked() })
            }
        }
    }

    /// Sets the input from the given bytes.
    #[inline]
    pub fn set_from_ref(&mut self, input: HashBuilderInputRef<'_>) {
        self.buf.clear();
        self.buf.extend_from_slice(input.as_slice());
        self.kind = input.kind();
    }

    /// Clears the input.
    #[inline]
    pub fn clear(&mut self) {
        self.buf.clear();
        self.kind = HashBuilderInputKind::default();
    }
}

/// The kind of the current hash builder input.
#[derive(Clone, Copy, Debug, Default)]
enum HashBuilderInputKind {
    /// Value of the leaf node.
    #[default]
    Bytes,
    /// Hash of adjacent nodes.
    Hash,
}

/// The input of the hash builder.
pub enum HashBuilderInputRef<'a> {
    /// Value of the leaf node.
    Bytes(&'a [u8]),
    /// Hash of adjacent nodes.
    Hash(&'a B256),
}

impl<'a> HashBuilderInputRef<'a> {
    /// Returns the input as a slice.
    pub const fn as_slice(&self) -> &'a [u8] {
        match *self {
            HashBuilderInputRef::Bytes(bytes) => bytes,
            HashBuilderInputRef::Hash(hash) => hash.as_slice(),
        }
    }

    const fn kind(&self) -> HashBuilderInputKind {
        match *self {
            HashBuilderInputRef::Bytes(_) => HashBuilderInputKind::Bytes,
            HashBuilderInputRef::Hash(_) => HashBuilderInputKind::Hash,
        }
    }
}

impl fmt::Debug for HashBuilderInputRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            HashBuilderInputRef::Bytes(_) => "Bytes",
            HashBuilderInputRef::Hash(_) => "Hash",
        };
        let slice = hex::encode_prefixed(self.as_slice());
        write!(f, "{name}({slice})")
    }
}
