use alloc::vec::Vec;
use alloy_primitives::{B256, hex};
use core::fmt;

/// Hash builder value.
///
/// Stores [`HashBuilderValueRef`] efficiently by reusing resources.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashBuilderValue {
    /// Stores the bytes of either the leaf node value or the hash of adjacent nodes.
    #[cfg_attr(feature = "serde", serde(with = "hex"))]
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

#[cfg(feature = "arbitrary")]
impl<'u> arbitrary::Arbitrary<'u> for HashBuilderValue {
    fn arbitrary(g: &mut arbitrary::Unstructured<'u>) -> arbitrary::Result<Self> {
        let kind = HashBuilderValueKind::arbitrary(g)?;
        let buf = match kind {
            HashBuilderValueKind::Bytes => Vec::arbitrary(g)?,
            HashBuilderValueKind::Hash => B256::arbitrary(g)?.to_vec(),
        };
        Ok(Self { buf, kind })
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for HashBuilderValue {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        proptest::arbitrary::any::<HashBuilderValueKind>()
            .prop_flat_map(|kind| {
                let range = match kind {
                    HashBuilderValueKind::Bytes => 0..=128,
                    HashBuilderValueKind::Hash => 32..=32,
                };
                proptest::collection::vec(any::<u8>(), range)
                    .prop_map(move |buf| Self { buf, kind })
            })
            .boxed()
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
enum HashBuilderValueKind {
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
    const fn kind(&self) -> HashBuilderValueKind {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_builder_value_default() {
        let value = HashBuilderValue::default();
        assert!(matches!(value.as_ref(), HashBuilderValueRef::Bytes(b) if b.is_empty()));
    }

    #[test]
    fn test_hash_builder_value_set_bytes() {
        let mut value = HashBuilderValue::new();
        value.set_from_ref(HashBuilderValueRef::Bytes(&[1, 2, 3, 4]));

        assert!(matches!(value.as_ref(), HashBuilderValueRef::Bytes(b) if b == &[1, 2, 3, 4]));
        assert_eq!(value.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_hash_builder_value_set_hash() {
        let mut value = HashBuilderValue::new();
        let hash = B256::repeat_byte(0xab);
        value.set_from_ref(HashBuilderValueRef::Hash(&hash));

        assert!(matches!(value.as_ref(), HashBuilderValueRef::Hash(h) if *h == hash));
        assert_eq!(value.as_slice(), hash.as_slice());
    }

    #[test]
    fn test_hash_builder_value_set_bytes_owned() {
        let mut value = HashBuilderValue::new();
        value.set_bytes_owned(vec![5, 6, 7, 8]);

        assert!(matches!(value.as_ref(), HashBuilderValueRef::Bytes(b) if b == &[5, 6, 7, 8]));
    }

    #[test]
    fn test_hash_builder_value_clear() {
        let mut value = HashBuilderValue::new();
        value.set_from_ref(HashBuilderValueRef::Bytes(&[1, 2, 3]));
        value.clear();

        assert!(matches!(value.as_ref(), HashBuilderValueRef::Bytes(b) if b.is_empty()));
    }

    #[test]
    fn test_hash_builder_value_switch_types() {
        let mut value = HashBuilderValue::new();

        // Start with bytes
        value.set_from_ref(HashBuilderValueRef::Bytes(&[1, 2, 3]));
        assert!(matches!(value.as_ref(), HashBuilderValueRef::Bytes(_)));

        // Switch to hash
        let hash = B256::repeat_byte(0xcd);
        value.set_from_ref(HashBuilderValueRef::Hash(&hash));
        assert!(matches!(value.as_ref(), HashBuilderValueRef::Hash(h) if *h == hash));

        // Switch back to bytes
        value.set_from_ref(HashBuilderValueRef::Bytes(&[4, 5, 6]));
        assert!(matches!(value.as_ref(), HashBuilderValueRef::Bytes(b) if b == &[4, 5, 6]));
    }

    #[test]
    fn test_hash_builder_value_ref_as_slice() {
        let bytes = [1u8, 2, 3, 4];
        let bytes_ref = HashBuilderValueRef::Bytes(&bytes);
        assert_eq!(bytes_ref.as_slice(), &bytes);

        let hash = B256::repeat_byte(0xef);
        let hash_ref = HashBuilderValueRef::Hash(&hash);
        assert_eq!(hash_ref.as_slice(), hash.as_slice());
    }

    #[test]
    fn test_hash_builder_value_debug() {
        let mut value = HashBuilderValue::new();
        value.set_from_ref(HashBuilderValueRef::Bytes(&[0xab, 0xcd]));
        let debug_str = format!("{:?}", value);
        assert!(debug_str.contains("Bytes"));
        assert!(debug_str.contains("abcd"));

        let hash = B256::repeat_byte(0x12);
        value.set_from_ref(HashBuilderValueRef::Hash(&hash));
        let debug_str = format!("{:?}", value);
        assert!(debug_str.contains("Hash"));
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_hash_builder_value_roundtrip() {
        use proptest::prelude::*;

        proptest!(|(value: HashBuilderValue)| {
            // Test that as_ref and as_slice are consistent
            let slice = value.as_slice();
            match value.as_ref() {
                HashBuilderValueRef::Bytes(b) => prop_assert_eq!(b, slice),
                HashBuilderValueRef::Hash(h) => prop_assert_eq!(h.as_slice(), slice),
            }
        });
    }
}
