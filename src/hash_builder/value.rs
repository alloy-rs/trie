use alloc::vec::Vec;
use alloy_primitives::{B256, hex};
use core::fmt;

/// Hash builder value.
///
/// Stores [`HashBuilderValueRef`] efficiently by reusing resources.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct HashBuilderValue {
    /// Stores the bytes of either the leaf node value or the hash of adjacent nodes.
    #[cfg_attr(feature = "serde", serde(with = "hex"))]
    buf: Vec<u8>,
    /// The kind of value that is stored in `buf`.
    kind: HashBuilderValueKind,
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for HashBuilderValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(rename = "HashBuilderValue")]
        struct Repr {
            #[serde(with = "hex")]
            buf: Vec<u8>,
            kind: HashBuilderValueKind,
        }

        let Repr { buf, kind } = Repr::deserialize(deserializer)?;
        if kind == HashBuilderValueKind::Hash && buf.len() != 32 {
            return Err(serde::de::Error::custom("Hash kind requires exactly 32 bytes"));
        }
        Ok(Self { buf, kind })
    }
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
                // SAFETY: Every constructor, including `Deserialize`, keeps `Hash` values at
                // exactly 32 bytes.
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

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[derive(serde::Serialize)]
    #[serde(rename = "HashBuilderValue")]
    struct UncheckedHashBuilderValue {
        #[serde(with = "hex")]
        buf: Vec<u8>,
        kind: HashBuilderValueKind,
    }

    #[test]
    fn serde_rejects_invalid_hash_lengths() {
        for len in [0, 1, 31, 33, 64] {
            let value = UncheckedHashBuilderValue {
                buf: vec![0xab; len],
                kind: HashBuilderValueKind::Hash,
            };

            let json = serde_json::to_vec(&value).unwrap();
            assert!(serde_json::from_slice::<HashBuilderValue>(&json).is_err());

            let json = serde_json::to_vec(&(hex::encode_prefixed(&value.buf), value.kind)).unwrap();
            assert!(serde_json::from_slice::<HashBuilderValue>(&json).is_err());

            let postcard = postcard::to_allocvec(&value).unwrap();
            assert!(postcard::from_bytes::<HashBuilderValue>(&postcard).is_err());
        }

        let mut value = HashBuilderValue::new();
        value.set_from_ref(HashBuilderValueRef::Hash(&B256::repeat_byte(0xab)));
        let json = serde_json::to_vec(&value).unwrap();
        assert_eq!(serde_json::from_slice::<HashBuilderValue>(&json).unwrap(), value);
        let postcard = postcard::to_allocvec(&value).unwrap();
        assert_eq!(postcard::from_bytes::<HashBuilderValue>(&postcard).unwrap(), value);
    }
}
