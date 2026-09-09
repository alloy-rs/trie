//! Shared chain-specific account payloads.

use alloc::vec::Vec;
use alloy_primitives::Bytes;
use core::{cmp::Ordering, ops::Deref};
use triomphe::ThinArc;

/// An immutable account payload with a one-pointer inline representation.
///
/// Empty payloads allocate nothing. Nonempty payloads store their length and bytes
/// in one reference-counted allocation; cloning shares that allocation.
#[derive(Clone, Debug, Default)]
pub struct AccountExtension(Option<ThinArc<(), u8>>);

impl AccountExtension {
    /// Takes ownership of a shared payload without copying its bytes.
    pub fn from_shared(payload: Option<ThinArc<(), u8>>) -> Self {
        Self(payload.filter(|arc| !arc.slice.is_empty()))
    }

    /// Transfers the shared allocation without copying its bytes.
    pub fn into_shared(self) -> Option<ThinArc<(), u8>> {
        self.0
    }

    /// Creates an empty payload without allocating.
    pub const fn new() -> Self {
        Self(None)
    }

    /// Copies bytes into a single shared allocation.
    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        Self((!bytes.is_empty()).then(|| ThinArc::from_header_and_slice((), bytes)))
    }

    /// Returns whether the payload is empty.
    pub const fn is_empty(&self) -> bool {
        self.0.is_none()
    }
}

impl AsRef<[u8]> for AccountExtension {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref().map_or(&[], |arc| &arc.slice)
    }
}

impl Deref for AccountExtension {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl From<Bytes> for AccountExtension {
    fn from(bytes: Bytes) -> Self {
        Self::copy_from_slice(&bytes)
    }
}

impl From<Vec<u8>> for AccountExtension {
    fn from(bytes: Vec<u8>) -> Self {
        Self::copy_from_slice(&bytes)
    }
}

impl PartialEq for AccountExtension {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for AccountExtension {}

#[cfg(feature = "borsh")]
impl borsh::BorshSerialize for AccountExtension {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        borsh::BorshSerialize::serialize(self.as_ref(), writer)
    }
}

#[cfg(feature = "borsh")]
impl borsh::BorshDeserialize for AccountExtension {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        <Vec<u8> as borsh::BorshDeserialize>::deserialize_reader(reader).map(Self::from)
    }
}

impl PartialOrd for AccountExtension {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AccountExtension {
    fn cmp(&self, other: &Self) -> Ordering {
        // Order payload bytes, not ThinArc's length header.
        self.as_ref().cmp(other.as_ref())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AccountExtension {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            alloy_primitives::hex::serialize(self.as_ref(), serializer)
        } else {
            serializer.serialize_bytes(self.as_ref())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AccountExtension {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Bytes::deserialize(deserializer).map(Self::from)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for AccountExtension {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Extensions must be complete RLP items.
        let bytes = <Vec<u8> as arbitrary::Arbitrary>::arbitrary(u)?;
        Ok(Self::copy_from_slice(&alloy_rlp::encode(bytes)))
    }
}
