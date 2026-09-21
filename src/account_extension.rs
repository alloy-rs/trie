//! Shared chain-specific account payloads.

use alloc::vec::Vec;
use alloy_primitives::Bytes;
use core::{cmp::Ordering, ops::Deref};
use triomphe::ThinArc;

/// Raw, unencoded account bytes with a one-pointer inline representation.
///
/// Empty payloads allocate nothing. Nonempty payloads store their length and bytes
/// in one reference-counted allocation; cloning shares that allocation.
///
/// Accounts omit empty extensions in Serde. Their binary representation requires
/// struct boundaries, as in MessagePack; bincode and Postcard are not supported.
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
        self.as_ref().serialize(writer)
    }
}

#[cfg(feature = "borsh")]
impl borsh::BorshDeserialize for AccountExtension {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        <Vec<u8>>::deserialize_reader(reader).map(Self::from)
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
        let bytes = <Vec<u8> as arbitrary::Arbitrary>::arbitrary(u)?;
        Ok(Self::from(bytes))
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn raw_bytes_wire_format() {
        for payload in [&[][..], &[0x82, 0xaa][..], &[42; 256][..]] {
            let extension = AccountExtension::copy_from_slice(payload);
            let expected = postcard::to_allocvec(&Bytes::copy_from_slice(payload)).unwrap();
            let encoded = postcard::to_allocvec(&extension).unwrap();
            assert_eq!(encoded, expected);
            assert_eq!(postcard::from_bytes::<AccountExtension>(&encoded).unwrap(), extension);
            let pair = (extension.clone(), 42u8);
            assert_eq!(
                postcard::from_bytes::<(AccountExtension, u8)>(
                    &postcard::to_allocvec(&pair).unwrap()
                )
                .unwrap(),
                pair
            );
            let json = serde_json::to_string(&extension).unwrap();
            assert_eq!(serde_json::from_str::<AccountExtension>(&json).unwrap(), extension);
            if !payload.is_empty() {
                assert!(
                    postcard::from_bytes::<AccountExtension>(&encoded[..encoded.len() - 1])
                        .is_err()
                );
            }
        }
    }
}

#[cfg(all(test, feature = "borsh"))]
mod borsh_tests {
    use super::*;

    #[test]
    fn uses_standard_byte_vector_encoding() {
        let extension = AccountExtension::copy_from_slice(&[0x82, 0xaa]);
        let encoded = borsh::to_vec(&extension).unwrap();
        assert_eq!(encoded, borsh::to_vec(&vec![0x82u8, 0xaa]).unwrap());
        assert_eq!(borsh::from_slice::<AccountExtension>(&encoded).unwrap(), extension);
    }
}
