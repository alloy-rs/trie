//! Shared chain-specific account payloads.

use alloc::vec::Vec;
use alloy_primitives::Bytes;
use core::{cmp::Ordering, ops::Deref};
use triomphe::ThinArc;

/// Raw, unencoded account bytes with a one-pointer inline representation.
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
        let len = u16::try_from(self.len()).map_err(|_| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidInput,
                "account extension exceeds u16 length",
            )
        })?;
        writer.write_all(&len.to_be_bytes())?;
        writer.write_all(self.as_ref())
    }
}

#[cfg(feature = "borsh")]
impl borsh::BorshDeserialize for AccountExtension {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut len = [0; 2];
        reader.read_exact(&mut len)?;
        let mut bytes = alloc::vec![0; usize::from(u16::from_be_bytes(len))];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from(bytes))
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
            use serde::ser::{Error, SerializeTuple};
            let len = u16::try_from(self.len()).map_err(S::Error::custom)?;
            // A tuple avoids the serializer's native sequence-length prefix.
            let mut tuple = serializer.serialize_tuple(2)?;
            tuple.serialize_element(&len.to_be_bytes())?;
            tuple.serialize_element(&RawBytes(self.as_ref()))?;
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AccountExtension {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            Bytes::deserialize(deserializer).map(Self::from)
        } else {
            deserializer.deserialize_tuple(2, ExtensionVisitor)
        }
    }
}

// Binary extensions use a fixed big-endian u16 length followed by raw bytes, including
// a zero length for empty payloads so fields embedded in larger records stay delimited.
#[cfg(feature = "serde")]
struct RawBytes<'a>(&'a [u8]);

#[cfg(feature = "serde")]
impl serde::Serialize for RawBytes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(self.0.len())?;
        for byte in self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

#[cfg(feature = "serde")]
struct ExtensionVisitor;

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for ExtensionVisitor {
    type Value = AccountExtension;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a u16 length followed by raw account extension bytes")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;
        let len = u16::from_be_bytes(
            seq.next_element()?.ok_or_else(|| A::Error::custom("missing extension length"))?,
        );
        seq.next_element_seed(PayloadVisitor(usize::from(len)))?
            .ok_or_else(|| A::Error::custom("missing extension payload"))
    }
}

#[cfg(feature = "serde")]
struct PayloadVisitor(usize);

#[cfg(feature = "serde")]
impl<'de> serde::de::DeserializeSeed<'de> for PayloadVisitor {
    type Value = AccountExtension;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_tuple(self.0, self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for PayloadVisitor {
    type Value = AccountExtension;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} raw account extension bytes", self.0)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;
        let mut bytes = Vec::with_capacity(self.0);
        for i in 0..self.0 {
            bytes.push(seq.next_element()?.ok_or_else(|| A::Error::invalid_length(i, &self))?);
        }
        Ok(AccountExtension::from(bytes))
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
            let mut expected = (payload.len() as u16).to_be_bytes().to_vec();
            expected.extend_from_slice(payload);
            let encoded = bincode::serialize(&extension).unwrap();
            assert_eq!(encoded, expected);
            assert_eq!(bincode::deserialize::<AccountExtension>(&encoded).unwrap(), extension);
            let pair = (extension.clone(), 42u8);
            assert_eq!(
                bincode::deserialize::<(AccountExtension, u8)>(&bincode::serialize(&pair).unwrap())
                    .unwrap(),
                pair
            );
            let json = serde_json::to_string(&extension).unwrap();
            assert_eq!(serde_json::from_str::<AccountExtension>(&json).unwrap(), extension);
            if !payload.is_empty() {
                assert!(
                    bincode::deserialize::<AccountExtension>(&encoded[..encoded.len() - 1])
                        .is_err()
                );
            }
        }
        assert!(
            bincode::serialize(&AccountExtension::from(alloc::vec![0; usize::from(u16::MAX) + 1]))
                .is_err()
        );
    }
}
