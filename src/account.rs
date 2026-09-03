use crate::{EMPTY_ROOT_HASH, KECCAK_EMPTY};
use alloy_primitives::{B256, U256, keccak256};
use alloy_rlp::{BufMut, Decodable, Encodable, Error, Header, Result};

/// Represents an TrieAccount in the account trie.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TrieAccount<E = ()> {
    /// The account's nonce.
    #[cfg_attr(feature = "serde", serde(with = "quantity"))]
    pub nonce: u64,
    /// The account's balance.
    pub balance: U256,
    /// The hash of the storage account data.
    pub storage_root: B256,
    /// The hash of the code of the account.
    pub code_hash: B256,
    /// Chain-specific fields committed to by this account leaf.
    #[cfg_attr(feature = "serde", serde(default))]
    pub extension: E,
}

impl<E: Default> Default for TrieAccount<E> {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: U256::ZERO,
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
            extension: E::default(),
        }
    }
}

impl<E: TrieAccountExtension> TrieAccount<E> {
    /// Compute  hash as committed to in the MPT trie without memorizing.
    pub fn trie_hash_slow(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }
}

/// Additional chain-specific fields appended to an account trie leaf's RLP list.
///
/// Implementations encode zero or more complete RLP items. The unit type encodes no items, so
/// The unit implementation emits no fields, so [`TrieAccount<()>`] is byte-for-byte compatible
/// with the canonical four-field Ethereum account encoding.
pub trait TrieAccountExtension: Sized {
    /// Returns the encoded length of all extension fields.
    fn payload_length(&self) -> usize;

    /// Appends all extension fields to an account RLP list payload.
    fn encode_payload(&self, out: &mut dyn BufMut);

    /// Decodes the extension fields from the remaining account RLP list payload.
    fn decode_payload(payload: &mut &[u8]) -> Result<Self>;
}

impl TrieAccountExtension for () {
    #[inline]
    fn payload_length(&self) -> usize {
        0
    }

    #[inline]
    fn encode_payload(&self, _out: &mut dyn BufMut) {}

    #[inline]
    fn decode_payload(_payload: &mut &[u8]) -> Result<Self> {
        Ok(())
    }
}

impl<E: TrieAccountExtension> Encodable for TrieAccount<E> {
    fn encode(&self, out: &mut dyn BufMut) {
        let payload_length = self.nonce.length()
            + self.balance.length()
            + self.storage_root.length()
            + self.code_hash.length()
            + self.extension.payload_length();
        Header { list: true, payload_length }.encode(out);
        self.nonce.encode(out);
        self.balance.encode(out);
        self.storage_root.encode(out);
        self.code_hash.encode(out);
        self.extension.encode_payload(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.nonce.length()
            + self.balance.length()
            + self.storage_root.length()
            + self.code_hash.length()
            + self.extension.payload_length();
        Header { list: true, payload_length }.length() + payload_length
    }
}

impl<E: TrieAccountExtension> Decodable for TrieAccount<E> {
    fn decode(buf: &mut &[u8]) -> Result<Self> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(Error::UnexpectedString);
        }

        let (mut payload, rest) = buf.split_at(header.payload_length);
        *buf = rest;
        let account = Self {
            nonce: Decodable::decode(&mut payload)?,
            balance: Decodable::decode(&mut payload)?,
            storage_root: Decodable::decode(&mut payload)?,
            code_hash: Decodable::decode(&mut payload)?,
            extension: E::decode_payload(&mut payload)?,
        };
        if !payload.is_empty() {
            return Err(Error::UnexpectedLength);
        }
        Ok(account)
    }
}

#[cfg(feature = "serde")]
mod quantity {
    use alloy_primitives::U64;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes a primitive number as a "quantity" hex string.
    pub(crate) fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        U64::from(*value).serialize(serializer)
    }

    /// Deserializes a primitive number from a "quantity" hex string.
    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        U64::deserialize(deserializer).map(|value| value.to())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U256, hex};
    use alloy_rlp::{Decodable, RlpEncodable};

    #[derive(RlpEncodable)]
    struct LegacyTrieAccount {
        nonce: u64,
        balance: U256,
        storage_root: B256,
        code_hash: B256,
    }

    #[test]
    fn test_account_encoding() {
        let account = TrieAccount {
            nonce: 1,
            balance: U256::from(1000),
            storage_root: B256::from_slice(&hex!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            code_hash: keccak256(hex!("5a465a905090036002900360015500")),
            extension: (),
        };

        let encoded = alloy_rlp::encode(account);

        let decoded = TrieAccount::decode(&mut &encoded[..]).unwrap();
        assert_eq!(account, decoded);
    }

    #[test]
    fn test_trie_hash_slow() {
        let account = TrieAccount {
            nonce: 1,
            balance: U256::from(1000),
            storage_root: B256::from_slice(&hex!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            code_hash: keccak256(hex!("5a465a905090036002900360015500")),
            extension: (),
        };

        let expected_hash = keccak256(alloy_rlp::encode(account));
        let actual_hash = account.trie_hash_slow();
        assert_eq!(expected_hash, actual_hash);
    }

    #[test]
    fn empty_extension_preserves_account_encoding() {
        let account = TrieAccount {
            nonce: 1,
            balance: U256::from(1000),
            storage_root: B256::repeat_byte(0xaa),
            code_hash: B256::repeat_byte(0xbb),
            extension: (),
        };
        let expected = alloy_rlp::encode(LegacyTrieAccount {
            nonce: account.nonce,
            balance: account.balance,
            storage_root: account.storage_root,
            code_hash: account.code_hash,
        });
        assert_eq!(alloy_rlp::encode(account), expected);
        assert_eq!(TrieAccount::<()>::decode(&mut expected.as_slice()).unwrap(), account);
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct TestExtension(u64);

    impl TrieAccountExtension for TestExtension {
        fn payload_length(&self) -> usize {
            self.0.length()
        }

        fn encode_payload(&self, out: &mut dyn BufMut) {
            self.0.encode(out);
        }

        fn decode_payload(payload: &mut &[u8]) -> Result<Self> {
            u64::decode(payload).map(Self)
        }
    }

    #[test]
    fn extended_account_roundtrip() {
        let account = TrieAccount { extension: TestExtension(42), ..Default::default() };
        let encoded = alloy_rlp::encode(account);

        assert_eq!(TrieAccount::decode(&mut encoded.as_slice()).unwrap(), account);
    }
}
