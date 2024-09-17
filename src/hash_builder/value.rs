use alloy_primitives::{hex, B256};
use core::fmt;

#[allow(unused_imports)]
use alloc::vec::Vec;

/// The current value of the hash builder.
#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(derive_arbitrary::Arbitrary, proptest_derive::Arbitrary))]
pub enum HashBuilderValue {
    /// Hash of adjacent nodes.
    Hash(B256),
    /// Value of the leaf node.
    Bytes(Vec<u8>),
}

impl fmt::Debug for HashBuilderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(bytes) => write!(f, "Bytes({:?})", hex::encode(bytes)),
            Self::Hash(hash) => write!(f, "Hash({:?})", hash),
        }
    }
}

impl From<Vec<u8>> for HashBuilderValue {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

impl From<&[u8]> for HashBuilderValue {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

impl From<B256> for HashBuilderValue {
    fn from(value: B256) -> Self {
        Self::Hash(value)
    }
}

impl Default for HashBuilderValue {
    fn default() -> Self {
        Self::Bytes(vec![])
    }
}
