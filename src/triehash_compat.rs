//! Implementation of hasher using our keccak256 hashing function for compatibility with `triehash`
//! crate.

use alloy_primitives::{keccak256, B256};
use hash_db::Hasher;
use plain_hasher::PlainHasher;

/// A [Hasher] that calculates a keccak256 hash of the given data.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeccakHasher;

impl Hasher for KeccakHasher {
    type Out = B256;
    type StdHasher = PlainHasher;

    const LENGTH: usize = 32;

    fn hash(x: &[u8]) -> Self::Out {
        keccak256(x)
    }
}
