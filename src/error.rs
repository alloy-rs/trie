use thiserror::Error;
use alloy_rlp;

/// Error type for trie operations.
#[derive(Error, Debug)]
pub enum TrieError {
    /// Error during RLP encoding/decoding
    #[error("RLP error: {0}")]
    RlpError(
        /// The underlying RLP error
        #[from] alloy_rlp::Error
    ),

    /// Error when node key is empty
    #[error("trie node key empty")]
    EmptyNodeKey,

    /// Error when node has invalid number of items
    #[error("invalid number of items in the list: expected 2 or 17, got {0}")]
    InvalidItemCount(
        /// The actual number of items found
        usize
    ),

    /// Error when branch node has values (not supported)
    #[error("branch node values are not supported")]
    BranchNodeValues,

    /// Error when node type is invalid
    #[error("invalid node type: expected extension or leaf node")]
    InvalidNodeType,

    /// Error when RLP node is too large
    #[error("RLP node too large: size {size} exceeds maximum {max}")]
    RlpNodeTooLarge {
        /// The actual size of the RLP node in bytes
        size: usize,
        /// The maximum allowed size in bytes
        max: usize,
    },

    /// Error when proof verification fails
    #[error("proof verification failed: {0}")]
    ProofVerification(
        /// The reason for verification failure
        String
    ),

    /// Error when hash mismatch occurs
    #[error("hash mismatch: expected {expected}, got {found}")]
    HashMismatch {
        /// The expected hash value
        expected: String,
        /// The actual hash value found
        found: String,
    },
}

impl From<TrieError> for alloy_rlp::Error {
    fn from(err: TrieError) -> Self {
        match err {
            TrieError::RlpError(e) => e,
            TrieError::EmptyNodeKey => alloy_rlp::Error::Custom("trie node key empty"),
            TrieError::InvalidItemCount(_count) => alloy_rlp::Error::Custom("invalid number of items in the list"),
            TrieError::BranchNodeValues => alloy_rlp::Error::Custom("branch node values are not supported"),
            TrieError::InvalidNodeType => alloy_rlp::Error::Custom("invalid node type"),
            TrieError::RlpNodeTooLarge { size: _, max: _ } => alloy_rlp::Error::Custom("RLP node too large"),
            TrieError::ProofVerification(_msg) => alloy_rlp::Error::Custom("proof verification failed"),
            TrieError::HashMismatch { expected: _, found: _ } => alloy_rlp::Error::Custom("hash mismatch"),
        }
    }
} 