use alloy_primitives::{Bytes, B256};
use nybbles::Nibbles;
use thiserror::Error;

/// Error during proof verification.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofVerificationError {
    /// State root does not match the expected.
    #[error("root mismatch. got: {got}, expected: {expected}")]
    RootMismatch {
        /// Computed state root.
        got: B256,
        /// State root provided to verify function.
        expected: B256,
    },
    /// The node value does not match at specified path.
    #[error("value mismatch at path {path:?}. got: {got:?}, expected: {expected:?}")]
    ValueMismatch {
        /// Path at which error occurred.
        path: Nibbles,
        /// Value in the proof.
        got: Option<Bytes>,
        /// Expected value.
        expected: Option<Bytes>,
    },
    /// Encountered unexpected empty root node.
    #[error("unexpected empty root node")]
    UnexpectedEmptyRoot,
    /// Error during RLP decoding of trie node.
    #[error(transparent)]
    Rlp(#[from] alloy_rlp::Error),
}
