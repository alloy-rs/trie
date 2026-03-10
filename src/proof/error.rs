use alloc::boxed::Box;
use alloy_primitives::{B256, Bytes};
use nybbles::Nibbles;

/// Error during proof verification.
#[derive(PartialEq, Eq, Debug, thiserror::Error)]
pub enum ProofVerificationError {
    /// State root does not match the expected.
    #[error(transparent)]
    RootMismatch(Box<RootMismatchError>),
    /// The node value does not match at specified path.
    #[error(transparent)]
    ValueMismatch(Box<ValueMismatchError>),
    /// Encountered unexpected empty root node.
    #[error("unexpected empty root node")]
    UnexpectedEmptyRoot,
    /// Error during RLP decoding of trie node.
    #[error(transparent)]
    Rlp(#[from] alloy_rlp::Error),
}

/// State root does not match the expected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("root mismatch. got: {got}. expected: {expected}")]
pub struct RootMismatchError {
    /// Computed state root.
    pub got: B256,
    /// State root provided to verify function.
    pub expected: B256,
}

/// The node value does not match at specified path.
#[derive(PartialEq, Eq, Debug, thiserror::Error)]
#[error("value mismatch at path {path:?}. got: {got:?}. expected: {expected:?}")]
pub struct ValueMismatchError {
    /// Path at which error occurred.
    pub path: Nibbles,
    /// Value in the proof.
    pub got: Option<Bytes>,
    /// Expected value.
    pub expected: Option<Bytes>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_size() {
        let size = core::mem::size_of::<ProofVerificationError>();
        eprintln!("ProofVerificationError size: {size} bytes");
        // Down from 144 bytes to 24 bytes after boxing both large variants.
        assert!(size <= 24, "ProofVerificationError is {size} bytes, should be <= 24");
    }
}
