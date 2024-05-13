use alloc::boxed::Box;
use alloy_primitives::{Bytes, B256};
use core::fmt;
use nybbles::Nibbles;

/// Error during proof verification.
#[derive(PartialEq, Eq, Debug)]
pub enum ProofVerificationError {
    /// State root does not match the expected.
    RootMismatch {
        /// Computed state root.
        got: B256,
        /// State root provided to verify function.
        expected: B256,
    },
    /// The node value does not match at specified path.
    ValueMismatch {
        /// Path at which error occurred.
        path: Box<Nibbles>,
        /// Value in the proof.
        got: Box<Bytes>,
        /// Expected value.
        expected: Box<Bytes>,
    },
    /// Unexpected key encountered in proof during verification.
    UnexpectedKey {
        /// Path at which unexpected key was encountered.
        path: Box<Nibbles>,
        /// Unexpected key. Empty means entry is missing from branch node at given path.
        key: Box<Nibbles>,
    },
    /// Branch node child is missing at specified path.
    MissingBranchChild {
        /// Full path at which child is missing.
        path: Box<Nibbles>,
    },
    /// Error during RLP decoding of trie node.
    Rlp(alloy_rlp::Error),
}

/// Enable Error trait implementation when core is stabilized.
/// <https://github.com/rust-lang/rust/issues/103765>
#[cfg(feature = "std")]
impl std::error::Error for ProofVerificationError {
    fn source(&self) -> ::core::option::Option<&(dyn std::error::Error + 'static)> {
        #[allow(deprecated)]
        match self {
            ProofVerificationError::Rlp { 0: transparent } => {
                std::error::Error::source(transparent as &dyn std::error::Error)
            }
            _ => None,
        }
    }
}

impl fmt::Display for ProofVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofVerificationError::RootMismatch { got, expected } => {
                write!(f, "root mismatch. got: {got}. expected: {expected}")
            }
            ProofVerificationError::ValueMismatch { path, got, expected } => {
                write!(f, "value mismatch at path {path:?}. got: {got}. expected: {expected}")
            }
            ProofVerificationError::UnexpectedKey { path, key } => {
                write!(f, "unexpected node key {key:?} at path {path:?}")
            }
            ProofVerificationError::MissingBranchChild { path } => {
                write!(f, "missing branch child at path {path:?}")
            }
            ProofVerificationError::Rlp(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl From<alloy_rlp::Error> for ProofVerificationError {
    fn from(source: alloy_rlp::Error) -> Self {
        ProofVerificationError::Rlp(source)
    }
}

impl ProofVerificationError {
    /// Create [ProofVerificationError::ValueMismatch] error variant.
    pub fn value_mismatch(path: Nibbles, got: Bytes, expected: Bytes) -> Self {
        Self::ValueMismatch {
            path: Box::new(path),
            got: Box::new(got),
            expected: Box::new(expected),
        }
    }

    /// Create [ProofVerificationError::UnexpectedKey] error variant.
    pub fn unexpected_key(path: Nibbles, key: Nibbles) -> Self {
        Self::UnexpectedKey { path: Box::new(path), key: Box::new(key) }
    }

    /// Create [ProofVerificationError::MissingBranchChild] error variant.
    pub fn missing_branch_child(path: Nibbles) -> Self {
        Self::MissingBranchChild { path: Box::new(path) }
    }
}
