//! Proof verification logic.

#[allow(unused_imports)]
use alloc::vec::Vec;

mod verify;
pub use verify::verify_proof;

mod error;
pub use error::ProofVerificationError;

mod retainer;
pub use retainer::ProofRetainer;
