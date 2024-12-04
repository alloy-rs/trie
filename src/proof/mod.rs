//! Proof verification logic.

#[allow(unused_imports)]
use alloc::vec::Vec;

mod verify;
pub use verify::verify_proof;

mod error;
pub use error::ProofVerificationError;

mod proof_nodes;
pub use proof_nodes::ProofNodes;

mod retainer;
pub use retainer::{BranchNodeHashMasks, ProofRetainer};
