//! Proof verification logic.

use crate::{HashMap, Nibbles};
#[allow(unused_imports)]
use alloc::vec::Vec;

mod verify;
pub use verify::verify_proof;

mod error;
pub use error::ProofVerificationError;

mod decoded_proof_nodes;
pub use decoded_proof_nodes::DecodedProofNodes;

mod decoded_retainer;
pub use decoded_retainer::DecodedProofRetainer;

mod proof_nodes;
pub use proof_nodes::ProofNodes;

mod retainer;
pub use retainer::ProofRetainer;

mod added_removed_keys;
pub use added_removed_keys::AddedRemovedKeys;

/// Returns the entries of a proof node map whose path is a prefix of the target.
///
/// A target of n nibbles has n + 1 prefixes. A lookup costs a few prefix comparisons, so once the
/// map holds several times more entries than that, looking up each prefix beats scanning the whole
/// map, which made matching every target of a multiproof quadratic. The lookups yield the entries
/// ordered by path.
fn matching_entries<'a, V>(
    nodes: &'a HashMap<Nibbles, V>,
    target: &'a Nibbles,
) -> impl Iterator<Item = (&'a Nibbles, &'a V)> {
    if nodes.len() > 4 * (target.len() + 1) {
        MatchingEntries::Lookups(
            (0..=target.len())
                .filter_map(|len| nodes.get_key_value(&target.slice_unchecked(0, len))),
        )
    } else {
        MatchingEntries::Scan(nodes.iter().filter(|(path, _)| target.starts_with(path)))
    }
}

/// The iterator [matching_entries] returns for either strategy.
enum MatchingEntries<S, L> {
    Scan(S),
    Lookups(L),
}

impl<T, S: Iterator<Item = T>, L: Iterator<Item = T>> Iterator for MatchingEntries<S, L> {
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<T> {
        match self {
            Self::Scan(iter) => iter.next(),
            Self::Lookups(iter) => iter.next(),
        }
    }
}
