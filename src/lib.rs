#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/alloy.jpg",
    html_favicon_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/favicon.ico"
)]
#![warn(
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    unreachable_pub,
    clippy::missing_const_for_fn,
    rustdoc::all
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
#[allow(unused_imports)]
extern crate alloc;

pub mod nodes;
pub use nodes::BranchNodeCompact;

pub mod hash_builder;
pub use hash_builder::HashBuilder;

pub mod proof;

mod mask;
pub use mask::TrieMask;

#[doc(hidden)]
pub use alloy_primitives::map::HashMap;

#[doc(no_inline)]
pub use nybbles::{self, Nibbles};

/// Root hash of an empty trie.
pub const EMPTY_ROOT_HASH: alloy_primitives::B256 =
    alloy_primitives::b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

#[cfg(test)]
pub(crate) fn triehash_trie_root<I, K, V>(iter: I) -> alloy_primitives::B256
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<[u8]> + Ord,
    V: AsRef<[u8]>,
{
    struct Keccak256Hasher;
    impl hash_db::Hasher for Keccak256Hasher {
        type Out = alloy_primitives::B256;
        type StdHasher = plain_hasher::PlainHasher;

        const LENGTH: usize = 32;

        fn hash(x: &[u8]) -> Self::Out {
            alloy_primitives::keccak256(x)
        }
    }

    // We use `trie_root` instead of `sec_trie_root` because we assume
    // the incoming keys are already hashed, which makes sense given
    // we're going to be using the Hashed tables & pre-hash the data
    // on the way in.
    triehash::trie_root::<Keccak256Hasher, _, _, _>(iter)
}
