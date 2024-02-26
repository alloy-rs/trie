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
#![cfg_attr(not(test), warn(unused_crate_dependencies))] // TODO: https://github.com/proptest-rs/proptest/pull/427
#![allow(unknown_lints, non_local_definitions)]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

pub mod nodes;
pub use nodes::BranchNodeCompact;

pub mod hash_builder;
pub use hash_builder::HashBuilder;

mod mask;
pub use mask::TrieMask;

#[cfg(feature = "std")]
use hashbrown as _;
#[cfg(feature = "std")]
pub use std::collections::HashMap;

#[cfg(not(feature = "std"))]
pub use hashbrown::HashMap;

#[doc(no_inline)]
pub use nybbles::{self, Nibbles};

/// Root hash of an empty trie.
pub const EMPTY_ROOT_HASH: alloy_primitives::B256 =
    alloy_primitives::b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
