use crate::{Account, HashBuilder, EMPTY_ROOT_HASH};
use alloy_primitives::{keccak256, B256};
use alloy_rlp::Encodable;

use alloc::vec::Vec;
use nybbles::Nibbles;

#[cfg(feature = "std")]
use {alloy_primitives::Address, itertools::Itertools};

/// Adjust the index of an item for rlp encoding.
pub const fn adjust_index_for_rlp(i: usize, len: usize) -> usize {
    if i > 0x7f {
        i
    } else if i == 0x7f || i + 1 == len {
        0
    } else {
        i + 1
    }
}

/// Compute a trie root of the collection of rlp encodable items.
pub fn ordered_trie_root<T: Encodable>(items: &[T]) -> B256 {
    ordered_trie_root_with_encoder(items, |item, buf| item.encode(buf))
}

/// Compute a trie root of the collection of items with a custom encoder.
pub fn ordered_trie_root_with_encoder<T, F>(items: &[T], mut encode: F) -> B256
where
    F: FnMut(&T, &mut Vec<u8>),
{
    if items.is_empty() {
        return EMPTY_ROOT_HASH;
    }

    let mut value_buffer = Vec::new();

    let mut hb = HashBuilder::default();
    let items_len = items.len();
    for i in 0..items_len {
        let index = adjust_index_for_rlp(i, items_len);

        let index_buffer = alloy_rlp::encode_fixed_size(&index);

        value_buffer.clear();
        encode(&items[index], &mut value_buffer);

        hb.add_leaf(Nibbles::unpack(&index_buffer), &value_buffer);
    }

    hb.root()
}

/// Hashes and sorts account keys, then proceeds to calculating the root hash of the state
/// represented as MPT.
/// See [`state_root_unsorted`] for more info.
#[cfg(feature = "std")]
pub fn state_root_ref_unhashed<'a, A: Into<Account> + Clone + 'a>(
    state: impl IntoIterator<Item = (&'a Address, &'a A)>,
) -> B256 {
    state_root_unsorted(
        state.into_iter().map(|(address, account)| (keccak256(address), account.clone())),
    )
}

/// Hashes and sorts account keys, then proceeds to calculating the root hash of the state
/// represented as MPT.
/// See [`state_root_unsorted`] for more info.
#[cfg(feature = "std")]
pub fn state_root_unhashed<A: Into<Account>>(
    state: impl IntoIterator<Item = (Address, A)>,
) -> B256 {
    state_root_unsorted(state.into_iter().map(|(address, account)| (keccak256(address), account)))
}

/// Sorts the hashed account keys and calculates the root hash of the state represented as MPT.
/// See [`state_root`] for more info.
#[cfg(feature = "std")]
pub fn state_root_unsorted<A: Into<Account>>(state: impl IntoIterator<Item = (B256, A)>) -> B256 {
    state_root(state.into_iter().sorted_unstable_by_key(|(key, _)| *key))
}

/// Calculates the root hash of the state represented as MPT.
///
/// Corresponds to [geth's `deriveHash`](https://github.com/ethereum/go-ethereum/blob/6c149fd4ad063f7c24d726a73bc0546badd1bc73/core/genesis.go#L119).
///
/// # Panics
///
/// If the items are not in sorted order.
pub fn state_root<A: Into<Account>>(state: impl IntoIterator<Item = (B256, A)>) -> B256 {
    let mut hb = HashBuilder::default();
    for (hashed_key, account) in state {
        let account_rlp_buf = alloy_rlp::encode(account.into());
        hb.add_leaf(Nibbles::unpack(hashed_key), &account_rlp_buf);
    }
    hb.root()
}
