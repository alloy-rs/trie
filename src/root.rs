use crate::{EMPTY_ROOT_HASH, HashBuilder};
use alloc::vec::Vec;
use alloy_primitives::B256;
use alloy_rlp::Encodable;
use core::fmt;
use nybbles::Nibbles;

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

/// Compute a trie root of the collection of pre-encoded items.
///
/// This is an optimized version of [`ordered_trie_root_with_encoder`] for items that are
/// already encoded as rlp (for example EIP-2718 transactions).
///
/// Each item is inserted into the trie with its index (adjusted by [`adjust_index_for_rlp`])
/// as the key and the item's byte representation as the value.
///
/// Returns [`EMPTY_ROOT_HASH`] if the collection is empty.
pub fn ordered_trie_root_encoded<T>(items: &[T]) -> B256
where
    T: AsRef<[u8]>,
{
    if items.is_empty() {
        return EMPTY_ROOT_HASH;
    }
    let mut hb = HashBuilder::default();
    let items_len = items.len();
    for i in 0..items_len {
        let index = adjust_index_for_rlp(i, items_len);

        let index_buffer = alloy_rlp::encode_fixed_size(&index);
        hb.add_leaf(Nibbles::unpack(&index_buffer), items[index].as_ref());
    }

    hb.root()
}

/// Error returned when using [`OrderedTrieRootBuilder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderedRootError {
    /// Called `finalize()` before all items were pushed.
    Incomplete {
        /// The expected number of items.
        expected: usize,
        /// The number of items received.
        received: usize,
    },
    /// Index is out of bounds.
    IndexOutOfBounds {
        /// The index that was provided.
        index: usize,
        /// The expected length.
        len: usize,
    },
    /// Item at this index was already pushed.
    DuplicateIndex {
        /// The duplicate index.
        index: usize,
    },
}

impl fmt::Display for OrderedRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { expected, received } => {
                write!(f, "incomplete: expected {expected} items, received {received}")
            }
            Self::IndexOutOfBounds { index, len } => {
                write!(f, "index {index} out of bounds for length {len}")
            }
            Self::DuplicateIndex { index } => {
                write!(f, "duplicate item at index {index}")
            }
        }
    }
}

impl core::error::Error for OrderedRootError {}

/// A builder for computing ordered trie roots incrementally.
///
/// This builder allows you to push items one by one as they become available
/// (e.g., receipts after each transaction execution), rather than requiring
/// all items upfront like [`ordered_trie_root_with_encoder`].
///
/// Items can be pushed in any order by specifying their index. The builder
/// internally buffers items and flushes them to the underlying [`HashBuilder`]
/// in the correct order for RLP key encoding.
///
/// # Example
///
/// ```
/// use alloy_trie::root::OrderedTrieRootBuilder;
/// use alloy_rlp::Encodable;
///
/// // Create a builder for 3 items
/// let mut builder = OrderedTrieRootBuilder::new(3, |item: &u64, buf: &mut Vec<u8>| {
///     item.encode(buf);
/// });
///
/// // Push items as they arrive (can be out of order)
/// builder.push(0, &100u64).unwrap();
/// builder.push(2, &300u64).unwrap();  // out of order is fine
/// builder.push(1, &200u64).unwrap();
///
/// // Finalize to get the root hash
/// let root = builder.finalize().unwrap();
/// ```
#[derive(Debug)]
pub struct OrderedTrieRootBuilder<T, F> {
    /// Total expected number of items.
    len: usize,
    /// Number of items received so far.
    received: usize,
    /// Next insertion loop counter (determines which adjusted index to flush next).
    next_insert_i: usize,
    /// Buffer for pending encoded items, indexed by execution index.
    pending: Vec<Option<Vec<u8>>>,
    /// The underlying hash builder.
    hb: HashBuilder,
    /// Encoder function.
    encode: F,
    /// Reusable buffer for encoding.
    encode_buf: Vec<u8>,
    /// Phantom marker for the item type.
    _marker: core::marker::PhantomData<T>,
}

impl<T, F> OrderedTrieRootBuilder<T, F>
where
    F: FnMut(&T, &mut Vec<u8>),
{
    /// Creates a new builder for `len` items with a custom encoder.
    ///
    /// # Arguments
    ///
    /// * `len` - The total number of items that will be pushed.
    /// * `encode` - A function that encodes an item into a byte buffer.
    pub fn new(len: usize, encode: F) -> Self {
        Self {
            len,
            received: 0,
            next_insert_i: 0,
            pending: vec![None; len],
            hb: HashBuilder::default(),
            encode,
            encode_buf: Vec::new(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Pushes an item at the given index to the builder.
    ///
    /// Items can be pushed in any order. The builder will automatically
    /// flush items to the underlying [`HashBuilder`] when they become
    /// available in the correct order.
    ///
    /// # Errors
    ///
    /// - [`OrderedRootError::IndexOutOfBounds`] if `index >= len`
    /// - [`OrderedRootError::DuplicateIndex`] if an item was already pushed at this index
    pub fn push(&mut self, index: usize, item: &T) -> Result<(), OrderedRootError> {
        if index >= self.len {
            return Err(OrderedRootError::IndexOutOfBounds { index, len: self.len });
        }

        if self.pending[index].is_some() {
            return Err(OrderedRootError::DuplicateIndex { index });
        }

        // Encode the item
        self.encode_buf.clear();
        (self.encode)(item, &mut self.encode_buf);

        // Store in pending buffer at the specified index
        self.pending[index] = Some(self.encode_buf.clone());
        self.received += 1;

        // Try to flush as many items as possible
        self.flush();

        Ok(())
    }

    /// Attempts to flush pending items to the hash builder.
    fn flush(&mut self) {
        while self.next_insert_i < self.len {
            let exec_index_needed = adjust_index_for_rlp(self.next_insert_i, self.len);

            // Check if we have the item at this execution index
            let Some(value) = self.pending[exec_index_needed].take() else {
                break;
            };

            // Add the leaf with the RLP-encoded index as key
            let index_buffer = alloy_rlp::encode_fixed_size(&exec_index_needed);
            self.hb.add_leaf(Nibbles::unpack(&index_buffer), &value);

            self.next_insert_i += 1;
        }
    }

    /// Returns `true` if all items have been pushed.
    #[inline]
    pub const fn is_complete(&self) -> bool {
        self.received == self.len
    }

    /// Returns the number of items pushed so far.
    #[inline]
    pub const fn pushed_count(&self) -> usize {
        self.received
    }

    /// Returns the expected total number of items.
    #[inline]
    pub const fn expected_count(&self) -> usize {
        self.len
    }

    /// Finalizes the builder and returns the trie root.
    ///
    /// # Errors
    ///
    /// Returns [`OrderedRootError::Incomplete`] if not all items have been pushed.
    pub fn finalize(mut self) -> Result<B256, OrderedRootError> {
        if self.len == 0 {
            return Ok(EMPTY_ROOT_HASH);
        }

        if self.received != self.len {
            return Err(OrderedRootError::Incomplete {
                expected: self.len,
                received: self.received,
            });
        }

        // All items should have been flushed by now
        debug_assert_eq!(self.next_insert_i, self.len, "not all items were flushed");

        Ok(self.hb.root())
    }
}

impl<T: Encodable> OrderedTrieRootBuilder<T, fn(&T, &mut Vec<u8>)> {
    /// Creates a new builder for `len` RLP-encodable items.
    pub fn with_rlp_encoding(len: usize) -> Self {
        Self::new(len, |item: &T, buf: &mut Vec<u8>| item.encode(buf))
    }
}

/// A builder for computing ordered trie roots incrementally from pre-encoded items.
///
/// This is similar to [`OrderedTrieRootBuilder`] but for items that are already
/// encoded (e.g., EIP-2718 transactions).
///
/// # Example
///
/// ```
/// use alloy_trie::root::OrderedTrieRootEncodedBuilder;
///
/// // Create a builder for 2 pre-encoded items
/// let mut builder = OrderedTrieRootEncodedBuilder::new(2);
///
/// // Push pre-encoded items as they arrive (can be out of order)
/// builder.push(1, b"encoded_item_1").unwrap();
/// builder.push(0, b"encoded_item_0").unwrap();
///
/// // Finalize to get the root hash
/// let root = builder.finalize().unwrap();
/// ```
#[derive(Debug)]
pub struct OrderedTrieRootEncodedBuilder {
    /// Total expected number of items.
    len: usize,
    /// Number of items received so far.
    received: usize,
    /// Next insertion loop counter (determines which adjusted index to flush next).
    next_insert_i: usize,
    /// Buffer for pending items, indexed by execution index.
    pending: Vec<Option<Vec<u8>>>,
    /// The underlying hash builder.
    hb: HashBuilder,
}

impl OrderedTrieRootEncodedBuilder {
    /// Creates a new builder for `len` pre-encoded items.
    pub fn new(len: usize) -> Self {
        Self {
            len,
            received: 0,
            next_insert_i: 0,
            pending: vec![None; len],
            hb: HashBuilder::default(),
        }
    }

    /// Pushes a pre-encoded item at the given index to the builder.
    ///
    /// Items can be pushed in any order. The builder will automatically
    /// flush items to the underlying [`HashBuilder`] when they become
    /// available in the correct order.
    ///
    /// # Errors
    ///
    /// - [`OrderedRootError::IndexOutOfBounds`] if `index >= len`
    /// - [`OrderedRootError::DuplicateIndex`] if an item was already pushed at this index
    pub fn push(&mut self, index: usize, bytes: &[u8]) -> Result<(), OrderedRootError> {
        if index >= self.len {
            return Err(OrderedRootError::IndexOutOfBounds { index, len: self.len });
        }

        if self.pending[index].is_some() {
            return Err(OrderedRootError::DuplicateIndex { index });
        }

        // Store in pending buffer at the specified index
        self.pending[index] = Some(bytes.to_vec());
        self.received += 1;

        // Try to flush as many items as possible
        self.flush();

        Ok(())
    }

    /// Attempts to flush pending items to the hash builder.
    fn flush(&mut self) {
        while self.next_insert_i < self.len {
            let exec_index_needed = adjust_index_for_rlp(self.next_insert_i, self.len);

            // Check if we have the item at this execution index
            let Some(value) = self.pending[exec_index_needed].take() else {
                break;
            };

            // Add the leaf with the RLP-encoded index as key
            let index_buffer = alloy_rlp::encode_fixed_size(&exec_index_needed);
            self.hb.add_leaf(Nibbles::unpack(&index_buffer), &value);

            self.next_insert_i += 1;
        }
    }

    /// Returns `true` if all items have been pushed.
    #[inline]
    pub const fn is_complete(&self) -> bool {
        self.received == self.len
    }

    /// Returns the number of items pushed so far.
    #[inline]
    pub const fn pushed_count(&self) -> usize {
        self.received
    }

    /// Returns the expected total number of items.
    #[inline]
    pub const fn expected_count(&self) -> usize {
        self.len
    }

    /// Finalizes the builder and returns the trie root.
    ///
    /// # Errors
    ///
    /// Returns [`OrderedRootError::Incomplete`] if not all items have been pushed.
    pub fn finalize(mut self) -> Result<B256, OrderedRootError> {
        if self.len == 0 {
            return Ok(EMPTY_ROOT_HASH);
        }

        if self.received != self.len {
            return Err(OrderedRootError::Incomplete {
                expected: self.len,
                received: self.received,
            });
        }

        // All items should have been flushed by now
        debug_assert_eq!(self.next_insert_i, self.len, "not all items were flushed");

        Ok(self.hb.root())
    }
}

/// Ethereum specific trie root functions.
#[cfg(feature = "ethereum")]
pub use ethereum::*;
#[cfg(feature = "ethereum")]
mod ethereum {
    use super::*;
    use crate::TrieAccount;
    use alloy_primitives::{Address, U256, keccak256};

    /// Hashes storage keys, sorts them and them calculates the root hash of the storage trie.
    /// See [`storage_root_unsorted`] for more info.
    pub fn storage_root_unhashed(storage: impl IntoIterator<Item = (B256, U256)>) -> B256 {
        storage_root_unsorted(storage.into_iter().map(|(slot, value)| (keccak256(slot), value)))
    }

    /// Sorts and calculates the root hash of account storage trie.
    /// See [`storage_root`] for more info.
    pub fn storage_root_unsorted(storage: impl IntoIterator<Item = (B256, U256)>) -> B256 {
        let mut v = Vec::from_iter(storage);
        v.sort_unstable_by_key(|(key, _)| *key);
        storage_root(v)
    }

    /// Calculates the root hash of account storage trie.
    ///
    /// # Panics
    ///
    /// If the items are not in sorted order.
    pub fn storage_root(storage: impl IntoIterator<Item = (B256, U256)>) -> B256 {
        let mut hb = HashBuilder::default();
        for (hashed_slot, value) in storage {
            hb.add_leaf(
                Nibbles::unpack(hashed_slot),
                alloy_rlp::encode_fixed_size(&value).as_ref(),
            );
        }
        hb.root()
    }

    /// Hashes and sorts account keys, then proceeds to calculating the root hash of the state
    /// represented as MPT.
    /// See [`state_root_unsorted`] for more info.
    pub fn state_root_ref_unhashed<'a, A: Into<TrieAccount> + Clone + 'a>(
        state: impl IntoIterator<Item = (&'a Address, &'a A)>,
    ) -> B256 {
        state_root_unsorted(
            state.into_iter().map(|(address, account)| (keccak256(address), account.clone())),
        )
    }

    /// Hashes and sorts account keys, then proceeds to calculating the root hash of the state
    /// represented as MPT.
    /// See [`state_root_unsorted`] for more info.
    pub fn state_root_unhashed<A: Into<TrieAccount>>(
        state: impl IntoIterator<Item = (Address, A)>,
    ) -> B256 {
        state_root_unsorted(
            state.into_iter().map(|(address, account)| (keccak256(address), account)),
        )
    }

    /// Sorts the hashed account keys and calculates the root hash of the state represented as MPT.
    /// See [`state_root`] for more info.
    pub fn state_root_unsorted<A: Into<TrieAccount>>(
        state: impl IntoIterator<Item = (B256, A)>,
    ) -> B256 {
        let mut vec = Vec::from_iter(state);
        vec.sort_unstable_by_key(|(key, _)| *key);
        state_root(vec)
    }

    /// Calculates the root hash of the state represented as MPT.
    ///
    /// Corresponds to [geth's `deriveHash`](https://github.com/ethereum/go-ethereum/blob/6c149fd4ad063f7c24d726a73bc0546badd1bc73/core/genesis.go#L119).
    ///
    /// # Panics
    ///
    /// If the items are not in sorted order.
    pub fn state_root<A: Into<TrieAccount>>(state: impl IntoIterator<Item = (B256, A)>) -> B256 {
        let mut hb = HashBuilder::default();
        let mut account_rlp_buf = Vec::new();
        for (hashed_key, account) in state {
            account_rlp_buf.clear();
            account.into().encode(&mut account_rlp_buf);
            hb.add_leaf(Nibbles::unpack(hashed_key), &account_rlp_buf);
        }
        hb.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that `adjust_index_for_rlp` produces the expected reordering.
    #[test]
    fn test_adjust_index_for_rlp() {
        // For len=1: [0] -> iter i=0 maps to exec_index=0
        assert_eq!(adjust_index_for_rlp(0, 1), 0);

        // For len=2: insertion order should be [1, 0]
        assert_eq!(adjust_index_for_rlp(0, 2), 1);
        assert_eq!(adjust_index_for_rlp(1, 2), 0);

        // For len=3: insertion order should be [1, 2, 0]
        assert_eq!(adjust_index_for_rlp(0, 3), 1);
        assert_eq!(adjust_index_for_rlp(1, 3), 2);
        assert_eq!(adjust_index_for_rlp(2, 3), 0);

        // For len=128: insertion order is [1, 2, ..., 127, 0]
        // i=0 -> 1, i=1 -> 2, ..., i=126 -> 127, i=127 (last element) -> 0
        assert_eq!(adjust_index_for_rlp(0, 128), 1);
        assert_eq!(adjust_index_for_rlp(126, 128), 127);
        assert_eq!(adjust_index_for_rlp(127, 128), 0); // last element maps to 0

        // For len=129: insertion order is [1, 2, ..., 127, 0, 128]
        // i=127 (0x7f) triggers the "i == 0x7f" condition, mapping to 0
        // i=128 > 0x7f, so it stays as 128
        assert_eq!(adjust_index_for_rlp(0, 129), 1);
        assert_eq!(adjust_index_for_rlp(126, 129), 127);
        assert_eq!(adjust_index_for_rlp(127, 129), 0); // 0x7f maps to 0
        assert_eq!(adjust_index_for_rlp(128, 129), 128); // > 0x7f, stays same

        // For len=130: [1, 2, ..., 127, 0, 128, 129]
        // i > 0x7f is checked first, so 128 and 129 just return themselves
        assert_eq!(adjust_index_for_rlp(0, 130), 1);
        assert_eq!(adjust_index_for_rlp(126, 130), 127);
        assert_eq!(adjust_index_for_rlp(127, 130), 0); // 0x7f maps to 0
        assert_eq!(adjust_index_for_rlp(128, 130), 128); // > 0x7f, stays same
        assert_eq!(adjust_index_for_rlp(129, 130), 129); // > 0x7f, stays same
    }

    /// Test OrderedTrieRootBuilder produces same results as ordered_trie_root_with_encoder
    #[test]
    fn test_ordered_builder_equivalence() {
        // Test with various lengths including edge cases
        for len in [0, 1, 2, 3, 10, 127, 128, 129, 130, 200] {
            let items: Vec<u64> = (0..len).map(|i| i as u64 * 100).collect();

            // Compute using the existing function
            let expected = ordered_trie_root_with_encoder(&items, |item, buf| {
                alloy_rlp::Encodable::encode(item, buf);
            });

            // Compute using the builder (in order)
            let mut builder =
                OrderedTrieRootBuilder::new(len, |item: &u64, buf: &mut Vec<u8>| {
                    alloy_rlp::Encodable::encode(item, buf);
                });

            for (i, item) in items.iter().enumerate() {
                builder.push(i, item).unwrap();
            }

            let actual = builder.finalize().unwrap();
            assert_eq!(
                expected, actual,
                "mismatch for len={len}: expected {expected:?}, got {actual:?}"
            );
        }
    }

    /// Test OrderedTrieRootBuilder with out-of-order pushes
    #[test]
    fn test_ordered_builder_out_of_order() {
        // Test that pushing items out of order still produces correct root
        for len in [2, 3, 5, 10, 50] {
            let items: Vec<u64> = (0..len).map(|i| i as u64 * 100).collect();

            let expected = ordered_trie_root_with_encoder(&items, |item, buf| {
                alloy_rlp::Encodable::encode(item, buf);
            });

            // Push in reverse order
            let mut builder =
                OrderedTrieRootBuilder::new(len, |item: &u64, buf: &mut Vec<u8>| {
                    alloy_rlp::Encodable::encode(item, buf);
                });

            for i in (0..len).rev() {
                builder.push(i, &items[i]).unwrap();
            }

            let actual = builder.finalize().unwrap();
            assert_eq!(expected, actual, "mismatch for reverse order len={len}");

            // Push in random order (odds first, then evens)
            let mut builder =
                OrderedTrieRootBuilder::new(len, |item: &u64, buf: &mut Vec<u8>| {
                    alloy_rlp::Encodable::encode(item, buf);
                });

            for i in (1..len).step_by(2) {
                builder.push(i, &items[i]).unwrap();
            }
            for i in (0..len).step_by(2) {
                builder.push(i, &items[i]).unwrap();
            }

            let actual = builder.finalize().unwrap();
            assert_eq!(expected, actual, "mismatch for odd/even order len={len}");
        }
    }

    /// Test OrderedTrieRootEncodedBuilder produces same results as ordered_trie_root_encoded
    #[test]
    fn test_ordered_encoded_builder_equivalence() {
        for len in [0, 1, 2, 3, 10, 127, 128, 129, 130, 200] {
            // Generate some "encoded" items (just arbitrary bytes for testing)
            let items: Vec<Vec<u8>> =
                (0..len).map(|i| format!("item_{i}_data").into_bytes()).collect();

            // Compute using the existing function
            let expected = ordered_trie_root_encoded(&items);

            // Compute using the builder
            let mut builder = OrderedTrieRootEncodedBuilder::new(len);

            for (i, item) in items.iter().enumerate() {
                builder.push(i, item).unwrap();
            }

            let actual = builder.finalize().unwrap();
            assert_eq!(
                expected, actual,
                "mismatch for len={len}: expected {expected:?}, got {actual:?}"
            );
        }
    }

    /// Test that the builder correctly handles the empty case
    #[test]
    fn test_ordered_builder_empty() {
        let builder: OrderedTrieRootBuilder<u64, _> =
            OrderedTrieRootBuilder::new(0, |_: &u64, _: &mut Vec<u8>| {});
        assert!(builder.is_complete());
        assert_eq!(builder.finalize().unwrap(), EMPTY_ROOT_HASH);

        let builder = OrderedTrieRootEncodedBuilder::new(0);
        assert!(builder.is_complete());
        assert_eq!(builder.finalize().unwrap(), EMPTY_ROOT_HASH);
    }

    /// Test that finalize errors when incomplete
    #[test]
    fn test_ordered_builder_incomplete_error() {
        let mut builder = OrderedTrieRootBuilder::new(3, |item: &u64, buf: &mut Vec<u8>| {
            alloy_rlp::Encodable::encode(item, buf);
        });

        builder.push(0, &1u64).unwrap();
        builder.push(1, &2u64).unwrap();
        // Don't push the third item

        assert!(!builder.is_complete());
        assert_eq!(
            builder.finalize(),
            Err(OrderedRootError::Incomplete { expected: 3, received: 2 })
        );
    }

    /// Test index validation errors
    #[test]
    fn test_ordered_builder_index_errors() {
        let mut builder = OrderedTrieRootBuilder::new(2, |item: &u64, buf: &mut Vec<u8>| {
            alloy_rlp::Encodable::encode(item, buf);
        });

        // Test out of bounds
        assert_eq!(
            builder.push(5, &1u64),
            Err(OrderedRootError::IndexOutOfBounds { index: 5, len: 2 })
        );

        // Push valid item
        builder.push(0, &1u64).unwrap();

        // Test duplicate
        assert_eq!(builder.push(0, &2u64), Err(OrderedRootError::DuplicateIndex { index: 0 }));

        // Complete the builder
        builder.push(1, &2u64).unwrap();
        assert!(builder.is_complete());
    }

    /// Test is_complete and pushed_count
    #[test]
    fn test_ordered_builder_state_tracking() {
        let mut builder = OrderedTrieRootBuilder::new(3, |item: &u64, buf: &mut Vec<u8>| {
            alloy_rlp::Encodable::encode(item, buf);
        });

        assert_eq!(builder.pushed_count(), 0);
        assert_eq!(builder.expected_count(), 3);
        assert!(!builder.is_complete());

        builder.push(0, &1u64).unwrap();
        assert_eq!(builder.pushed_count(), 1);
        assert!(!builder.is_complete());

        builder.push(2, &3u64).unwrap(); // out of order is fine
        assert_eq!(builder.pushed_count(), 2);
        assert!(!builder.is_complete());

        builder.push(1, &2u64).unwrap();
        assert_eq!(builder.pushed_count(), 3);
        assert!(builder.is_complete());
    }

    /// Test that items are flushed incrementally when possible
    #[test]
    fn test_ordered_builder_incremental_flush() {
        // For len=3, insertion order is [1, 2, 0]
        // So after pushing exec_index 0, nothing can be flushed (need exec_index 1 first)
        // After pushing exec_index 1, we can flush exec_index 1
        // After pushing exec_index 2, we can flush exec_index 2 and then exec_index 0

        let mut builder = OrderedTrieRootBuilder::new(3, |item: &u64, buf: &mut Vec<u8>| {
            alloy_rlp::Encodable::encode(item, buf);
        });

        // Push item at index 0
        builder.push(0, &100u64).unwrap();
        // next_insert_i should still be 0 because we need index 1 first
        assert_eq!(builder.next_insert_i, 0);

        // Push item at index 1
        builder.push(1, &200u64).unwrap();
        // Now we should have flushed index 1, so next_insert_i = 1
        assert_eq!(builder.next_insert_i, 1);

        // Push item at index 2
        builder.push(2, &300u64).unwrap();
        // Now we should have flushed index 2 and then index 0
        assert_eq!(builder.next_insert_i, 3);
        assert!(builder.is_complete());
    }

    /// Test with_rlp_encoding convenience constructor
    #[test]
    fn test_with_rlp_encoding() {
        let items: Vec<u64> = vec![100, 200, 300];

        let expected = ordered_trie_root(&items);

        let mut builder = OrderedTrieRootBuilder::<u64, _>::with_rlp_encoding(3);
        for (i, item) in items.iter().enumerate() {
            builder.push(i, item).unwrap();
        }
        let actual = builder.finalize().unwrap();

        assert_eq!(expected, actual);
    }

    /// Test single item
    #[test]
    fn test_ordered_builder_single_item() {
        let items = vec![42u64];

        let expected = ordered_trie_root(&items);

        let mut builder = OrderedTrieRootBuilder::new(1, |item: &u64, buf: &mut Vec<u8>| {
            alloy_rlp::Encodable::encode(item, buf);
        });
        builder.push(0, &42u64).unwrap();

        // For len=1, after pushing index 0, we should flush immediately
        assert_eq!(builder.next_insert_i, 1);
        assert!(builder.is_complete());

        assert_eq!(builder.finalize().unwrap(), expected);
    }

    /// Test that the flush logic handles boundary at 127/128 correctly
    #[test]
    fn test_ordered_builder_boundary_128() {
        // For len=128: insertion order is [1, 2, ..., 127, 0]
        // For len=129: insertion order is [1, 2, ..., 127, 0, 128]

        for len in [127, 128, 129, 130] {
            let items: Vec<u64> = (0..len).map(|i| i as u64).collect();

            let expected = ordered_trie_root(&items);

            let mut builder =
                OrderedTrieRootBuilder::new(len, |item: &u64, buf: &mut Vec<u8>| {
                    alloy_rlp::Encodable::encode(item, buf);
                });

            for (i, item) in items.iter().enumerate() {
                builder.push(i, item).unwrap();
            }

            assert!(builder.is_complete());
            assert_eq!(builder.finalize().unwrap(), expected, "failed for len={len}");
        }
    }
}
