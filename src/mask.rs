use core::fmt;
use derive_more::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Deref, From, Not};

/// A struct representing a mask of 16 bits, used for Ethereum trie operations.
///
/// Masks in a trie are used to efficiently represent and manage information about the presence or
/// absence of certain elements, such as child nodes, within a trie. Masks are usually implemented
/// as bit vectors, where each bit represents the presence (1) or absence (0) of a corresponding
/// element.
#[derive(
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deref,
    From,
    BitAnd,
    BitAndAssign,
    BitOr,
    BitOrAssign,
    Not,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(derive_arbitrary::Arbitrary, proptest_derive::Arbitrary))]
pub struct TrieMask(u16);

impl fmt::Debug for TrieMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TrieMask({:016b})", self.0)
    }
}

impl TrieMask {
    /// Creates a new `TrieMask` from the given inner value.
    #[inline]
    pub const fn new(inner: u16) -> Self {
        Self(inner)
    }

    /// Returns the inner value of the `TrieMask`.
    #[inline]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Creates a new `TrieMask` from the given nibble.
    #[inline]
    pub const fn from_nibble(nibble: u8) -> Self {
        Self(1u16 << nibble)
    }

    /// Returns `true` if the current `TrieMask` is a subset of `other`.
    #[inline]
    pub fn is_subset_of(self, other: Self) -> bool {
        self & other == self
    }

    /// Returns `true` if a given bit is set in a mask.
    #[inline]
    pub const fn is_bit_set(self, index: u8) -> bool {
        self.0 & (1u16 << index) != 0
    }

    /// Returns `true` if the mask is empty.
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the number of bits set in the mask.
    #[inline]
    pub const fn count_bits(self) -> u8 {
        self.0.count_ones() as u8
    }

    /// Returns the index of the first bit set in the mask, or `None` if the mask is empty.
    #[inline]
    pub const fn first_set_bit_index(self) -> Option<u8> {
        if self.is_empty() { None } else { Some(self.0.trailing_zeros() as u8) }
    }

    /// Set bit at a specified index.
    #[inline]
    pub fn set_bit(&mut self, index: u8) {
        self.0 |= 1u16 << index;
    }

    /// Unset bit at a specified index.
    #[inline]
    pub fn unset_bit(&mut self, index: u8) {
        self.0 &= !(1u16 << index);
    }
}

/// A unified mask set that groups state, tree, and hash masks together for better cache locality.
/// 
/// This structure replaces the separate `Vec<TrieMask>` for each mask type in HashBuilder,
/// ensuring that when masks are accessed together at the same depth, they are loaded
/// in the same cache line, reducing cache misses in the hot update loop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(derive_arbitrary::Arbitrary, proptest_derive::Arbitrary))]
pub struct MaskSet {
    /// Mask indicating which children are present in the trie node
    pub state: TrieMask,
    /// Mask indicating which children are stored in the database
    pub tree: TrieMask,
    /// Mask indicating which children are represented by hashes (not inline data)
    pub hash: TrieMask,
}

impl MaskSet {
    /// Creates a new empty mask set.
    #[inline]
    pub const fn new() -> Self {
        Self {
            state: TrieMask::new(0),
            tree: TrieMask::new(0),
            hash: TrieMask::new(0),
        }
    }

    /// Creates a mask set with the given values.
    #[inline]
    pub const fn from_masks(state: TrieMask, tree: TrieMask, hash: TrieMask) -> Self {
        Self { state, tree, hash }
    }

    /// Returns true if all masks are empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.state.is_empty() && self.tree.is_empty() && self.hash.is_empty()
    }

    /// Clears all masks.
    #[inline]
    pub fn clear(&mut self) {
        self.state = TrieMask::new(0);
        self.tree = TrieMask::new(0);
        self.hash = TrieMask::new(0);
    }
}
