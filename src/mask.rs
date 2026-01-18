use core::{
    fmt,
    ops::{Shl, ShlAssign, Shr, ShrAssign},
};
use derive_more::{
    BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Deref, From, Not,
};

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
    BitAndAssign,
    BitAnd,
    BitOr,
    BitOrAssign,
    BitXor,
    BitXorAssign,
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
    /// The size of this mask in bits.
    pub const BITS: u32 = u16::BITS;

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
    pub const fn set_bit(&mut self, index: u8) {
        self.0 |= 1u16 << index;
    }

    /// Unset bit at a specified index.
    #[inline]
    pub const fn unset_bit(&mut self, index: u8) {
        self.0 &= !(1u16 << index);
    }
}

impl<T> Shl<T> for TrieMask
where
    u16: Shl<T, Output = u16>,
{
    type Output = Self;

    #[inline]
    fn shl(self, rhs: T) -> Self::Output {
        Self(self.0.shl(rhs))
    }
}

impl<T> ShlAssign<T> for TrieMask
where
    u16: ShlAssign<T>,
{
    #[inline]
    fn shl_assign(&mut self, rhs: T) {
        self.0.shl_assign(rhs);
    }
}

impl<T> Shr<T> for TrieMask
where
    u16: Shr<T, Output = u16>,
{
    type Output = Self;

    #[inline]
    fn shr(self, rhs: T) -> Self::Output {
        Self(self.0.shr(rhs))
    }
}

impl<T> ShrAssign<T> for TrieMask
where
    u16: ShrAssign<T>,
{
    #[inline]
    fn shr_assign(&mut self, rhs: T) {
        self.0.shr_assign(rhs);
    }
}
