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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trie_mask_new_and_get() {
        let mask = TrieMask::new(0b1010);
        assert_eq!(mask.get(), 0b1010);

        let mask = TrieMask::new(0xFFFF);
        assert_eq!(mask.get(), 0xFFFF);

        let mask = TrieMask::new(0);
        assert_eq!(mask.get(), 0);
    }

    #[test]
    fn test_trie_mask_from_nibble() {
        assert_eq!(TrieMask::from_nibble(0).get(), 0b1);
        assert_eq!(TrieMask::from_nibble(1).get(), 0b10);
        assert_eq!(TrieMask::from_nibble(4).get(), 0b10000);
        assert_eq!(TrieMask::from_nibble(15).get(), 0b1000_0000_0000_0000);
    }

    #[test]
    fn test_trie_mask_is_bit_set() {
        let mask = TrieMask::new(0b1010);
        assert!(!mask.is_bit_set(0));
        assert!(mask.is_bit_set(1));
        assert!(!mask.is_bit_set(2));
        assert!(mask.is_bit_set(3));
    }

    #[test]
    fn test_trie_mask_is_empty() {
        assert!(TrieMask::new(0).is_empty());
        assert!(!TrieMask::new(1).is_empty());
        assert!(!TrieMask::new(0xFFFF).is_empty());
    }

    #[test]
    fn test_trie_mask_count_bits() {
        assert_eq!(TrieMask::new(0).count_bits(), 0);
        assert_eq!(TrieMask::new(0b1).count_bits(), 1);
        assert_eq!(TrieMask::new(0b1010).count_bits(), 2);
        assert_eq!(TrieMask::new(0b1111).count_bits(), 4);
        assert_eq!(TrieMask::new(0xFFFF).count_bits(), 16);
    }

    #[test]
    fn test_trie_mask_first_set_bit_index() {
        assert_eq!(TrieMask::new(0).first_set_bit_index(), None);
        assert_eq!(TrieMask::new(0b1).first_set_bit_index(), Some(0));
        assert_eq!(TrieMask::new(0b10).first_set_bit_index(), Some(1));
        assert_eq!(TrieMask::new(0b1000).first_set_bit_index(), Some(3));
        assert_eq!(TrieMask::new(0b1010).first_set_bit_index(), Some(1));
    }

    #[test]
    fn test_trie_mask_set_bit() {
        let mut mask = TrieMask::new(0);
        mask.set_bit(0);
        assert_eq!(mask.get(), 0b1);
        mask.set_bit(3);
        assert_eq!(mask.get(), 0b1001);
        mask.set_bit(0);
        assert_eq!(mask.get(), 0b1001);
    }

    #[test]
    fn test_trie_mask_unset_bit() {
        let mut mask = TrieMask::new(0b1111);
        mask.unset_bit(0);
        assert_eq!(mask.get(), 0b1110);
        mask.unset_bit(2);
        assert_eq!(mask.get(), 0b1010);
        mask.unset_bit(0);
        assert_eq!(mask.get(), 0b1010);
    }

    #[test]
    fn test_trie_mask_is_subset_of() {
        let subset = TrieMask::new(0b0101);
        let superset = TrieMask::new(0b1111);
        assert!(subset.is_subset_of(superset));
        assert!(!superset.is_subset_of(subset));
        assert!(subset.is_subset_of(subset));
        assert!(TrieMask::new(0).is_subset_of(subset));
    }

    #[test]
    fn test_trie_mask_bitwise_ops() {
        let a = TrieMask::new(0b1100);
        let b = TrieMask::new(0b1010);

        assert_eq!((a & b).get(), 0b1000);
        assert_eq!((a | b).get(), 0b1110);
        assert_eq!((a ^ b).get(), 0b0110);
        assert_eq!((!TrieMask::new(0)).get(), 0xFFFF);
    }

    #[test]
    fn test_trie_mask_shift_ops() {
        let mask = TrieMask::new(0b0100);
        assert_eq!((mask << 1).get(), 0b1000);
        assert_eq!((mask >> 1).get(), 0b0010);

        let mut mask = TrieMask::new(0b0100);
        mask <<= 2;
        assert_eq!(mask.get(), 0b10000);

        let mut mask = TrieMask::new(0b0100);
        mask >>= 2;
        assert_eq!(mask.get(), 0b0001);
    }

    #[test]
    fn test_trie_mask_debug() {
        let mask = TrieMask::new(0b1010);
        let debug_str = format!("{:?}", mask);
        assert!(debug_str.contains("TrieMask"));
        assert!(debug_str.contains("1010"));
    }

    #[test]
    fn test_trie_mask_default() {
        let mask = TrieMask::default();
        assert_eq!(mask.get(), 0);
        assert!(mask.is_empty());
    }

    #[test]
    fn test_trie_mask_deref() {
        let mask = TrieMask::new(0b1010);
        assert_eq!(*mask, 0b1010u16);
    }

    #[test]
    fn test_trie_mask_bits_constant() {
        assert_eq!(TrieMask::BITS, 16);
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_trie_mask_properties() {
        use proptest::prelude::*;

        proptest!(|(mask: TrieMask)| {
            // count_bits should match popcount of inner value
            prop_assert_eq!(mask.count_bits() as u32, mask.get().count_ones());

            // first_set_bit_index should match trailing zeros if non-empty
            if !mask.is_empty() {
                prop_assert_eq!(
                    mask.first_set_bit_index(),
                    Some(mask.get().trailing_zeros() as u8)
                );
            } else {
                prop_assert_eq!(mask.first_set_bit_index(), None);
            }

            // A mask is always a subset of itself
            prop_assert!(mask.is_subset_of(mask));

            // Empty mask is subset of any mask
            prop_assert!(TrieMask::new(0).is_subset_of(mask));
        });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_trie_mask_set_unset_roundtrip() {
        use proptest::prelude::*;

        proptest!(|(initial: u16, bit in 0u8..16)| {
            let mut mask = TrieMask::new(initial);
            mask.set_bit(bit);
            prop_assert!(mask.is_bit_set(bit));

            mask.unset_bit(bit);
            prop_assert!(!mask.is_bit_set(bit));

            // Verify other bits remain unchanged (bit is now cleared)
            let expected = initial & !(1u16 << bit);
            prop_assert_eq!(mask.get(), expected);
        });
    }

    #[test]
    fn test_trie_mask_shift_boundaries() {
        // Shift by 0 should be identity
        let mask = TrieMask::new(0b1010);
        assert_eq!((mask << 0u8).get(), 0b1010);
        assert_eq!((mask >> 0u8).get(), 0b1010);

        // Maximum meaningful shifts within 16 bits
        let mask = TrieMask::new(0b1);
        assert_eq!((mask << 15u8).get(), 0b1000_0000_0000_0000);

        let mask = TrieMask::new(0b1000_0000_0000_0000);
        assert_eq!((mask >> 15u8).get(), 0b1);
    }

    #[test]
    fn test_trie_mask_valid_nibble_range() {
        // Document that valid nibble indices are 0-15 (matching hex nibbles 0x0-0xF)
        for i in 0u8..16 {
            let mask = TrieMask::from_nibble(i);
            assert!(mask.is_bit_set(i));
            assert_eq!(mask.count_bits(), 1);
        }
    }

    #[test]
    #[should_panic]
    fn test_trie_mask_from_nibble_out_of_range_panics() {
        // Index >= 16 causes shift overflow panic in debug builds
        TrieMask::from_nibble(16);
    }

    #[test]
    #[should_panic]
    fn test_trie_mask_set_bit_out_of_range_panics() {
        let mut mask = TrieMask::new(0);
        mask.set_bit(16);
    }

    #[test]
    #[should_panic]
    fn test_trie_mask_unset_bit_out_of_range_panics() {
        let mut mask = TrieMask::new(0xFFFF);
        mask.unset_bit(16);
    }

    #[test]
    #[should_panic]
    fn test_trie_mask_is_bit_set_out_of_range_panics() {
        let mask = TrieMask::new(0);
        mask.is_bit_set(16);
    }
}
