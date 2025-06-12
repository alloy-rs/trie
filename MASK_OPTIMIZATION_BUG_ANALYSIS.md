# Mask Optimization Bug Analysis

## Summary

The packed masks optimization (combining `state_masks`, `tree_masks`, and `hash_masks` into a single `Vec<MaskSet>`) causes incorrect trie root calculation because it forces all three mask types to have the same length, whereas the original algorithm relies on them having different lengths at different times.

## Root Cause

In the original implementation:
- `state_masks`: Resized independently using `self.state_masks.resize()`
- `tree_masks` and `hash_masks`: Resized together using `self.resize_masks()`

The algorithm specifically relies on this behavior:

1. `state_masks` is resized at lines 229 and 322 to track which children exist at each trie level
2. `tree_masks` and `hash_masks` are resized together at lines 240, 306, and 323 to track database storage and hash representation

## Example of the Issue

In the `update()` method:
- Line 229: `self.state_masks.resize(new_len, TrieMask::default())` - state_masks grows to len+1
- Line 240: `self.resize_masks(current.len())` - tree/hash masks grow to current.len()
- At this point, state_masks.len() could be different from tree_masks.len()

When combined into `MaskSet`, we lose this ability to have different lengths, breaking the algorithm.

## Why This Matters

The different lengths are used to track different aspects of the trie construction:
- `state_masks` tracks the logical structure being built
- `tree_masks` and `hash_masks` track the physical representation

These can diverge during construction, especially when building extension nodes and branch nodes.

## Solutions

1. **Keep masks separate**: Revert to the original structure with three separate `Vec<TrieMask>` fields
2. **Redesign algorithm**: Fundamentally change how masks are managed to work with unified lengths (complex, risky)
3. **Hybrid approach**: Keep state_masks separate but pack tree/hash masks together (partial optimization)

## Recommendation

Revert the mask packing optimization. The algorithm's correctness depends on the ability to resize these mask vectors independently. While packing them together might improve cache locality, it fundamentally breaks the algorithm's invariants.