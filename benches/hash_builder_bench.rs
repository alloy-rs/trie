#![allow(missing_docs)]

use alloy_primitives::{B256, keccak256};
use alloy_trie::{
    HashBuilder, Nibbles, TrieMask,
    nodes::{BranchNodeRef, RlpNode},
    proof::ProofRetainer,
};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use proptest::{prelude::*, strategy::ValueTree, test_runner::TestRunner};
use std::collections::BTreeMap;

/// Generate random key-value pairs for trie benchmarks
fn generate_leaves(count: usize) -> BTreeMap<B256, Vec<u8>> {
    let mut runner = TestRunner::default();
    let mut leaves = BTreeMap::new();

    for _ in 0..count {
        let key = any::<B256>().new_tree(&mut runner).unwrap().current();
        let value = any::<[u8; 32]>().new_tree(&mut runner).unwrap().current().to_vec();
        leaves.insert(keccak256(key), value);
    }
    leaves
}

/// Benchmark HashBuilder with varying number of leaves
fn hash_builder_leaves(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_builder");

    for count in [100, 500, 1000, 5000, 10000] {
        let leaves = generate_leaves(count);

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::new("leaves", count), &leaves, |b, leaves| {
            b.iter(|| {
                let mut hb = HashBuilder::default();
                for (key, value) in leaves {
                    hb.add_leaf(Nibbles::unpack(key), value);
                }
                black_box(hb.root())
            });
        });
    }
    group.finish();
}

/// Benchmark HashBuilder with updates enabled
fn hash_builder_with_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_builder_updates");

    for count in [100, 500, 1000] {
        let leaves = generate_leaves(count);

        group.throughput(Throughput::Elements(count as u64));

        // Without updates
        group.bench_with_input(BenchmarkId::new("without_updates", count), &leaves, |b, leaves| {
            b.iter(|| {
                let mut hb = HashBuilder::default();
                for (key, value) in leaves {
                    hb.add_leaf(Nibbles::unpack(key), value);
                }
                black_box(hb.root())
            });
        });

        // With updates
        group.bench_with_input(BenchmarkId::new("with_updates", count), &leaves, |b, leaves| {
            b.iter(|| {
                let mut hb = HashBuilder::default().with_updates(true);
                for (key, value) in leaves {
                    hb.add_leaf(Nibbles::unpack(key), value);
                }
                let root = hb.root();
                let (_, updates) = hb.split();
                black_box((root, updates))
            });
        });
    }
    group.finish();
}

/// Benchmark HashBuilder with proof retainer
fn hash_builder_with_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_builder_proofs");

    for count in [100, 500, 1000] {
        let leaves = generate_leaves(count);
        let targets: Vec<Nibbles> = leaves
            .keys()
            .take(count / 10) // 10% of keys as targets
            .map(|k| Nibbles::unpack(k))
            .collect();

        group.throughput(Throughput::Elements(count as u64));

        group.bench_with_input(
            BenchmarkId::new("with_proofs", count),
            &(leaves.clone(), targets.clone()),
            |b, (leaves, targets)| {
                b.iter(|| {
                    let retainer = ProofRetainer::from_iter(targets.clone());
                    let mut hb = HashBuilder::default().with_proof_retainer(retainer);
                    for (key, value) in leaves {
                        hb.add_leaf(Nibbles::unpack(key), value);
                    }
                    let root = hb.root();
                    let proofs = hb.take_proof_nodes();
                    black_box((root, proofs))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark ProofRetainer matching
fn proof_retainer_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_retainer_match");

    for target_count in [10, 50, 100, 500] {
        let mut runner = TestRunner::default();
        let targets: Vec<Nibbles> = (0..target_count)
            .map(|_| {
                let key = any::<B256>().new_tree(&mut runner).unwrap().current();
                Nibbles::unpack(keccak256(key))
            })
            .collect();

        let retainer = ProofRetainer::from_iter(targets.clone());

        // Test matching prefix (first target's prefix)
        let matching_prefix = targets[0].slice(..4);
        group.bench_with_input(
            BenchmarkId::new("match", target_count),
            &(retainer.clone(), matching_prefix),
            |b, (retainer, prefix)| {
                b.iter(|| black_box(retainer.matches(prefix)));
            },
        );

        // Test non-matching prefix (0xFF... which won't match random targets)
        let non_matching_prefix = Nibbles::from_nibbles([0xF, 0xF, 0xF, 0xF]);
        group.bench_with_input(
            BenchmarkId::new("no_match", target_count),
            &(retainer, non_matching_prefix),
            |b, (retainer, prefix)| {
                b.iter(|| black_box(retainer.matches(prefix)));
            },
        );
    }
    group.finish();
}

/// Benchmark mask resize operations (simulates update loop behavior)
fn mask_resize(c: &mut Criterion) {
    let mut group = c.benchmark_group("mask_resize");

    for depth in [16, 32, 64] {
        // Benchmark three separate vectors (old approach)
        group.bench_with_input(BenchmarkId::new("three_vecs", depth), &depth, |b, &depth| {
            b.iter(|| {
                let mut state_masks: Vec<TrieMask> = Vec::new();
                let mut tree_masks: Vec<TrieMask> = Vec::new();
                let mut hash_masks: Vec<TrieMask> = Vec::new();

                for new_len in 1..=depth {
                    state_masks.resize(new_len, TrieMask::default());
                    tree_masks.resize(new_len, TrieMask::default());
                    hash_masks.resize(new_len, TrieMask::default());
                }
                black_box((state_masks.len(), tree_masks.len(), hash_masks.len()))
            });
        });

        // Benchmark consolidated approach (new TrieMasks struct)
        // state_masks kept separate (different lifecycle), tree+hash consolidated
        group.bench_with_input(BenchmarkId::new("consolidated", depth), &depth, |b, &depth| {
            b.iter(|| {
                let mut state_masks: Vec<TrieMask> = Vec::new();
                let mut masks: Vec<alloy_trie::TrieMasks> = Vec::new();

                for new_len in 1..=depth {
                    state_masks.resize(new_len, TrieMask::default());
                    masks.resize(new_len, alloy_trie::TrieMasks::default());
                }
                black_box((state_masks.len(), masks.len()))
            });
        });
    }
    group.finish();
}

/// Benchmark branch node encoding
fn branch_node_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("branch_node");

    // Create a branch node with various child counts
    for child_count in [2, 4, 8, 16] {
        let mut stack: Vec<RlpNode> = Vec::new();
        let mut state_mask = TrieMask::default();

        for i in 0..child_count {
            let hash = B256::repeat_byte(i);
            stack.push(RlpNode::word_rlp(&hash));
            state_mask.set_bit(i);
        }

        let branch = BranchNodeRef::new(&stack, state_mask);

        group.bench_with_input(BenchmarkId::new("encode", child_count), &branch, |b, branch| {
            let mut buf = Vec::with_capacity(600);
            b.iter(|| {
                buf.clear();
                black_box(branch.rlp(&mut buf))
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    hash_builder_leaves,
    hash_builder_with_updates,
    hash_builder_with_proofs,
    proof_retainer_match,
    mask_resize,
    branch_node_encode,
);
criterion_main!(benches);
