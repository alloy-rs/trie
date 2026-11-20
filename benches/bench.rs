#![allow(missing_docs)]

use alloy_primitives::keccak256;
use alloy_trie::{
    HashBuilder,
    nodes::encode_path_leaf,
    proof::{DecodedProofNodes, ProofRetainer},
};
use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use nybbles::Nibbles;
use proptest::{prelude::*, strategy::ValueTree};
use std::{hint::black_box, time::Duration};

/// Benchmarks the nibble path encoding.
pub fn nibbles_path_encoding(c: &mut Criterion) {
    let lengths = [8u64, 16, 32, 64];

    let mut g = group(c, "encode_path_leaf");
    for len in lengths {
        g.throughput(criterion::Throughput::Bytes(len));
        let id = criterion::BenchmarkId::new("trie", len);
        g.bench_function(id, |b| {
            let nibbles = &get_nibbles(len as usize);
            b.iter(|| encode_path_leaf(black_box(nibbles), false))
        });
    }
}

/// Benchmarks looking up every target's proof nodes in a multiproof.
pub fn proof_matching_nodes(c: &mut Criterion) {
    let mut keys =
        (0u64..10_000).map(|i| Nibbles::unpack(keccak256(i.to_be_bytes()))).collect::<Vec<_>>();
    keys.sort_unstable();

    let mut g = group(c, "proof_matching_nodes");
    for targets in [1usize, 10, 100, 1000] {
        let targets = keys.iter().step_by(keys.len() / targets).copied().collect::<Vec<_>>();
        let mut hash_builder =
            HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets.clone()));
        for key in &keys {
            hash_builder.add_leaf(*key, &[0x01; 32]);
        }
        hash_builder.root();
        let proof_nodes = hash_builder.take_proof_nodes();
        let decoded = DecodedProofNodes::try_from(proof_nodes.clone()).unwrap();

        let id = criterion::BenchmarkId::new("encoded", targets.len());
        g.bench_function(id, |b| {
            b.iter(|| {
                for target in &targets {
                    black_box(proof_nodes.matching_nodes_sorted(black_box(target)));
                }
            })
        });
        let id = criterion::BenchmarkId::new("decoded", targets.len());
        g.bench_function(id, |b| {
            b.iter(|| {
                for target in &targets {
                    black_box(decoded.matching_nodes_sorted(black_box(target)));
                }
            })
        });
    }
}

fn group<'c>(c: &'c mut Criterion, name: &str) -> BenchmarkGroup<'c, WallTime> {
    let mut g = c.benchmark_group(name);
    g.warm_up_time(Duration::from_secs(1));
    g.noise_threshold(0.02);
    g
}

fn get_nibbles(len: usize) -> Nibbles {
    proptest::arbitrary::any_with::<Nibbles>(len.into())
        .new_tree(&mut Default::default())
        .unwrap()
        .current()
}

criterion_group!(benches, nibbles_path_encoding, proof_matching_nodes);
criterion_main!(benches);
