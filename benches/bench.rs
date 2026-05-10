#![allow(missing_docs)]

use alloy_primitives::{B256, keccak256};
use alloy_trie::{HashBuilder, nodes::encode_path_leaf};
use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use nybbles::Nibbles;
use proptest::{prelude::*, strategy::ValueTree};
use std::{collections::BTreeMap, hint::black_box, time::Duration};

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

/// Benchmarks the HashBuilder with various numbers of leaves.
pub fn hash_builder_benchmark(c: &mut Criterion) {
    let counts = [100u64, 1000, 10000];

    let mut g = group(c, "hash_builder");
    for count in counts {
        // Generate sorted key-value pairs
        let data: BTreeMap<B256, Vec<u8>> = (0..count)
            .map(|i| {
                let key = keccak256(i.to_be_bytes());
                let value = alloy_rlp::encode(i);
                (key, value)
            })
            .collect();

        g.throughput(criterion::Throughput::Elements(count));
        let id = criterion::BenchmarkId::new("leaves", count);
        g.bench_function(id, |b| {
            b.iter(|| {
                let mut hb = HashBuilder::default();
                for (key, value) in &data {
                    let nibbles = Nibbles::unpack(key);
                    hb.add_leaf(nibbles, value);
                }
                black_box(hb.root())
            })
        });
    }
}

/// Benchmarks the HashBuilder with updates enabled.
pub fn hash_builder_with_updates(c: &mut Criterion) {
    let counts = [100u64, 1000, 10000];

    let mut g = group(c, "hash_builder_updates");
    for count in counts {
        let data: BTreeMap<B256, Vec<u8>> = (0..count)
            .map(|i| {
                let key = keccak256(i.to_be_bytes());
                let value = alloy_rlp::encode(i);
                (key, value)
            })
            .collect();

        g.throughput(criterion::Throughput::Elements(count));
        let id = criterion::BenchmarkId::new("leaves", count);
        g.bench_function(id, |b| {
            b.iter(|| {
                let mut hb = HashBuilder::default().with_updates(true);
                for (key, value) in &data {
                    let nibbles = Nibbles::unpack(key);
                    hb.add_leaf(nibbles, value);
                }
                let root = hb.root();
                let (_, updates) = hb.split();
                black_box((root, updates))
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

criterion_group!(benches, nibbles_path_encoding, hash_builder_benchmark, hash_builder_with_updates);
criterion_main!(benches);
