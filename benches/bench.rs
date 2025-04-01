#![allow(missing_docs)]

use alloy_trie::{nodes::encode_path_leaf, HashBuilder};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, Criterion,
};
use alloy_primitives::hex;
use nybbles::Nibbles;
use proptest::{prelude::*, strategy::ValueTree};
use std::{hint::black_box, time::Duration};

/// Benchmarks the nibble path encoding.
pub fn nibbles_path_encoding(c: &mut Criterion) {
    let lengths = [16u64, 32, 256, 2048];

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

fn group<'c>(c: &'c mut Criterion, name: &str) -> BenchmarkGroup<'c, WallTime> {
    let mut g = c.benchmark_group(name);
    g.warm_up_time(Duration::from_secs(1));
    g.noise_threshold(0.02);
    g
}

pub fn bench_add_leaf(c: &mut Criterion) {
    let raw_input = vec![
        (hex!("646f").to_vec(), hex!("76657262").to_vec()),
        (hex!("676f6f64").to_vec(), hex!("7075707079").to_vec()),
    ];

    c.bench_function("hash_builder_leaves", |b| {
        b.iter(|| {
            let mut hb = HashBuilder::default();
            for (key, val) in &raw_input {
                hb.add_leaf(Nibbles::unpack(key), val.as_slice());
            }
            black_box(hb.root())
        })
    });
}

fn get_nibbles(len: usize) -> Nibbles {
    proptest::arbitrary::any_with::<Nibbles>(len.into())
        .new_tree(&mut Default::default())
        .unwrap()
        .current()
}

criterion_group!(benches, bench_add_leaf);
criterion_main!(benches);
