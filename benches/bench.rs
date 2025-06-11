#![allow(missing_docs)]

use alloy_trie::{HashBuilder, nodes::encode_path_leaf};
use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use nybbles::Nibbles;
use proptest::{prelude::*, strategy::ValueTree};
use std::{hint::black_box, time::Duration, collections::BTreeMap};
use alloy_primitives::{B256, keccak256};
use alloy_rlp::Encodable;

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

/// Benchmarks HashBuilder with dense sequential keys (realistic branch creation scenario)
pub fn hash_builder_dense_keys(c: &mut Criterion) {
    let counts = [100, 1000, 10000];
    
    let mut g = group(c, "hash_builder_dense");
    for count in counts {
        g.throughput(criterion::Throughput::Elements(count));
        let id = criterion::BenchmarkId::new("sequential_keys", count);
        g.bench_function(id, |b| {
            // Pre-generate data to exclude generation time from benchmark
            let data: Vec<(Vec<u8>, Vec<u8>)> = (0..count)
                .map(|i| {
                    let key = format!("key_{:08}", i).into_bytes();
                    let value = format!("value_{}", i).into_bytes();
                    (key, value)
                })
                .collect();
            
            b.iter(|| {
                let mut hb = HashBuilder::default();
                for (key, value) in &data {
                    let nibbles = Nibbles::unpack(key);
                    hb.add_leaf(nibbles, black_box(value));
                }
                black_box(hb.root())
            })
        });
    }
}

/// Benchmarks HashBuilder with sparse keys (realistic extension node scenario)
pub fn hash_builder_sparse_keys(c: &mut Criterion) {
    let counts = [100, 1000];
    
    let mut g = group(c, "hash_builder_sparse");
    for count in counts {
        g.throughput(criterion::Throughput::Elements(count));
        let id = criterion::BenchmarkId::new("sparse_keys", count);
        g.bench_function(id, |b| {
            // Generate keys with large gaps to force extension nodes
            let data: Vec<(Vec<u8>, Vec<u8>)> = (0..count)
                .map(|i| {
                    let key = format!("prefix_{:016}_suffix", i * 1000).into_bytes();
                    let value = format!("value_{}", i).into_bytes();
                    (key, value)
                })
                .collect();
            
            b.iter(|| {
                let mut hb = HashBuilder::default();
                for (key, value) in &data {
                    let nibbles = Nibbles::unpack(key);
                    hb.add_leaf(nibbles, black_box(value));
                }
                black_box(hb.root())
            })
        });
    }
}

/// Benchmarks HashBuilder with hashed keys (realistic Ethereum scenario)
pub fn hash_builder_hashed_keys(c: &mut Criterion) {
    let counts = [100, 1000, 5000];
    
    let mut g = group(c, "hash_builder_hashed");
    for count in counts {
        g.throughput(criterion::Throughput::Elements(count));
        let id = criterion::BenchmarkId::new("hashed_keys", count);
        g.bench_function(id, |b| {
            // Pre-hash keys and sort to simulate real Ethereum state trie
            let mut data: Vec<(B256, Vec<u8>)> = (0..count)
                .map(|i| {
                    let key = format!("address_{:08}", i).into_bytes();
                    let hashed_key = keccak256(&key);
                    let value = i.to_be_bytes().to_vec(); // Simulate account data
                    (hashed_key, value)
                })
                .collect();
            
            // Sort by hash (critical for HashBuilder ordering requirement)
            data.sort_by_key(|(k, _)| *k);
            
            b.iter(|| {
                let mut hb = HashBuilder::default();
                for (hashed_key, value) in &data {
                    let nibbles = Nibbles::unpack(hashed_key);
                    hb.add_leaf(nibbles, black_box(value));
                }
                black_box(hb.root())
            })
        });
    }
}

/// Benchmarks HashBuilder with mixed branch and leaf operations
pub fn hash_builder_mixed_operations(c: &mut Criterion) {
    let mut g = group(c, "hash_builder_mixed");
    g.bench_function("branch_and_leaf_mix", |b| {
        b.iter(|| {
            let mut hb = HashBuilder::default();
            
            // Add some leaves
            for i in 0..100 {
                let key = format!("leaf_{:04}", i).into_bytes();
                let nibbles = Nibbles::unpack(&key);
                hb.add_leaf(nibbles, black_box(&key));
            }
            
            // Add some branches (simulate intermediate trie state)
            for i in 0..10 {
                let key = format!("branch_{:02}", i).into_bytes();
                let nibbles = Nibbles::unpack(&key);
                let hash = keccak256(&key);
                hb.add_branch(nibbles, hash, black_box(i % 2 == 0));
            }
            
            black_box(hb.root())
        })
    });
}

/// Benchmarks individual HashBuilder operations
pub fn hash_builder_individual_ops(c: &mut Criterion) {
    let mut g = group(c, "hash_builder_ops");
    
    // Benchmark add_leaf operation
    g.bench_function("add_leaf", |b| {
        let key = b"test_key_for_leaf_benchmark";
        let value = b"test_value_for_benchmark";
        let nibbles = Nibbles::unpack(key);
        
        b.iter(|| {
            let mut hb = HashBuilder::default();
            hb.add_leaf(black_box(nibbles), black_box(value));
        })
    });
    
    // Benchmark add_branch operation
    g.bench_function("add_branch", |b| {
        let key = b"test_key_for_branch_benchmark";
        let nibbles = Nibbles::unpack(key);
        let hash = keccak256(key);
        
        b.iter(|| {
            let mut hb = HashBuilder::default();
            hb.add_branch(black_box(nibbles), black_box(hash), black_box(false));
        })
    });
    
    // Benchmark root calculation
    g.bench_function("root_calculation", |b| {
        // Pre-build a HashBuilder with some data
        let mut base_hb = HashBuilder::default();
        for i in 0..50 {
            let key = format!("key_{:03}", i).into_bytes();
            let nibbles = Nibbles::unpack(&key);
            base_hb.add_leaf(nibbles, &key);
        }
        
        b.iter(|| {
            let mut hb = base_hb.clone();
            black_box(hb.root())
        })
    });
}

criterion_group!(
    benches, 
    nibbles_path_encoding,
    hash_builder_dense_keys,
    hash_builder_sparse_keys, 
    hash_builder_hashed_keys,
    hash_builder_mixed_operations,
    hash_builder_individual_ops
);
criterion_main!(benches);
