#![allow(missing_docs)]

use alloy_primitives::{B256, Bytes, U256};
use alloy_rlp::{Decodable, Encodable, Header};
#[cfg(feature = "ethereum")]
use alloy_trie::TrieAccount;
use alloy_trie::{
    HashBuilder, TrieMask,
    nodes::{BranchNode, ExtensionNode, LeafNode, RlpNode, TrieNode, encode_path_leaf},
    proof::{ProofRetainer, verify_proof},
    root::{ordered_trie_root, ordered_trie_root_encoded},
};
use criterion::{
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
    measurement::WallTime,
};
use nybbles::Nibbles;
use proptest::{prelude::*, strategy::ValueTree};
use std::{hint::black_box, time::Duration};

const SEED: u64 = 0x616c_6c6f_792d_7472;
const TRIE_SIZES: [usize; 3] = [100, 1_000, 10_000];
const RETAINED_TARGETS: usize = 16;

/// Benchmarks the nibble path encoding.
pub fn nibbles_path_encoding(c: &mut Criterion) {
    let lengths = [8u64, 16, 32, 64];

    let mut g = group(c, "encode_path_leaf");
    for len in lengths {
        g.throughput(Throughput::Bytes(len));
        let id = BenchmarkId::new("trie", len);
        g.bench_function(id, |b| {
            let nibbles = &get_nibbles(len as usize);
            b.iter(|| encode_path_leaf(black_box(nibbles), false))
        });
    }
}

/// Benchmarks computing the root of a sorted trie with [`HashBuilder`].
pub fn hash_builder_root(c: &mut Criterion) {
    let mut g = group(c, "hash_builder_root");
    for (kind, value) in [("account", account_value as ValueFn), ("storage", storage_value)] {
        for size in TRIE_SIZES {
            let leaves = sorted_leaves(size, value);
            g.throughput(Throughput::Elements(size as u64));
            g.bench_function(BenchmarkId::new(kind, size), |b| {
                b.iter(|| {
                    let mut hb = HashBuilder::default();
                    for (key, value) in &leaves {
                        hb.add_leaf(*key, value);
                    }
                    black_box(hb.root())
                })
            });
        }
    }
}

/// Benchmarks computing the root while retaining proofs for a subset of the leaves.
pub fn hash_builder_root_with_proofs(c: &mut Criterion) {
    let mut g = group(c, "hash_builder_root_with_proofs");
    for size in TRIE_SIZES {
        let leaves = sorted_leaves(size, account_value);
        let step = size / RETAINED_TARGETS;
        let targets = leaves.iter().step_by(step).map(|(key, _)| *key).collect::<Vec<_>>();
        g.throughput(Throughput::Elements(size as u64));
        g.bench_function(BenchmarkId::new("account", size), |b| {
            b.iter(|| {
                let retainer = ProofRetainer::new(targets.clone());
                let mut hb = HashBuilder::default().with_proof_retainer(retainer);
                for (key, value) in &leaves {
                    hb.add_leaf(*key, value);
                }
                let root = hb.root();
                black_box((root, hb.take_proof_nodes()))
            })
        });
    }
}

/// Benchmarks the root of tries keyed by the RLP-encoded transaction or receipt index.
pub fn ordered_root(c: &mut Criterion) {
    let mut g = group(c, "ordered_trie_root");
    let mut rng = Rng(SEED);
    for size in [10usize, 100, 1_000] {
        let items = (0..size)
            .map(|_| {
                let len = 100 + (rng.next() % 200) as usize;
                rng.bytes(len)
            })
            .collect::<Vec<_>>();
        g.throughput(Throughput::Elements(size as u64));
        g.bench_function(BenchmarkId::new("encodable", size), |b| {
            b.iter(|| ordered_trie_root(black_box(&items)))
        });
        g.bench_function(BenchmarkId::new("encoded", size), |b| {
            b.iter(|| ordered_trie_root_encoded(black_box(&items)))
        });
    }
}

/// Benchmarks RLP encoding and decoding of the [`TrieNode`] variants.
pub fn trie_node_rlp(c: &mut Criterion) {
    let mut rng = Rng(SEED);
    let nodes = [
        ("branch_full", TrieNode::Branch(branch_node(&mut rng, 16))),
        ("branch_sparse", TrieNode::Branch(branch_node(&mut rng, 3))),
        (
            "extension",
            TrieNode::Extension(ExtensionNode::new(rng.nibbles(5), RlpNode::word_rlp(&rng.b256()))),
        ),
        ("leaf_account", TrieNode::Leaf(LeafNode::new(rng.nibbles(60), account_value(&mut rng)))),
        ("leaf_storage", TrieNode::Leaf(LeafNode::new(rng.nibbles(60), storage_value(&mut rng)))),
    ];

    let mut g = group(c, "trie_node_rlp");
    for (name, node) in &nodes {
        let encoded = alloy_rlp::encode(node);
        g.throughput(Throughput::Bytes(encoded.len() as u64));
        g.bench_function(BenchmarkId::new("encode", name), |b| {
            let mut buf = Vec::with_capacity(encoded.len());
            b.iter(|| {
                buf.clear();
                black_box(node).encode(&mut buf);
                black_box(&buf);
            })
        });
        g.bench_function(BenchmarkId::new("decode", name), |b| {
            b.iter(|| TrieNode::decode(&mut black_box(encoded.as_slice())).unwrap())
        });
    }
}

/// Benchmarks verifying inclusion and exclusion proofs.
pub fn verify_proof_bench(c: &mut Criterion) {
    let leaves = sorted_leaves(1_000, account_value);
    let (present_key, present_value) = leaves[leaves.len() / 3].clone();
    let absent_key = Nibbles::unpack(Rng(SEED ^ 1).b256());
    let retainer = ProofRetainer::new(vec![present_key, absent_key]);
    let mut hb = HashBuilder::default().with_proof_retainer(retainer);
    for (key, value) in &leaves {
        hb.add_leaf(*key, value);
    }
    let root = hb.root();
    let proof_nodes = hb.take_proof_nodes();
    let proof = |key: &Nibbles| -> Vec<Bytes> {
        proof_nodes.matching_nodes_sorted(key).into_iter().map(|(_, node)| node).collect()
    };
    let present_proof = proof(&present_key);
    let absent_proof = proof(&absent_key);
    assert_eq!(
        verify_proof(root, present_key, Some(present_value.clone()), &present_proof),
        Ok(())
    );
    assert_eq!(verify_proof(root, absent_key, None, &absent_proof), Ok(()));

    let mut g = group(c, "verify_proof");
    g.bench_function("inclusion", |b| {
        b.iter_batched(
            || Some(present_value.clone()),
            |value| verify_proof(root, present_key, value, black_box(&present_proof)).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("exclusion", |b| {
        b.iter(|| verify_proof(root, absent_key, None, black_box(&absent_proof)).unwrap())
    });
}

/// Benchmarks RLP encoding of [`TrieAccount`]s, as done for every account leaf of a state root.
#[cfg(feature = "ethereum")]
pub fn trie_account_encode(c: &mut Criterion) {
    let mut rng = Rng(SEED);
    let accounts = (0..1_000)
        .map(|_| TrieAccount::new(rng.next() % 1_000_000, rng.u256(16), rng.b256(), rng.b256()))
        .collect::<Vec<_>>();
    let len = accounts.iter().map(Encodable::length).sum::<usize>();

    let mut g = group(c, "trie_account");
    g.throughput(Throughput::Elements(accounts.len() as u64));
    g.bench_function("encode", |b| {
        let mut buf = Vec::with_capacity(len);
        b.iter(|| {
            buf.clear();
            for account in black_box(&accounts) {
                account.encode(&mut buf);
            }
            black_box(&buf);
        })
    });
}

/// Benchmarks RLP encoding of [`TrieAccount`]s; requires the `ethereum` feature.
#[cfg(not(feature = "ethereum"))]
pub fn trie_account_encode(_: &mut Criterion) {}

type ValueFn = fn(&mut Rng) -> Vec<u8>;

/// Deterministic SplitMix64 generator.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn nibbles(&mut self, len: usize) -> Nibbles {
        Nibbles::from_nibbles_unchecked(
            (0..len).map(|_| (self.next() % 16) as u8).collect::<Vec<_>>(),
        )
    }

    fn u256(&mut self, max_bytes: u64) -> U256 {
        let len = 1 + (self.next() % max_bytes) as usize;
        U256::from_be_slice(&self.bytes(len))
    }

    fn b256(&mut self) -> B256 {
        B256::from_slice(&self.bytes(32))
    }
}

/// RLP-encoded account, as stored in the state trie.
fn account_value(rng: &mut Rng) -> Vec<u8> {
    let mut payload = Vec::new();
    (rng.next() % 1_000_000).encode(&mut payload);
    rng.u256(16).encode(&mut payload);
    rng.b256().encode(&mut payload);
    rng.b256().encode(&mut payload);
    let mut out = Vec::new();
    Header { list: true, payload_length: payload.len() }.encode(&mut out);
    out.extend(payload);
    out
}

/// RLP-encoded slot value, as stored in a storage trie.
fn storage_value(rng: &mut Rng) -> Vec<u8> {
    alloy_rlp::encode(rng.u256(32))
}

/// Unique random 32-byte keys with their values, sorted by key.
fn sorted_leaves(size: usize, value: ValueFn) -> Vec<(Nibbles, Vec<u8>)> {
    let mut rng = Rng(SEED);
    let mut keys = (0..size).map(|_| rng.b256()).collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    keys.into_iter().map(|key| (Nibbles::unpack(key), value(&mut rng))).collect()
}

fn branch_node(rng: &mut Rng, children: usize) -> BranchNode {
    let mut state_mask = TrieMask::default();
    let mut stack = Vec::new();
    let step = 16 / children;
    for nibble in (0..16).step_by(step).take(children) {
        state_mask.set_bit(nibble as u8);
        stack.push(RlpNode::word_rlp(&rng.b256()));
    }
    BranchNode::new(stack, state_mask)
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

criterion_group!(
    benches,
    nibbles_path_encoding,
    hash_builder_root,
    hash_builder_root_with_proofs,
    ordered_root,
    trie_node_rlp,
    trie_account_encode,
    verify_proof_bench
);
criterion_main!(benches);
