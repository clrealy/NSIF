//! Seed-corpus generator for the `cargo-fuzz` targets in `fuzz/`.
//!
//! Run with:
//!   cargo test -p nsif-format --test corpus -- --ignored --nocapture
//!
//! Valid seeds matter: without them a fuzzer spends its whole budget failing
//! the magic check and never reaches the manifest validator.

mod common;

use std::fs;
use std::path::PathBuf;

fn corpus_dir(target: &str) -> PathBuf {
    // tests/ -> crates/nsif-format/ -> crates/ -> repo root
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    root.join("fuzz").join("corpus").join(target)
}

fn write(target: &str, name: &str, bytes: &[u8]) {
    let dir = corpus_dir(target);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
}

#[test]
#[ignore = "writes files into fuzz/corpus; run explicitly"]
fn dump_fuzz_corpus() {
    // A payload built from a small rootfs, plus the same one with a few
    // single-byte mutations in interesting places.
    let (payload, manifest, _) = common::small_payload();
    let header = &payload[..4096];
    let manifest_bytes = manifest.encode().unwrap();

    write("fuzz_header", "valid_header", header);
    write("fuzz_manifest", "valid_manifest", &manifest_bytes);
    write("fuzz_payload", "valid_payload", &payload);

    // A larger manifest, so the chunk-list paths are reachable from a seed.
    let big = common::sample_rootfs(3 * 1024 * 1024);
    let c = common::zstd();
    let (bm, _) = common::manifest_for(&big, &c);
    write("fuzz_manifest", "valid_manifest_large", &bm.encode().unwrap());

    // Minimal non-trivial CBOR shapes, to give the mutator structure to chew on.
    write("fuzz_manifest", "empty_map", &[0xA0]);
    write("fuzz_manifest", "one_entry", &[0xA1, 0x61, b'a', 0x00]);

    // A header whose regions are deliberately at the edge of legality.
    let mut h = nsif_format::PayloadHeader::parse(header).unwrap();
    h.payload_used_len = h.chunk_data_offset + h.chunk_data_len;
    write("fuzz_header", "tight_header", &h.encode());

    // Zeroed and all-ones headers: cheap boundary seeds.
    write("fuzz_header", "zeros", &[0u8; 4096]);
    let mut ones = vec![0xFFu8; 4096];
    ones[..8].copy_from_slice(&nsif_format::MAGIC);
    write("fuzz_header", "magic_then_ones", &ones);
}
