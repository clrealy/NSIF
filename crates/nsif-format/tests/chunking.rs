//! Chunking, the codec round trip, random reads, and corruption detection.

mod common;

use nsif_format::chunker::{self, ChunkIndex};
use nsif_format::codec::{Codec, NoCodec};
use nsif_format::error::Error;
use nsif_format::payload::PayloadView;

#[test]
fn chunks_tile_the_input_exactly() {
    let data = common::sample_rootfs(700 * 1024);
    let ch = common::chunking_small();
    let bounds = chunker::boundaries(&data, &ch).unwrap();
    assert!(!bounds.is_empty());
    let mut expect = 0u64;
    for (off, len) in &bounds {
        assert_eq!(*off, expect, "chunks must be contiguous");
        assert!(*len <= ch.max, "chunk longer than max");
        expect += len;
    }
    assert_eq!(expect, data.len() as u64, "chunks must cover the input");
}

#[test]
fn chunking_is_deterministic() {
    let data = common::sample_rootfs(500 * 1024);
    let ch = common::chunking_small();
    assert_eq!(
        chunker::boundaries(&data, &ch).unwrap(),
        chunker::boundaries(&data, &ch).unwrap()
    );
}

#[test]
fn store_round_trips_through_zstd() {
    let data = common::sample_rootfs(600 * 1024);
    let c = common::zstd();
    let store = chunker::build(&data, &common::chunking_small(), &c).unwrap();
    let idx = ChunkIndex::new(&store.chunks, store.rootfs_size);
    let back = idx.read_all(&store.data, &c).unwrap();
    assert_eq!(back, data);
    assert!(store.data.len() < data.len(), "zstd should shrink this input");
}

#[test]
fn store_round_trips_through_the_none_codec() {
    let data = common::sample_rootfs(200 * 1024);
    let c = NoCodec;
    let store = chunker::build(&data, &common::chunking_small(), &c).unwrap();
    assert_eq!(store.data.len(), data.len(), "`none` must not change size");
    let idx = ChunkIndex::new(&store.chunks, store.rootfs_size);
    assert_eq!(idx.read_all(&store.data, &c).unwrap(), data);
}

/// A long run of one byte has no content-defined cut points, so every cut is
/// forced at `max` and every chunk is byte-identical. That makes this a
/// deterministic test of the dedup path itself, with no reliance on how well
/// FastCDC happens to resynchronise.
#[test]
fn identical_chunks_share_one_compressed_extent() {
    let ch = common::chunking_small();
    let data = vec![0xABu8; 10 * ch.max as usize];
    let c = common::zstd();
    let store = chunker::build(&data, &ch, &c).unwrap();

    assert_eq!(store.chunks.len(), 10, "cuts should be forced at max");
    assert_eq!(store.dedup_hits, 9, "nine chunks should reuse the first extent");
    assert!(store.dedup_saved > 0);

    // All ten chunks point at one extent.
    let first = store.chunks[0];
    for (i, c) in store.chunks.iter().enumerate() {
        assert_eq!(c.hash, first.hash, "chunk {i} hash");
        assert_eq!((c.coff, c.clen), (first.coff, first.clen), "chunk {i} extent");
    }
    // Only one chunk's worth of compressed data was actually stored.
    assert_eq!(store.data.len() as u64, first.clen);

    // Shared extents must still validate and reassemble correctly.
    let idx = ChunkIndex::new(&store.chunks, store.rootfs_size);
    assert_eq!(idx.read_all(&store.data, &c).unwrap(), data);
    let bytes = nsif_format::payload::build(
        &{
            let (m, _) = common::manifest_for(&data, &c);
            m
        },
        &store.data,
        &common::SECRET,
    )
    .expect("a manifest with shared extents must validate");
    assert!(!bytes.is_empty());
}

/// Content-defined chunking is supposed to resynchronise after an insertion, so
/// a duplicated region should mostly deduplicate even though the seam shifts
/// every absolute offset. This is a statistical property of FastCDC, not an
/// exact one, so the bound is deliberately loose.
#[test]
fn chunking_resynchronises_across_a_seam() {
    let half = incompressible(2 * 1024 * 1024);
    let mut data = half.clone();
    data.extend_from_slice(&half);
    let c = NoCodec;
    let store = chunker::build(&data, &common::chunking_small(), &c).unwrap();
    let ratio = store.dedup_hits as f64 / store.chunks.len() as f64;
    assert!(
        ratio > 0.30,
        "only {:.1}% of {} chunks deduplicated; FastCDC should resynchronise far better than that",
        ratio * 100.0,
        store.chunks.len()
    );
    let idx = ChunkIndex::new(&store.chunks, store.rootfs_size);
    assert_eq!(idx.read_all(&store.data, &c).unwrap(), data);
}

/// Deterministic pseudo-random bytes: no runs, so cut points are genuinely
/// content-defined and zstd cannot compress them.
fn incompressible(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut s: u64 = 0xDEAD_BEEF_CAFE_F00D;
    while v.len() < len {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        v.extend_from_slice(&s.to_le_bytes());
    }
    v.truncate(len);
    v
}

#[test]
fn random_reads_match_the_source() {
    let data = common::sample_rootfs(400 * 1024);
    let c = common::zstd();
    let store = chunker::build(&data, &common::chunking_small(), &c).unwrap();
    let idx = ChunkIndex::new(&store.chunks, store.rootfs_size);

    // A deterministic spread of ranges, including chunk-boundary straddles.
    let mut state: u64 = 12345;
    for _ in 0..200 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let off = (state >> 33) % data.len() as u64;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let max = (data.len() as u64 - off).min(200 * 1024);
        let len = if max == 0 { 0 } else { (state >> 33) % max + 1 };
        let got = idx.read_range(&store.data, &c, off, len).unwrap();
        assert_eq!(
            got,
            &data[off as usize..(off + len) as usize],
            "mismatch at {off}..{}",
            off + len
        );
    }
}

#[test]
fn reads_past_the_end_are_refused() {
    let data = common::sample_rootfs(100 * 1024);
    let c = common::zstd();
    let store = chunker::build(&data, &common::chunking_small(), &c).unwrap();
    let idx = ChunkIndex::new(&store.chunks, store.rootfs_size);
    assert!(idx.read_range(&store.data, &c, store.rootfs_size, 1).is_err());
    assert!(idx.read_range(&store.data, &c, 0, store.rootfs_size + 1).is_err());
    assert!(idx.read_range(&store.data, &c, u64::MAX - 1, 4).is_err());
}

/// SPEC §13.3: a flipped byte in the chunk data must produce an error, never
/// wrong data.
#[test]
fn a_flipped_byte_in_a_chunk_is_an_error_not_bad_data() {
    let data = common::sample_rootfs(300 * 1024);
    let c = common::zstd();
    let mut store = chunker::build(&data, &common::chunking_small(), &c).unwrap();

    // Flip a byte inside the last chunk's compressed extent, so earlier chunks
    // stay readable and only this one fails.
    let last = store.chunks.len() - 1;
    let target = store.chunks[last];
    let pos = (target.coff + target.clen - 1) as usize;
    store.data[pos] ^= 0xFF;

    let idx = ChunkIndex::new(&store.chunks, store.rootfs_size);
    let mut buf = vec![0u8; target.ulen as usize];
    let e = idx.read_chunk(last, &store.data, &c, &mut buf).unwrap_err();
    // Either the codec rejects the frame or the hash check catches it. Both are
    // errors; neither returns the corrupted bytes.
    assert!(
        matches!(
            e,
            Error::ChunkHashMismatch { .. }
                | Error::CodecFailure { .. }
                | Error::CodecLengthMismatch { .. }
        ),
        "wrong variant: {e}"
    );

    // Reading the whole image must fail too.
    assert!(idx.read_all(&store.data, &c).is_err());
    // An earlier chunk is unaffected.
    let mut buf0 = vec![0u8; store.chunks[0].ulen as usize];
    idx.read_chunk(0, &store.data, &c, &mut buf0).unwrap();
}

/// With the `none` codec the hash check is the only line of defence, so this
/// isolates it from the codec's own frame checking.
#[test]
fn hash_check_catches_corruption_with_no_codec_help() {
    let data = common::sample_rootfs(200 * 1024);
    let c = NoCodec;
    let mut store = chunker::build(&data, &common::chunking_small(), &c).unwrap();
    store.data[1000] ^= 0x01;
    let idx = ChunkIndex::new(&store.chunks, store.rootfs_size);
    let mut buf = vec![0u8; store.chunks[0].ulen as usize];
    let e = idx.read_chunk(0, &store.data, &c, &mut buf).unwrap_err();
    assert!(matches!(e, Error::ChunkHashMismatch { index: 0, .. }), "{e}");
}

#[test]
fn full_payload_verifies_end_to_end() {
    let (bytes, m, _) = common::small_payload();
    let v = PayloadView::open(&bytes, bytes.len() as u64).unwrap();
    assert_eq!(v.manifest, m);
    let codec = v.codec().unwrap();
    v.verify_chunks(codec.as_ref()).expect("all chunks verify");
    v.verify_signature(&common::public_key()).expect("signature verifies");
}

#[test]
fn payload_verify_catches_a_flipped_chunk_byte() {
    let (mut bytes, _, _) = common::small_payload();
    let cdo = PayloadView::open(&bytes, bytes.len() as u64)
        .unwrap()
        .header
        .chunk_data_offset as usize;
    bytes[cdo + 5] ^= 0xFF;
    let v = PayloadView::open(&bytes, bytes.len() as u64).unwrap();
    let codec = v.codec().unwrap();
    assert!(v.verify_chunks(codec.as_ref()).is_err());
    // The manifest and signature are untouched, so those still pass: the chunk
    // check is what must catch this.
    v.verify_signature(&common::public_key()).unwrap();
}

#[test]
fn chunk_index_find_is_correct_at_boundaries() {
    let data = common::sample_rootfs(300 * 1024);
    let c = NoCodec;
    let store = chunker::build(&data, &common::chunking_small(), &c).unwrap();
    let idx = ChunkIndex::new(&store.chunks, store.rootfs_size);
    for (i, ch) in store.chunks.iter().enumerate() {
        assert_eq!(idx.find(ch.uoff), Some(i), "start of chunk {i}");
        assert_eq!(idx.find(ch.uoff + ch.ulen - 1), Some(i), "end of chunk {i}");
    }
    assert_eq!(idx.find(store.rootfs_size), None);
}

#[test]
fn empty_input_produces_no_chunks() {
    let bounds = chunker::boundaries(&[], &common::chunking_small()).unwrap();
    assert!(bounds.is_empty());
}

#[test]
fn max_expansion_is_the_extra_beyond_the_input() {
    // SPEC §10.2: total bound is n + (n >> 8) + 64.
    let z = common::zstd();
    assert_eq!(z.max_expansion(0), 64);
    assert_eq!(z.max_expansion(65536), 256 + 64);
    assert_eq!(NoCodec.max_expansion(1 << 20), 0);
}

/// Incompressible data must still fit inside the declared bound, which is what
/// SPEC §5.3.8 relies on.
#[test]
fn incompressible_chunks_stay_within_the_expansion_bound() {
    let data = incompressible(512 * 1024);
    let c = common::zstd();
    let store = chunker::build(&data, &common::chunking_small(), &c).unwrap();
    for (i, ch) in store.chunks.iter().enumerate() {
        let bound = ch.ulen + c.max_expansion(ch.ulen);
        assert!(
            ch.clen <= bound,
            "chunk {i}: clen {} exceeds bound {bound} for ulen {}",
            ch.clen,
            ch.ulen
        );
    }
    let idx = ChunkIndex::new(&store.chunks, store.rootfs_size);
    assert_eq!(idx.read_all(&store.data, &c).unwrap(), data);
}
