//! Shared fixtures. Everything here is deterministic: no clocks, no RNG.

#![allow(dead_code)]

use std::collections::BTreeMap;

use nsif_format::chunker::{self, ChunkStore};
use nsif_format::codec::{Codec, NoCodec, ParamValue, Zstd};
use nsif_format::manifest::{Chunking, EspFile, Manifest};

/// A fixed signing seed. Test-only; never used for anything real.
pub const SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// A different fixed seed, for "wrong key" tests.
pub const OTHER_SECRET: [u8; 32] = [7u8; 32];

pub fn public_key() -> [u8; 32] {
    nsif_format::sig::public_key_from_secret(&SECRET)
}

pub fn other_public_key() -> [u8; 32] {
    nsif_format::sig::public_key_from_secret(&OTHER_SECRET)
}

/// Deterministic, realistically compressible test data: a mix of long runs,
/// repeated blocks and pseudo-random bytes, so FastCDC produces a sensible
/// number of chunks and zstd has something to do.
pub fn sample_rootfs(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u64 = 0x243F_6A88_85A3_08D3;
    let mut block = 0u64;
    while out.len() < len {
        // Cycle through three textures so chunk boundaries are not uniform.
        match block % 3 {
            0 => {
                // pseudo-random
                for _ in 0..4096 {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    out.push((state >> 33) as u8);
                    if out.len() == len {
                        return out;
                    }
                }
            }
            1 => {
                // highly compressible run
                let b = (block % 251) as u8;
                for _ in 0..8192 {
                    out.push(b);
                    if out.len() == len {
                        return out;
                    }
                }
            }
            _ => {
                // repeated structure, to give dedup something to find
                let pat: [u8; 16] = *b"NSIF-TEST-BLOCK\n";
                for i in 0..6000 {
                    out.push(pat[i % pat.len()]);
                    if out.len() == len {
                        return out;
                    }
                }
            }
        }
        block += 1;
    }
    out.truncate(len);
    out
}

pub fn zstd() -> Zstd {
    // Level 3 keeps the tests fast; level is recorded in the manifest either way.
    Zstd::new(3).unwrap()
}

pub fn none() -> NoCodec {
    NoCodec
}

pub fn chunking_small() -> Chunking {
    // Small parameters so test inputs of a few hundred KiB still produce many
    // chunks. Still within SPEC §5.3.5 (min >= 16 KiB).
    Chunking { min: 16 * 1024, avg: 32 * 1024, max: 64 * 1024, algo_fastcdc: true, seed: 0, normalization: 2 }
}

pub fn esp_files() -> Vec<EspFile> {
    vec![
        EspFile {
            path: "/EFI/BOOT/BOOTX64.EFI".into(),
            size: 123,
            hash: *blake3::hash(b"bootloader").as_bytes(),
        },
        EspFile {
            path: "/EFI/nsif/vmlinuz".into(),
            size: 456,
            hash: *blake3::hash(b"kernel").as_bytes(),
        },
        EspFile {
            path: "/loader/entries/nsif.conf".into(),
            size: 78,
            hash: *blake3::hash(b"entry").as_bytes(),
        },
    ]
}

pub fn metadata() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("nsif.codename".into(), "Hammer".into());
    m.insert("nsif.packer".into(), "nsif 0.1.0".into());
    m.insert("zstd.version".into(), "1.5.7".into());
    m
}

/// Build a valid manifest over `data` with the given codec.
pub fn manifest_for(data: &[u8], codec: &dyn Codec) -> (Manifest, ChunkStore) {
    let ch = chunking_small();
    let store = chunker::build(data, &ch, codec).expect("chunking");
    let mut params = BTreeMap::new();
    for (k, v) in codec.params() {
        params.insert(k, v);
    }
    let m = Manifest {
        arch: "x86_64".into(),
        name: "NSIF Test".into(),
        codec: codec.id().into(),
        chunks: store.chunks.clone(),
        cmdline: "rd.nsif.cache=192M quiet".into(),
        version: 1,
        chunking: ch,
        metadata: metadata(),
        esp_files: esp_files(),
        build_date: 1_762_646_400, // 2025-11-09T00:00:00Z, fixed
        rootfs_hash: store.rootfs_hash,
        rootfs_size: store.rootfs_size,
        codec_params: params,
        image_version: "0.1.0".into(),
        rootfs_fstype: "erofs".into(),
        version_ordinal: 1,
    };
    (m, store)
}

/// A complete, valid payload region plus the manifest it describes.
pub fn payload_for(data: &[u8], codec: &dyn Codec) -> (Vec<u8>, Manifest, ChunkStore) {
    let (m, store) = manifest_for(data, codec);
    let bytes = nsif_format::payload::build(&m, &store.data, &SECRET).expect("payload build");
    (bytes, m, store)
}

/// A small valid payload, the common case for tests.
pub fn small_payload() -> (Vec<u8>, Manifest, ChunkStore) {
    let data = sample_rootfs(400 * 1024);
    let c = zstd();
    payload_for(&data, &c)
}

/// Unused `ParamValue` re-export so tests can build odd codec_params.
pub fn param_uint(v: u64) -> ParamValue {
    ParamValue::Uint(v)
}
