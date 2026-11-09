//! Cross-field manifest validation (SPEC §5.3) and payload consistency checks.
//!
//! Everything here is a reject, never a clamp. The functions take already
//! decoded values, so they are cheap to call from tests and from fuzz targets.

use std::collections::BTreeSet;

use crate::codec;
use crate::error::{Error, Result};
use crate::header::PayloadHeader;
use crate::limits;
use crate::manifest::{
    Chunking, Manifest, ARCH_X86_64, FSTYPE_EROFS, FSTYPE_EXT4, FSTYPE_SQUASHFS,
    MANIFEST_SCHEMA_VERSION,
};

/// SPEC §5.3, the whole list.
///
/// `chunk_data_len` comes from the payload header; pass `None` to skip the
/// §5.3.8 in-range check when validating a manifest on its own.
pub fn manifest(m: &Manifest, chunk_data_len: Option<u64>) -> Result<()> {
    // 1. schema
    if m.version != MANIFEST_SCHEMA_VERSION {
        return Err(Error::BadField {
            field: "version",
            problem: format!("expected {MANIFEST_SCHEMA_VERSION}, got {}", m.version),
        });
    }

    // 2. arch
    if m.arch != ARCH_X86_64 {
        return Err(Error::BadField {
            field: "arch",
            problem: format!("v0 supports only {ARCH_X86_64:?}, got {:?}", m.arch),
        });
    }

    // 3. codec id and params. `resolve` rejects unknown ids and unknown params.
    let cdc = codec::resolve(&m.codec, &m.codec_params)?;

    // 4. rootfs_fstype
    if ![FSTYPE_EROFS, FSTYPE_SQUASHFS, FSTYPE_EXT4].contains(&m.rootfs_fstype.as_str()) {
        return Err(Error::BadField {
            field: "rootfs_fstype",
            problem: format!(
                "{:?} is not one of {FSTYPE_EROFS:?}, {FSTYPE_SQUASHFS:?}, {FSTYPE_EXT4:?}",
                m.rootfs_fstype
            ),
        });
    }

    // 5. chunking parameters
    chunking(&m.chunking)?;

    // 6. chunk count
    if m.chunks.is_empty() {
        return Err(Error::BadField {
            field: "chunks",
            problem: "must contain at least one chunk".into(),
        });
    }
    if m.chunks.len() as u64 > limits::MAX_CHUNKS {
        return Err(Error::LimitExceeded {
            what: "chunk count",
            value: m.chunks.len() as u64,
            limit: limits::MAX_CHUNKS,
        });
    }

    // 10. rootfs_size
    if m.rootfs_size == 0 {
        return Err(Error::LimitBelow { what: "rootfs_size", value: 0, min: 1 });
    }
    if m.rootfs_size > limits::MAX_ROOTFS_SIZE {
        return Err(Error::LimitExceeded {
            what: "rootfs_size",
            value: m.rootfs_size,
            limit: limits::MAX_ROOTFS_SIZE,
        });
    }

    // 7. uncompressed coverage is exact and contiguous
    // 8. compressed extents are in range
    let mut expect_uoff: u64 = 0;
    for (i, c) in m.chunks.iter().enumerate() {
        if c.ulen < limits::MIN_CHUNK_ULEN {
            return Err(Error::BadChunk { index: i, problem: "ulen is 0".into() });
        }
        if c.ulen > limits::MAX_CHUNK_ULEN {
            return Err(Error::BadChunk {
                index: i,
                problem: format!("ulen {} exceeds the {} cap", c.ulen, limits::MAX_CHUNK_ULEN),
            });
        }
        if c.ulen > m.chunking.max {
            return Err(Error::BadChunk {
                index: i,
                problem: format!("ulen {} exceeds chunking.max {}", c.ulen, m.chunking.max),
            });
        }
        if c.uoff != expect_uoff {
            return Err(Error::BadChunk {
                index: i,
                problem: format!("uoff is {}, expected {expect_uoff} (chunks must tile the rootfs with no gap or overlap)", c.uoff),
            });
        }
        expect_uoff = c
            .uend()
            .ok_or(Error::Overflow { what: "chunk uoff + ulen" })?;

        if c.clen == 0 {
            return Err(Error::BadChunk { index: i, problem: "clen is 0".into() });
        }
        if c.clen > limits::MAX_CHUNK_CLEN {
            return Err(Error::BadChunk {
                index: i,
                problem: format!("clen {} exceeds the {} cap", c.clen, limits::MAX_CHUNK_CLEN),
            });
        }
        let bound = c
            .ulen
            .checked_add(cdc.max_expansion(c.ulen))
            .ok_or(Error::Overflow { what: "ulen + max_expansion" })?;
        if c.clen > bound {
            return Err(Error::BadChunk {
                index: i,
                problem: format!(
                    "clen {} exceeds the codec's maximum expansion bound {bound} for a {}-byte input",
                    c.clen, c.ulen
                ),
            });
        }
        let cend = c
            .cend()
            .ok_or(Error::Overflow { what: "chunk coff + clen" })?;
        if let Some(cdl) = chunk_data_len {
            if cend > cdl {
                return Err(Error::BadChunk {
                    index: i,
                    problem: format!(
                        "compressed extent {}..{cend} runs past chunk_data_len {cdl}",
                        c.coff
                    ),
                });
            }
        }
    }
    if expect_uoff != m.rootfs_size {
        return Err(Error::BadField {
            field: "rootfs_size",
            problem: format!("chunks cover {expect_uoff} bytes but rootfs_size is {}", m.rootfs_size),
        });
    }

    // 9. compressed extents do not partially overlap
    chunk_extents(m)?;

    // 11. esp_files
    if m.esp_files.len() as u64 > limits::MAX_ESP_FILES {
        return Err(Error::LimitExceeded {
            what: "esp_files count",
            value: m.esp_files.len() as u64,
            limit: limits::MAX_ESP_FILES,
        });
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (i, e) in m.esp_files.iter().enumerate() {
        esp_path(&e.path).map_err(|problem| Error::BadEspFile { index: i, problem })?;
        // FAT is case-insensitive, so duplicates are detected case-folded.
        let folded = e.path.to_ascii_lowercase();
        if !seen.insert(folded) {
            return Err(Error::BadEspFile {
                index: i,
                problem: format!("duplicate path {:?} (compared case-insensitively)", e.path),
            });
        }
    }

    // 12. text field caps (decode enforces these too; re-checked for
    // manifests built in memory rather than decoded)
    for (field, s) in [
        ("name", &m.name),
        ("image_version", &m.image_version),
        ("cmdline", &m.cmdline),
    ] {
        if s.len() > limits::MAX_TEXT_FIELD_LEN {
            return Err(Error::BadField {
                field,
                problem: format!("{} bytes exceeds the {}-byte cap", s.len(), limits::MAX_TEXT_FIELD_LEN),
            });
        }
    }
    if m.metadata.len() as u64 > limits::MAX_METADATA_ENTRIES {
        return Err(Error::LimitExceeded {
            what: "metadata entries",
            value: m.metadata.len() as u64,
            limit: limits::MAX_METADATA_ENTRIES,
        });
    }

    Ok(())
}

/// SPEC §5.3.5, plus the narrower bounds the FastCDC implementation requires.
pub fn chunking(c: &Chunking) -> Result<()> {
    if !c.algo_fastcdc {
        return Err(Error::BadChunkingParams("algo must be \"fastcdc\"".into()));
    }
    if c.normalization > 3 {
        return Err(Error::BadChunkingParams(format!(
            "normalization is {}, must be 0..=3",
            c.normalization
        )));
    }
    if c.min < limits::MIN_CHUNKING_MIN {
        return Err(Error::BadChunkingParams(format!(
            "min is {}, must be at least {}",
            c.min, limits::MIN_CHUNKING_MIN
        )));
    }
    if !(c.min <= c.avg && c.avg <= c.max) {
        return Err(Error::BadChunkingParams(format!(
            "require min <= avg <= max, got min={} avg={} max={}",
            c.min, c.avg, c.max
        )));
    }
    if c.max > limits::MAX_CHUNKING_MAX {
        return Err(Error::BadChunkingParams(format!(
            "max is {}, must be at most {}",
            c.max, limits::MAX_CHUNKING_MAX
        )));
    }
    if c.min > limits::CHUNKER_MIN_SIZE_CEILING {
        return Err(Error::BadChunkingParams(format!(
            "min is {}, but this implementation's chunker accepts at most {}",
            c.min, limits::CHUNKER_MIN_SIZE_CEILING
        )));
    }
    if c.avg > limits::CHUNKER_AVG_SIZE_CEILING {
        return Err(Error::BadChunkingParams(format!(
            "avg is {}, but this implementation's chunker accepts at most {}",
            c.avg, limits::CHUNKER_AVG_SIZE_CEILING
        )));
    }
    // FastCDC requires even sizes.
    for (name, v) in [("min", c.min), ("avg", c.avg), ("max", c.max)] {
        if v % 2 != 0 {
            return Err(Error::BadChunkingParams(format!("{name} must be even, got {v}")));
        }
    }
    if c.seed != 0 {
        return Err(Error::BadChunkingParams(format!(
            "seed is {}; v0 defines only seed 0",
            c.seed
        )));
    }
    Ok(())
}

/// SPEC §5.3.9: distinct compressed extents must be disjoint; identical ones
/// may be shared by deduplicated chunks.
fn chunk_extents(m: &Manifest) -> Result<()> {
    // (coff, clen, first chunk index that owns it)
    let mut extents: Vec<(u64, u64, usize)> = Vec::with_capacity(m.chunks.len());
    let mut by_key: std::collections::HashMap<(u64, u64), usize> = Default::default();

    for (i, c) in m.chunks.iter().enumerate() {
        match by_key.entry((c.coff, c.clen)) {
            std::collections::hash_map::Entry::Occupied(e) => {
                // A shared extent is only legal between identical chunks.
                let first = *e.get();
                if m.chunks[first].hash != c.hash {
                    return Err(Error::BadChunk {
                        index: i,
                        problem: format!(
                            "shares the compressed extent {}..{} with chunk {first} but has a different hash",
                            c.coff,
                            c.coff + c.clen
                        ),
                    });
                }
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(i);
                extents.push((c.coff, c.clen, i));
            }
        }
    }

    extents.sort_unstable();
    for w in extents.windows(2) {
        let (a_off, a_len, a_i) = w[0];
        let (b_off, b_len, b_i) = w[1];
        let a_end = a_off + a_len; // already overflow-checked in `manifest`
        if b_off < a_end {
            return Err(Error::ChunkExtentOverlap {
                a: a_i,
                b: b_i,
                a_off,
                a_end,
                b_off,
                b_end: b_off + b_len,
            });
        }
    }
    Ok(())
}

/// SPEC §5.3.11: an ESP path must be absolute, componentwise clean, and free of
/// anything FAT or a path walker could reinterpret.
pub fn esp_path(path: &str) -> std::result::Result<(), String> {
    if path.is_empty() {
        return Err("path is empty".into());
    }
    if path.len() > limits::MAX_ESP_PATH_LEN {
        return Err(format!(
            "{} bytes exceeds the {}-byte cap",
            path.len(),
            limits::MAX_ESP_PATH_LEN
        ));
    }
    if !path.starts_with('/') {
        return Err(format!("{path:?} is not absolute"));
    }
    if path.contains('\\') {
        return Err(format!("{path:?} contains a backslash"));
    }
    if path.contains('\0') {
        return Err(format!("{path:?} contains a NUL"));
    }
    for comp in path.split('/').skip(1) {
        if comp.is_empty() {
            return Err(format!("{path:?} has an empty component"));
        }
        if comp == "." || comp == ".." {
            return Err(format!("{path:?} has a {comp:?} component"));
        }
    }
    Ok(())
}

/// Convenience: validate a header's regions and then its manifest, the order
/// SPEC §4.2 requires.
pub fn payload(header: &PayloadHeader, payload_bytes: &[u8], partition_size: u64) -> Result<Manifest> {
    header.validate_regions(partition_size)?;
    let mbytes = header.manifest_bytes(payload_bytes)?;
    let m = Manifest::decode(mbytes)?;
    manifest(&m, Some(header.chunk_data_len))?;
    Ok(m)
}
