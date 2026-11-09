//! Content-defined chunking (FastCDC) and the chunk store it produces.

use std::collections::HashMap;

use fastcdc::v2020::{FastCDC, Normalization};

use crate::codec::Codec;
use crate::error::{Error, HexBytes, Result};
use crate::manifest::{Chunk, Chunking};
use crate::validate;

fn normalization(level: u64) -> Normalization {
    match level {
        0 => Normalization::Level0,
        1 => Normalization::Level1,
        2 => Normalization::Level2,
        _ => Normalization::Level3,
    }
}

/// Split `data` into `(offset, length)` pairs. Deterministic for given params.
pub fn boundaries(data: &[u8], c: &Chunking) -> Result<Vec<(u64, u64)>> {
    validate::chunking(c)?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let cdc = FastCDC::with_level_and_seed(
        data,
        c.min as usize,
        c.avg as usize,
        c.max as usize,
        normalization(c.normalization),
        c.seed,
    );
    let mut out = Vec::new();
    for e in cdc {
        out.push((e.offset as u64, e.length as u64));
    }
    Ok(out)
}

/// A packed chunk store: the manifest chunk list plus the compressed bytes they
/// index into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkStore {
    pub chunks: Vec<Chunk>,
    pub data: Vec<u8>,
    /// BLAKE3 of the whole uncompressed input, for `rootfs_hash`.
    pub rootfs_hash: [u8; 32],
    pub rootfs_size: u64,
    /// Bytes of compressed data saved by deduplication.
    pub dedup_saved: u64,
    /// Number of chunks that reused an earlier chunk's extent.
    pub dedup_hits: u64,
}

/// Chunk, hash, compress and deduplicate `data`.
///
/// Deduplication follows SPEC §11: the **first** occurrence of a hash owns the
/// compressed extent and later identical chunks reuse its `(coff, clen)`, which
/// keeps the output a pure function of the input.
pub fn build(data: &[u8], c: &Chunking, codec: &dyn Codec) -> Result<ChunkStore> {
    let bounds = boundaries(data, c)?;
    let mut chunks = Vec::with_capacity(bounds.len());
    let mut out: Vec<u8> = Vec::with_capacity(data.len() / 2 + 1024);
    let mut seen: HashMap<[u8; 32], (u64, u64)> = HashMap::with_capacity(bounds.len());
    let mut dedup_saved = 0u64;
    let mut dedup_hits = 0u64;

    for (uoff, ulen) in bounds {
        let src = &data[uoff as usize..(uoff + ulen) as usize];
        let hash: [u8; 32] = *blake3::hash(src).as_bytes();

        let (coff, clen) = if let Some(&(coff, clen)) = seen.get(&hash) {
            dedup_hits += 1;
            dedup_saved += clen;
            (coff, clen)
        } else {
            let comp = codec.compress(src)?;
            let coff = out.len() as u64;
            let clen = comp.len() as u64;
            out.extend_from_slice(&comp);
            seen.insert(hash, (coff, clen));
            (coff, clen)
        };

        chunks.push(Chunk { hash, uoff, ulen, coff, clen });
    }

    Ok(ChunkStore {
        chunks,
        data: out,
        rootfs_hash: *blake3::hash(data).as_bytes(),
        rootfs_size: data.len() as u64,
        dedup_saved,
        dedup_hits,
    })
}

/// Random-access reader over a chunk list (SPEC §5.4).
///
/// Chunks tile `[0, rootfs_size)` in order, so a lookup is a binary search on
/// `uoff` followed by a forward walk.
pub struct ChunkIndex<'a> {
    chunks: &'a [Chunk],
    rootfs_size: u64,
}

impl<'a> ChunkIndex<'a> {
    pub fn new(chunks: &'a [Chunk], rootfs_size: u64) -> Self {
        Self { chunks, rootfs_size }
    }

    /// Index of the chunk containing byte `off`, or `None` past the end.
    pub fn find(&self, off: u64) -> Option<usize> {
        if off >= self.rootfs_size {
            return None;
        }
        match self.chunks.binary_search_by(|c| c.uoff.cmp(&off)) {
            Ok(i) => Some(i),
            // `Err(i)` is the insertion point, so the containing chunk is i-1.
            Err(0) => None,
            Err(i) => Some(i - 1),
        }
    }

    /// The chunk indices a read of `[off, off+len)` touches.
    pub fn range(&self, off: u64, len: u64) -> Option<std::ops::Range<usize>> {
        if len == 0 {
            return Some(0..0);
        }
        let end = off.checked_add(len)?;
        if end > self.rootfs_size {
            return None;
        }
        let first = self.find(off)?;
        let last = self.find(end - 1)?;
        Some(first..last + 1)
    }

    /// Decompress and verify one chunk into `dst`, which must be `ulen` bytes.
    ///
    /// The hash is checked **after** decompression and before the bytes are
    /// handed back, so a corrupted chunk can never be returned as data
    /// (SPEC §13.3).
    pub fn read_chunk(
        &self,
        index: usize,
        chunk_data: &[u8],
        codec: &dyn Codec,
        dst: &mut [u8],
    ) -> Result<()> {
        let c = self.chunks.get(index).ok_or(Error::BadChunk {
            index,
            problem: "index out of range".into(),
        })?;
        if dst.len() as u64 != c.ulen {
            return Err(Error::BadChunk {
                index,
                problem: format!("destination is {} bytes, chunk ulen is {}", dst.len(), c.ulen),
            });
        }
        let coff = usize::try_from(c.coff).map_err(|_| Error::Overflow { what: "coff" })?;
        let clen = usize::try_from(c.clen).map_err(|_| Error::Overflow { what: "clen" })?;
        let cend = coff.checked_add(clen).ok_or(Error::Overflow { what: "coff + clen" })?;
        if cend > chunk_data.len() {
            return Err(Error::BadChunk {
                index,
                problem: format!(
                    "compressed extent {coff}..{cend} runs past the {}-byte chunk-data region",
                    chunk_data.len()
                ),
            });
        }
        codec.decompress(&chunk_data[coff..cend], dst)?;
        let actual: [u8; 32] = *blake3::hash(dst).as_bytes();
        if actual != c.hash {
            return Err(Error::ChunkHashMismatch {
                index,
                expected: HexBytes::new(c.hash),
                actual: HexBytes::new(actual),
            });
        }
        Ok(())
    }

    /// Serve an arbitrary byte range, verifying every chunk it touches.
    pub fn read_range(
        &self,
        chunk_data: &[u8],
        codec: &dyn Codec,
        off: u64,
        len: u64,
    ) -> Result<Vec<u8>> {
        let r = self.range(off, len).ok_or(Error::BadField {
            field: "read range",
            problem: format!("{off}..{} is outside 0..{}", off.saturating_add(len), self.rootfs_size),
        })?;
        let mut out = Vec::with_capacity(len as usize);
        let mut buf = Vec::new();
        for i in r {
            let c = &self.chunks[i];
            buf.resize(c.ulen as usize, 0);
            self.read_chunk(i, chunk_data, codec, &mut buf)?;
            let start = off.saturating_sub(c.uoff);
            let stop = (off + len).min(c.uoff + c.ulen) - c.uoff;
            out.extend_from_slice(&buf[start as usize..stop as usize]);
        }
        Ok(out)
    }

    /// Reassemble and verify the whole image.
    pub fn read_all(&self, chunk_data: &[u8], codec: &dyn Codec) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.rootfs_size as usize);
        let mut buf = Vec::new();
        for i in 0..self.chunks.len() {
            buf.resize(self.chunks[i].ulen as usize, 0);
            self.read_chunk(i, chunk_data, codec, &mut buf)?;
            out.extend_from_slice(&buf);
        }
        Ok(out)
    }
}
