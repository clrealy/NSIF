//! Assembling and reading the payload partition region (SPEC §4).
//!
//! Still no I/O: this produces and consumes a byte slice that happens to be
//! the contents of a partition. `nsif pack` writes the slice to a file;
//! `nsif-boot` maps it from a block device.

use crate::codec::Codec;
use crate::error::{Error, Result};
use crate::header::{PayloadHeader, VERSION_MAJOR, VERSION_MINOR};
use crate::limits;
use crate::manifest::Manifest;
use crate::sig::{self, SignatureBlock};
use crate::validate;

fn align_up(v: u64, a: u64) -> Result<u64> {
    let m = v % a;
    if m == 0 {
        return Ok(v);
    }
    v.checked_add(a - m).ok_or(Error::Overflow { what: "alignment" })
}

/// Lay out `header | manifest | signature | pad | chunk_data`.
///
/// The layout is a pure function of the inputs, which is what makes the whole
/// image reproducible (SPEC §11).
pub fn build(manifest: &Manifest, chunk_data: &[u8], secret: &[u8; 32]) -> Result<Vec<u8>> {
    let manifest_bytes = manifest.encode()?;

    // Validate what we are about to write, so `pack` can never emit an image
    // that `verify` would reject.
    validate::manifest(manifest, Some(chunk_data.len() as u64))?;

    let hl = u64::from(limits::HEADER_LEN);
    let manifest_offset = hl;
    let manifest_len = manifest_bytes.len() as u64;
    if manifest_len > limits::MAX_MANIFEST_LEN {
        return Err(Error::LimitExceeded {
            what: "manifest_len",
            value: manifest_len,
            limit: limits::MAX_MANIFEST_LEN,
        });
    }

    let signature_offset = align_up(
        manifest_offset
            .checked_add(manifest_len)
            .ok_or(Error::Overflow { what: "manifest end" })?,
        limits::REGION_ALIGN,
    )?;
    let signature_len = limits::SIGNATURE_BLOCK_LEN;

    let chunk_data_offset = align_up(
        signature_offset
            .checked_add(signature_len)
            .ok_or(Error::Overflow { what: "signature end" })?,
        limits::REGION_ALIGN,
    )?;
    let chunk_data_len = chunk_data.len() as u64;
    let payload_used_len = chunk_data_offset
        .checked_add(chunk_data_len)
        .ok_or(Error::Overflow { what: "payload end" })?;

    let block = sig::sign(secret, VERSION_MAJOR, VERSION_MINOR, &manifest_bytes);

    let header = PayloadHeader {
        version_major: VERSION_MAJOR,
        version_minor: VERSION_MINOR,
        header_len: limits::HEADER_LEN,
        manifest_offset,
        manifest_len,
        signature_offset,
        signature_len,
        chunk_data_offset,
        chunk_data_len,
        manifest_hash: *blake3::hash(&manifest_bytes).as_bytes(),
        payload_used_len,
        flags: 0,
    };

    let mut out = vec![0u8; payload_used_len as usize];
    out[..limits::HEADER_LEN as usize].copy_from_slice(&header.encode());
    let mo = manifest_offset as usize;
    out[mo..mo + manifest_bytes.len()].copy_from_slice(&manifest_bytes);
    let so = signature_offset as usize;
    out[so..so + sig::BLOCK_LEN].copy_from_slice(&block.encode());
    let co = chunk_data_offset as usize;
    out[co..co + chunk_data.len()].copy_from_slice(chunk_data);
    Ok(out)
}

/// A validated view over a payload region.
#[derive(Debug)]
pub struct PayloadView<'a> {
    pub header: PayloadHeader,
    pub manifest: Manifest,
    pub manifest_bytes: &'a [u8],
    bytes: &'a [u8],
}

impl<'a> PayloadView<'a> {
    /// Parse and fully validate, in the order SPEC §4.2 requires.
    ///
    /// `partition_size` is the containing partition's size in bytes; pass
    /// `bytes.len()` when reading a bare payload blob.
    pub fn open(bytes: &'a [u8], partition_size: u64) -> Result<Self> {
        let header = PayloadHeader::parse(bytes)?;
        header.validate_regions(partition_size)?;
        let manifest_bytes = header.manifest_bytes(bytes)?;
        let manifest = Manifest::decode(manifest_bytes)?;
        validate::manifest(&manifest, Some(header.chunk_data_len))?;
        Ok(Self { header, manifest, manifest_bytes, bytes })
    }

    pub fn signature_block(&self) -> Result<SignatureBlock> {
        SignatureBlock::parse(self.header.signature_bytes(self.bytes)?)
    }

    /// Verify the manifest signature with a **caller-supplied** key (SPEC §7.2).
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> Result<()> {
        let block = self.signature_block()?;
        sig::verify(
            public_key,
            &block,
            self.header.version_major,
            self.header.version_minor,
            self.manifest_bytes,
        )
    }

    pub fn chunk_data(&self) -> Result<&'a [u8]> {
        let off = usize::try_from(self.header.chunk_data_offset)
            .map_err(|_| Error::Overflow { what: "chunk_data_offset" })?;
        let len = usize::try_from(self.header.chunk_data_len)
            .map_err(|_| Error::Overflow { what: "chunk_data_len" })?;
        let end = off.checked_add(len).ok_or(Error::Overflow { what: "chunk_data range" })?;
        if end > self.bytes.len() {
            return Err(Error::ShortBuffer { need: end as u64, have: self.bytes.len() as u64 });
        }
        Ok(&self.bytes[off..end])
    }

    pub fn index(&self) -> crate::chunker::ChunkIndex<'_> {
        crate::chunker::ChunkIndex::new(&self.manifest.chunks, self.manifest.rootfs_size)
    }

    /// Verify every chunk and the overall rootfs hash.
    pub fn verify_chunks(&self, codec: &dyn Codec) -> Result<()> {
        let data = self.chunk_data()?;
        let idx = self.index();
        let mut hasher = blake3::Hasher::new();
        let mut buf = Vec::new();
        for i in 0..self.manifest.chunks.len() {
            buf.resize(self.manifest.chunks[i].ulen as usize, 0);
            idx.read_chunk(i, data, codec, &mut buf)?;
            hasher.update(&buf);
        }
        let actual: [u8; 32] = *hasher.finalize().as_bytes();
        if actual != self.manifest.rootfs_hash {
            return Err(Error::RootfsHashMismatch {
                expected: crate::error::HexBytes::new(self.manifest.rootfs_hash),
                actual: crate::error::HexBytes::new(actual),
            });
        }
        Ok(())
    }

    pub fn codec(&self) -> Result<Box<dyn Codec>> {
        crate::codec::resolve(&self.manifest.codec, &self.manifest.codec_params)
    }
}
