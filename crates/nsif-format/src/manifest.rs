//! The manifest (SPEC §5): structs, deterministic encoding, strict decoding.
//!
//! Decoding enforces the CBOR profile (SPEC §5.1) via [`crate::cbor::Reader`]
//! and the field-level caps from SPEC §9 here. Cross-field invariants
//! (contiguity, extent overlap, …) live in [`crate::validate`].

use std::collections::BTreeMap;

use crate::cbor::{MapWriter, Reader, Writer};
use crate::codec::{Params, ParamValue};
use crate::error::{Error, Result};
use crate::limits;

pub const MANIFEST_FORMAT: &str = "nsif-manifest";
pub const MANIFEST_SCHEMA_VERSION: u64 = 1;
pub const ARCH_X86_64: &str = "x86_64";

pub const FSTYPE_EROFS: &str = "erofs";
pub const FSTYPE_SQUASHFS: &str = "squashfs";
pub const FSTYPE_EXT4: &str = "ext4";

pub const CHUNKING_ALGO_FASTCDC: &str = "fastcdc";

/// Reserved `metadata` keys (SPEC §5.5).
pub const META_CODENAME: &str = "nsif.codename";
pub const META_PACKER: &str = "nsif.packer";
pub const META_ZSTD_VERSION: &str = "zstd.version";

/// One chunk: `[hash, uoff, ulen, coff, clen]` (SPEC §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub hash: [u8; 32],
    /// Offset of this chunk within the uncompressed rootfs image.
    pub uoff: u64,
    /// Uncompressed length.
    pub ulen: u64,
    /// Offset within the chunk-data region.
    pub coff: u64,
    /// Compressed length.
    pub clen: u64,
}

impl Chunk {
    pub fn uend(&self) -> Option<u64> {
        self.uoff.checked_add(self.ulen)
    }
    pub fn cend(&self) -> Option<u64> {
        self.coff.checked_add(self.clen)
    }
}

/// One ESP file: `[path, size, hash]` (SPEC §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspFile {
    pub path: String,
    pub size: u64,
    pub hash: [u8; 32],
}

/// FastCDC parameters, recorded so a reader never has to guess them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunking {
    pub avg: u64,
    pub max: u64,
    pub min: u64,
    pub algo_fastcdc: bool,
    pub seed: u64,
    pub normalization: u64,
}

impl Default for Chunking {
    fn default() -> Self {
        Self {
            min: 16 * 1024,
            avg: 64 * 1024,
            max: 256 * 1024,
            algo_fastcdc: true,
            seed: 0,
            normalization: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub arch: String,
    pub name: String,
    pub codec: String,
    pub chunks: Vec<Chunk>,
    pub cmdline: String,
    pub version: u64,
    pub chunking: Chunking,
    pub metadata: BTreeMap<String, String>,
    pub esp_files: Vec<EspFile>,
    pub build_date: u64,
    pub rootfs_hash: [u8; 32],
    pub rootfs_size: u64,
    pub codec_params: Params,
    pub image_version: String,
    pub rootfs_fstype: String,
    pub version_ordinal: u64,
}

/// Every top-level key the v0 schema defines. Used to reject unknown keys.
const TOP_LEVEL_KEYS: &[&str] = &[
    "arch",
    "build_date",
    "chunking",
    "chunks",
    "cmdline",
    "codec",
    "codec_params",
    "esp_files",
    "format",
    "image_version",
    "metadata",
    "name",
    "rootfs_fstype",
    "rootfs_hash",
    "rootfs_size",
    "version",
    "version_ordinal",
];

impl Manifest {
    /// Encode to deterministic CBOR (SPEC §5.1).
    ///
    /// Key ordering is handled by [`MapWriter`], which sorts by encoded key
    /// bytes, so the written order here is irrelevant to the output.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut m = MapWriter::new();
        m.entry("format", |w| w.tstr(MANIFEST_FORMAT));
        m.entry("version", |w| w.uint(self.version));
        m.entry("name", |w| w.tstr(&self.name));
        m.entry("image_version", |w| w.tstr(&self.image_version));
        m.entry("version_ordinal", |w| w.uint(self.version_ordinal));
        m.entry("arch", |w| w.tstr(&self.arch));
        m.entry("build_date", |w| w.uint(self.build_date));
        m.entry("codec", |w| w.tstr(&self.codec));
        m.entry("cmdline", |w| w.tstr(&self.cmdline));
        m.entry("rootfs_fstype", |w| w.tstr(&self.rootfs_fstype));
        m.entry("rootfs_size", |w| w.uint(self.rootfs_size));
        m.entry("rootfs_hash", |w| w.bstr(&self.rootfs_hash));

        let params = self.codec_params.clone();
        m.entry("codec_params", move |w| {
            let mut pm = MapWriter::new();
            for (k, v) in &params {
                let v = v.clone();
                pm.entry(k, move |w| match v {
                    ParamValue::Uint(u) => w.uint(u),
                    ParamValue::Text(ref t) => w.tstr(t),
                    ParamValue::Bool(b) => w.boolean(b),
                });
            }
            // A nested MapWriter cannot fail for distinct BTreeMap keys.
            pm.finish(w).expect("codec_params keys are unique by construction");
        });

        let ch = self.chunking;
        m.entry("chunking", move |w| {
            let mut cm = MapWriter::new();
            cm.entry("algo", |w| w.tstr(CHUNKING_ALGO_FASTCDC));
            cm.entry("avg", |w| w.uint(ch.avg));
            cm.entry("max", |w| w.uint(ch.max));
            cm.entry("min", |w| w.uint(ch.min));
            cm.entry("normalization", |w| w.uint(ch.normalization));
            cm.entry("seed", |w| w.uint(ch.seed));
            cm.finish(w).expect("chunking keys are literals and unique");
        });

        let meta = self.metadata.clone();
        m.entry("metadata", move |w| {
            let mut mm = MapWriter::new();
            for (k, v) in &meta {
                let v = v.clone();
                mm.entry(k, move |w| w.tstr(&v));
            }
            mm.finish(w).expect("metadata keys are unique by construction");
        });

        let chunks = self.chunks.clone();
        m.entry("chunks", move |w| {
            w.array(chunks.len());
            for c in &chunks {
                w.array(5);
                w.bstr(&c.hash);
                w.uint(c.uoff);
                w.uint(c.ulen);
                w.uint(c.coff);
                w.uint(c.clen);
            }
        });

        let esp = self.esp_files.clone();
        m.entry("esp_files", move |w| {
            w.array(esp.len());
            for e in &esp {
                w.array(3);
                w.tstr(&e.path);
                w.uint(e.size);
                w.bstr(&e.hash);
            }
        });

        let mut out = Writer::with_capacity(64 + self.chunks.len() * 72);
        m.finish(&mut out)?;
        Ok(out.into_bytes())
    }

    /// Decode from deterministic CBOR. Enforces the §5.1 profile and the
    /// per-field caps of §9; call [`crate::validate::manifest`] for the
    /// cross-field invariants of §5.3.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > limits::MAX_MANIFEST_LEN {
            return Err(Error::LimitExceeded {
                what: "manifest_len",
                value: bytes.len() as u64,
                limit: limits::MAX_MANIFEST_LEN,
            });
        }

        // Enforce the whole SPEC §5.1 profile first, so a profile violation is
        // reported as such rather than as whatever schema error it triggers.
        crate::cbor::validate_profile(bytes)?;

        let mut r = Reader::new(bytes);

        let mut format: Option<String> = None;
        let mut version: Option<u64> = None;
        let mut name: Option<String> = None;
        let mut image_version: Option<String> = None;
        let mut version_ordinal: Option<u64> = None;
        let mut arch: Option<String> = None;
        let mut build_date: Option<u64> = None;
        let mut codec: Option<String> = None;
        let mut cmdline: Option<String> = None;
        let mut rootfs_fstype: Option<String> = None;
        let mut rootfs_size: Option<u64> = None;
        let mut rootfs_hash: Option<[u8; 32]> = None;
        let mut codec_params: Option<Params> = None;
        let mut chunking: Option<Chunking> = None;
        let mut metadata: Option<BTreeMap<String, String>> = None;
        let mut chunks: Option<Vec<Chunk>> = None;
        let mut esp_files: Option<Vec<EspFile>> = None;

        r.map(|r, key| {
            match key {
                "format" => format = Some(text_capped(r, "format", 64)?),
                "version" => version = Some(r.uint()?),
                "name" => name = Some(text_capped(r, "name", limits::MAX_TEXT_FIELD_LEN)?),
                "image_version" => {
                    image_version =
                        Some(text_capped(r, "image_version", limits::MAX_TEXT_FIELD_LEN)?)
                }
                "version_ordinal" => version_ordinal = Some(r.uint()?),
                "arch" => arch = Some(text_capped(r, "arch", 64)?),
                "build_date" => build_date = Some(r.uint()?),
                "codec" => codec = Some(text_capped(r, "codec", 64)?),
                "cmdline" => {
                    cmdline = Some(text_capped(r, "cmdline", limits::MAX_TEXT_FIELD_LEN)?)
                }
                "rootfs_fstype" => rootfs_fstype = Some(text_capped(r, "rootfs_fstype", 64)?),
                "rootfs_size" => rootfs_size = Some(r.uint()?),
                "rootfs_hash" => rootfs_hash = Some(r.bstr_exact::<32>()?),
                "codec_params" => codec_params = Some(decode_codec_params(r)?),
                "chunking" => chunking = Some(decode_chunking(r)?),
                "metadata" => metadata = Some(decode_metadata(r)?),
                "chunks" => chunks = Some(decode_chunks(r)?),
                "esp_files" => esp_files = Some(decode_esp_files(r)?),
                other => return Err(Error::UnknownKey { key: other.to_owned() }),
            }
            Ok(())
        })?;
        r.finish()?;

        let format = format.ok_or(Error::MissingKey { key: "format" })?;
        if format != MANIFEST_FORMAT {
            return Err(Error::BadField {
                field: "format",
                problem: format!("expected {MANIFEST_FORMAT:?}, got {format:?}"),
            });
        }

        Ok(Self {
            arch: arch.ok_or(Error::MissingKey { key: "arch" })?,
            name: name.ok_or(Error::MissingKey { key: "name" })?,
            codec: codec.ok_or(Error::MissingKey { key: "codec" })?,
            chunks: chunks.ok_or(Error::MissingKey { key: "chunks" })?,
            cmdline: cmdline.ok_or(Error::MissingKey { key: "cmdline" })?,
            version: version.ok_or(Error::MissingKey { key: "version" })?,
            chunking: chunking.ok_or(Error::MissingKey { key: "chunking" })?,
            metadata: metadata.ok_or(Error::MissingKey { key: "metadata" })?,
            esp_files: esp_files.ok_or(Error::MissingKey { key: "esp_files" })?,
            build_date: build_date.ok_or(Error::MissingKey { key: "build_date" })?,
            rootfs_hash: rootfs_hash.ok_or(Error::MissingKey { key: "rootfs_hash" })?,
            rootfs_size: rootfs_size.ok_or(Error::MissingKey { key: "rootfs_size" })?,
            codec_params: codec_params.ok_or(Error::MissingKey { key: "codec_params" })?,
            image_version: image_version.ok_or(Error::MissingKey { key: "image_version" })?,
            rootfs_fstype: rootfs_fstype.ok_or(Error::MissingKey { key: "rootfs_fstype" })?,
            version_ordinal: version_ordinal
                .ok_or(Error::MissingKey { key: "version_ordinal" })?,
        })
    }

    /// The keys a v0 manifest may contain, for diagnostics.
    pub fn top_level_keys() -> &'static [&'static str] {
        TOP_LEVEL_KEYS
    }
}

fn text_capped(r: &mut Reader<'_>, field: &'static str, cap: usize) -> Result<String> {
    let s = r.tstr()?;
    if s.len() > cap {
        return Err(Error::BadField {
            field,
            problem: format!("{} bytes exceeds the {cap}-byte cap", s.len()),
        });
    }
    Ok(s.to_owned())
}

fn decode_codec_params(r: &mut Reader<'_>) -> Result<Params> {
    let mut out = Params::new();
    let mut n = 0u64;
    r.map(|r, key| {
        n += 1;
        if n > limits::MAX_CODEC_PARAMS {
            return Err(Error::LimitExceeded {
                what: "codec_params entries",
                value: n,
                limit: limits::MAX_CODEC_PARAMS,
            });
        }
        // Peek the value type by trying each permitted shape in turn is not
        // possible with a forward-only reader, so the shape is dispatched on
        // the next byte's major type without consuming it.
        let v = decode_param_value(r)?;
        out.insert(key.to_owned(), v);
        Ok(())
    })?;
    Ok(out)
}

/// `codec_params` values may be uint, tstr or bool (SPEC §5.2).
fn decode_param_value(r: &mut Reader<'_>) -> Result<ParamValue> {
    match r.peek_major()? {
        0 => Ok(ParamValue::Uint(r.uint()?)),
        3 => Ok(ParamValue::Text(r.tstr()?.to_owned())),
        7 => Ok(ParamValue::Bool(r.boolean()?)),
        other => Err(Error::BadField {
            field: "codec_params",
            problem: format!("value has CBOR major type {other}, expected uint, text or bool"),
        }),
    }
}

fn decode_chunking(r: &mut Reader<'_>) -> Result<Chunking> {
    let mut algo: Option<String> = None;
    let mut avg = None;
    let mut max = None;
    let mut min = None;
    let mut normalization = None;
    let mut seed = None;
    r.map(|r, key| {
        match key {
            "algo" => algo = Some(text_capped(r, "chunking.algo", 32)?),
            "avg" => avg = Some(r.uint()?),
            "max" => max = Some(r.uint()?),
            "min" => min = Some(r.uint()?),
            "normalization" => normalization = Some(r.uint()?),
            "seed" => seed = Some(r.uint()?),
            other => {
                return Err(Error::BadField {
                    field: "chunking",
                    problem: format!("unknown key {other:?}"),
                })
            }
        }
        Ok(())
    })?;
    let algo = algo.ok_or(Error::MissingKey { key: "chunking.algo" })?;
    if algo != CHUNKING_ALGO_FASTCDC {
        return Err(Error::BadField {
            field: "chunking.algo",
            problem: format!("expected {CHUNKING_ALGO_FASTCDC:?}, got {algo:?}"),
        });
    }
    Ok(Chunking {
        avg: avg.ok_or(Error::MissingKey { key: "chunking.avg" })?,
        max: max.ok_or(Error::MissingKey { key: "chunking.max" })?,
        min: min.ok_or(Error::MissingKey { key: "chunking.min" })?,
        algo_fastcdc: true,
        seed: seed.ok_or(Error::MissingKey { key: "chunking.seed" })?,
        normalization: normalization.ok_or(Error::MissingKey { key: "chunking.normalization" })?,
    })
}

fn decode_metadata(r: &mut Reader<'_>) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut n = 0u64;
    r.map(|r, key| {
        n += 1;
        if n > limits::MAX_METADATA_ENTRIES {
            return Err(Error::LimitExceeded {
                what: "metadata entries",
                value: n,
                limit: limits::MAX_METADATA_ENTRIES,
            });
        }
        if key.len() > limits::MAX_METADATA_KEY_LEN {
            return Err(Error::BadField {
                field: "metadata",
                problem: format!(
                    "key {:?} is {} bytes, over the {}-byte cap",
                    key,
                    key.len(),
                    limits::MAX_METADATA_KEY_LEN
                ),
            });
        }
        let v = text_capped(r, "metadata", limits::MAX_METADATA_VALUE_LEN)?;
        out.insert(key.to_owned(), v);
        Ok(())
    })?;
    Ok(out)
}

fn decode_chunks(r: &mut Reader<'_>) -> Result<Vec<Chunk>> {
    let n = r.array_header()? as u64;
    if n > limits::MAX_CHUNKS {
        return Err(Error::LimitExceeded { what: "chunk count", value: n, limit: limits::MAX_CHUNKS });
    }
    let mut out = Vec::with_capacity((n as usize).min(1 << 16));
    for i in 0..n {
        let len = r.array_header()?;
        if len != 5 {
            return Err(Error::BadChunk {
                index: i as usize,
                problem: format!("expected a 5-element array, got {len}"),
            });
        }
        out.push(Chunk {
            hash: r.bstr_exact::<32>()?,
            uoff: r.uint()?,
            ulen: r.uint()?,
            coff: r.uint()?,
            clen: r.uint()?,
        });
    }
    Ok(out)
}

fn decode_esp_files(r: &mut Reader<'_>) -> Result<Vec<EspFile>> {
    let n = r.array_header()? as u64;
    if n > limits::MAX_ESP_FILES {
        return Err(Error::LimitExceeded {
            what: "esp_files count",
            value: n,
            limit: limits::MAX_ESP_FILES,
        });
    }
    let mut out = Vec::with_capacity((n as usize).min(4096));
    for i in 0..n {
        let len = r.array_header()?;
        if len != 3 {
            return Err(Error::BadEspFile {
                index: i as usize,
                problem: format!("expected a 3-element array, got {len}"),
            });
        }
        let path = r.tstr()?;
        if path.len() > limits::MAX_ESP_PATH_LEN {
            return Err(Error::BadEspFile {
                index: i as usize,
                problem: format!(
                    "path is {} bytes, over the {}-byte cap",
                    path.len(),
                    limits::MAX_ESP_PATH_LEN
                ),
            });
        }
        out.push(EspFile {
            path: path.to_owned(),
            size: r.uint()?,
            hash: r.bstr_exact::<32>()?,
        });
    }
    Ok(out)
}
