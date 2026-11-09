//! The `Codec` trait and the v0 registry (SPEC §10).
//!
//! Decompression always targets a buffer of exactly the chunk's declared
//! uncompressed length, so a decompression bomb is impossible by construction:
//! the declared size *is* the allocation size, and SPEC §9 caps it at 16 MiB.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// A `codec_params` value. Deliberately only the three CBOR types SPEC §5.2
/// permits here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ParamValue {
    Uint(u64),
    Text(String),
    Bool(bool),
}

impl ParamValue {
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            ParamValue::Uint(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ParamValue::Bool(v) => Some(*v),
            _ => None,
        }
    }
}

pub type Params = BTreeMap<String, ParamValue>;

pub trait Codec: Send + Sync {
    /// Stable registry id, recorded in the manifest.
    fn id(&self) -> &'static str;

    /// Parameters, recorded in `codec_params`. Keys must be stable.
    fn params(&self) -> Params;

    /// Compress `src`. Must be deterministic for a given build and params.
    fn compress(&self, src: &[u8]) -> Result<Vec<u8>>;

    /// Decompress `src` into exactly `dst.len()` bytes, failing otherwise.
    fn decompress(&self, src: &[u8], dst: &mut [u8]) -> Result<()>;

    /// Upper bound on how many bytes *beyond* `n` the output may occupy
    /// (SPEC §10.2). The total bound is `n + max_expansion(n)`.
    fn max_expansion(&self, n: u64) -> u64;
}

// ---------------------------------------------------------------- zstd

pub const ZSTD_ID: &str = "zstd";
pub const ZSTD_DEFAULT_LEVEL: u64 = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Zstd {
    pub level: u64,
    /// Long-distance matching. Not implemented in v0; only `false` is accepted.
    pub long: bool,
}

impl Default for Zstd {
    fn default() -> Self {
        Self { level: ZSTD_DEFAULT_LEVEL, long: false }
    }
}

impl Zstd {
    pub fn new(level: u64) -> Result<Self> {
        if !(1..=22).contains(&level) {
            return Err(Error::BadCodecParam {
                codec: ZSTD_ID,
                param: "level".into(),
                problem: format!("{level} is outside 1..=22"),
            });
        }
        Ok(Self { level, long: false })
    }

    /// Build from a manifest's `codec_params`, rejecting unknown keys.
    pub fn from_params(p: &Params) -> Result<Self> {
        let mut out = Zstd::default();
        for (k, v) in p {
            match k.as_str() {
                "level" => {
                    let lv = v.as_uint().ok_or_else(|| Error::BadCodecParam {
                        codec: ZSTD_ID,
                        param: k.clone(),
                        problem: "must be an unsigned integer".into(),
                    })?;
                    out = Zstd::new(lv)?;
                }
                "long" => {
                    let b = v.as_bool().ok_or_else(|| Error::BadCodecParam {
                        codec: ZSTD_ID,
                        param: k.clone(),
                        problem: "must be a boolean".into(),
                    })?;
                    if b {
                        return Err(Error::BadCodecParam {
                            codec: ZSTD_ID,
                            param: k.clone(),
                            problem: "long-distance matching is not implemented in v0".into(),
                        });
                    }
                    out.long = false;
                }
                _ => {
                    return Err(Error::UnknownCodecParam { codec: ZSTD_ID, param: k.clone() });
                }
            }
        }
        Ok(out)
    }
}

impl Codec for Zstd {
    fn id(&self) -> &'static str {
        ZSTD_ID
    }

    fn params(&self) -> Params {
        let mut p = Params::new();
        p.insert("level".into(), ParamValue::Uint(self.level));
        p.insert("long".into(), ParamValue::Bool(self.long));
        p
    }

    fn compress(&self, src: &[u8]) -> Result<Vec<u8>> {
        zstd::bulk::compress(src, self.level as i32).map_err(|e| Error::CodecFailure {
            codec: ZSTD_ID,
            problem: e.to_string(),
        })
    }

    fn decompress(&self, src: &[u8], dst: &mut [u8]) -> Result<()> {
        let n = zstd::bulk::decompress_to_buffer(src, dst).map_err(|e| Error::CodecFailure {
            codec: ZSTD_ID,
            problem: e.to_string(),
        })?;
        if n != dst.len() {
            return Err(Error::CodecLengthMismatch {
                codec: ZSTD_ID,
                produced: n,
                expected: dst.len(),
            });
        }
        Ok(())
    }

    fn max_expansion(&self, n: u64) -> u64 {
        // SPEC §10.2: the total bound is n + (n >> 8) + 64, so the expansion
        // beyond n is (n >> 8) + 64. This covers ZSTD_COMPRESSBOUND, whose
        // small-input term is at most 64.
        (n >> 8).saturating_add(64)
    }
}

// ---------------------------------------------------------------- none

pub const NONE_ID: &str = "none";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoCodec;

impl NoCodec {
    pub fn from_params(p: &Params) -> Result<Self> {
        if let Some((k, _)) = p.iter().next() {
            return Err(Error::UnknownCodecParam { codec: NONE_ID, param: k.clone() });
        }
        Ok(NoCodec)
    }
}

impl Codec for NoCodec {
    fn id(&self) -> &'static str {
        NONE_ID
    }

    fn params(&self) -> Params {
        Params::new()
    }

    fn compress(&self, src: &[u8]) -> Result<Vec<u8>> {
        Ok(src.to_vec())
    }

    fn decompress(&self, src: &[u8], dst: &mut [u8]) -> Result<()> {
        if src.len() != dst.len() {
            return Err(Error::CodecLengthMismatch {
                codec: NONE_ID,
                produced: src.len(),
                expected: dst.len(),
            });
        }
        dst.copy_from_slice(src);
        Ok(())
    }

    fn max_expansion(&self, _n: u64) -> u64 {
        0
    }
}

// ---------------------------------------------------------------- registry

/// Resolve a manifest's `codec` id plus `codec_params` into a codec.
///
/// An unknown id is rejected with the id named, per SPEC §10.1.
pub fn resolve(id: &str, params: &Params) -> Result<Box<dyn Codec>> {
    match id {
        ZSTD_ID => Ok(Box::new(Zstd::from_params(params)?)),
        NONE_ID => Ok(Box::new(NoCodec::from_params(params)?)),
        other => Err(Error::UnsupportedCodec(other.to_string())),
    }
}

/// Every codec id this build understands, for `nsif info` and error messages.
pub fn known_ids() -> &'static [&'static str] {
    &[ZSTD_ID, NONE_ID]
}
