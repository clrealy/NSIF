//! Error types for every rejection the format specification requires.
//!
//! Variants are deliberately fine-grained: the rejection test suite asserts on
//! specific variants, so a test cannot pass just because "something failed".

use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// Low-level CBOR decoding failures (SPEC §5.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CborError {
    #[error("truncated: needed {need} more byte(s) at offset {at}")]
    Truncated { at: usize, need: usize },
    #[error("indefinite-length item at offset {at} (SPEC 5.1.1)")]
    IndefiniteLength { at: usize },
    #[error("non-shortest-form head at offset {at}: value {value} encoded in {used} byte(s) (SPEC 5.1.2)")]
    NonShortestForm { at: usize, value: u64, used: u8 },
    #[error("reserved additional-information value {ai} at offset {at}")]
    ReservedAdditionalInfo { at: usize, ai: u8 },
    #[error("unexpected major type {found} at offset {at}, expected {expected}")]
    UnexpectedMajor { at: usize, found: u8, expected: &'static str },
    #[error("floating-point item at offset {at} (SPEC 5.1.5)")]
    FloatNotAllowed { at: usize },
    #[error("tag at offset {at} (SPEC 5.1.5)")]
    TagNotAllowed { at: usize },
    #[error("negative integer at offset {at}; no v0 field is signed (SPEC 5.1.5)")]
    NegativeIntNotAllowed { at: usize },
    #[error("simple value {value} at offset {at} is not allowed (SPEC 5.1.5)")]
    SimpleNotAllowed { at: usize, value: u8 },
    #[error("invalid UTF-8 in text string at offset {at} (SPEC 5.1.6)")]
    InvalidUtf8 { at: usize },
    #[error("map keys out of order at offset {at}: {later:?} must not follow {earlier:?} (SPEC 5.1.3)")]
    MapKeysUnsorted { at: usize, earlier: String, later: String },
    #[error("duplicate map key {key:?} at offset {at} (SPEC 5.1.4)")]
    DuplicateMapKey { at: usize, key: String },
    #[error("nesting deeper than {max} at offset {at} (SPEC 5.1.7)")]
    DepthExceeded { at: usize, max: u32 },
    #[error("{count} trailing byte(s) after the top-level item (SPEC 5.1.8)")]
    TrailingBytes { count: usize },
    #[error("item length {len} at offset {at} exceeds the remaining input ({remaining})")]
    LengthBeyondInput { at: usize, len: u64, remaining: usize },
    #[error("integer {value} at offset {at} does not fit in the target type")]
    IntegerTooLarge { at: usize, value: u64 },
    #[error("byte string at offset {at} is {found} byte(s), expected exactly {expected}")]
    WrongByteStringLength { at: usize, found: usize, expected: usize },
}

/// Everything that can make NSIF reject an image.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    // ---- payload header (SPEC §4.1) ----
    #[error("not an NSIF payload: magic is {found} (expected \"NSIFPAY\\0\")")]
    BadMagic { found: HexBytes },
    #[error("buffer too small: need {need} byte(s), have {have}")]
    ShortBuffer { need: u64, have: u64 },
    #[error("header_len is {found}, must be exactly {expected} in format 0.x (SPEC §4.1)")]
    BadHeaderLen { found: u32, expected: u32 },
    #[error("unsupported format version {major}.{minor}; this build implements 0.1 (SPEC §4.1.2)")]
    UnsupportedVersion { major: u16, minor: u16 },
    #[error("header CRC32C mismatch: stored {stored:#010x}, computed {computed:#010x} (SPEC §4.1.1)")]
    HeaderCrc { stored: u32, computed: u32 },
    #[error("reserved field `{field}` must be zero")]
    ReservedNotZero { field: &'static str },
    #[error("unknown flag bits set: {bits:#018x} (SPEC §4.1)")]
    UnknownFlags { bits: u64 },

    // ---- range validation (SPEC §4.2) ----
    #[error("integer overflow while computing {what}")]
    Overflow { what: &'static str },
    #[error("region `{region}` is out of bounds: offset {off} + length {len} exceeds {limit}")]
    RegionOutOfBounds { region: &'static str, off: u64, len: u64, limit: u64 },
    #[error("region `{region}` starts at {off}, inside the {header_len}-byte header")]
    RegionInsideHeader { region: &'static str, off: u64, header_len: u64 },
    #[error("region `{a}` ({a_off}..{a_end}) overlaps region `{b}` ({b_off}..{b_end}) (SPEC §4.2.3)")]
    RegionOverlap {
        a: &'static str,
        a_off: u64,
        a_end: u64,
        b: &'static str,
        b_off: u64,
        b_end: u64,
    },
    #[error("region `{region}` offset {off} is not {align}-byte aligned (SPEC §4)")]
    Misaligned { region: &'static str, off: u64, align: u64 },
    #[error("payload_used_len {used} exceeds the partition size {partition}")]
    PayloadExceedsPartition { used: u64, partition: u64 },

    // ---- limits (SPEC §9) ----
    #[error("{what} is {value}, over the limit of {limit} (SPEC §9)")]
    LimitExceeded { what: &'static str, value: u64, limit: u64 },
    #[error("{what} is {value}, under the minimum of {min} (SPEC §9)")]
    LimitBelow { what: &'static str, value: u64, min: u64 },

    // ---- integrity ----
    #[error("manifest hash mismatch: header declares {expected}, manifest bytes hash to {actual} (SPEC §4.2.5)")]
    ManifestHashMismatch { expected: HexBytes, actual: HexBytes },
    #[error("rootfs hash mismatch: manifest declares {expected}, chunks hash to {actual}")]
    RootfsHashMismatch { expected: HexBytes, actual: HexBytes },
    #[error("chunk {index} hash mismatch: manifest declares {expected}, data hashes to {actual}")]
    ChunkHashMismatch { index: usize, expected: HexBytes, actual: HexBytes },

    // ---- CBOR ----
    #[error("manifest CBOR: {0}")]
    Cbor(#[from] CborError),

    // ---- manifest semantics (SPEC §5.3) ----
    #[error("manifest is missing required key `{key}`")]
    MissingKey { key: &'static str },
    #[error("manifest has unknown top-level key {key:?}; format 0.x rejects unknown keys (SPEC §5.3.13)")]
    UnknownKey { key: String },
    #[error("manifest `{field}`: {problem}")]
    BadField { field: &'static str, problem: String },
    #[error("chunk {index}: {problem}")]
    BadChunk { index: usize, problem: String },
    #[error("chunks {a} and {b} have partially overlapping compressed extents: {a_off}..{a_end} vs {b_off}..{b_end} (SPEC §5.3.9)")]
    ChunkExtentOverlap {
        a: usize,
        b: usize,
        a_off: u64,
        a_end: u64,
        b_off: u64,
        b_end: u64,
    },
    #[error("esp_files[{index}]: {problem}")]
    BadEspFile { index: usize, problem: String },

    // ---- codecs (SPEC §10) ----
    #[error("unsupported codec {0:?} (SPEC §10.1)")]
    UnsupportedCodec(String),
    #[error("codec `{codec}`: unknown parameter {param:?}")]
    UnknownCodecParam { codec: &'static str, param: String },
    #[error("codec `{codec}`: parameter {param:?}: {problem}")]
    BadCodecParam { codec: &'static str, param: String, problem: String },
    #[error("codec `{codec}`: {problem}")]
    CodecFailure { codec: &'static str, problem: String },
    #[error("codec `{codec}` produced {produced} byte(s), expected exactly {expected} (SPEC §9)")]
    CodecLengthMismatch { codec: &'static str, produced: usize, expected: usize },

    // ---- chunking (SPEC §5.2 `chunking`) ----
    #[error("chunking parameters rejected: {0}")]
    BadChunkingParams(String),

    // ---- signature (SPEC §7) ----
    #[error("signature block: {0}")]
    BadSignatureBlock(String),
    #[error("unsupported signature algorithm {0}")]
    UnsupportedSigAlgo(u8),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("malformed public key")]
    MalformedPublicKey,
}

/// A byte string that prints as lowercase hex, so error messages are diffable.
#[derive(Clone, PartialEq, Eq)]
pub struct HexBytes(pub Vec<u8>);

impl HexBytes {
    pub fn new(b: impl AsRef<[u8]>) -> Self {
        Self(b.as_ref().to_vec())
    }
}

impl fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
