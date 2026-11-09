//! The hard limits from SPEC §9. Every one is a reject, never a clamp.

/// Payload header length, fixed in format 0.x.
pub const HEADER_LEN: u32 = 4096;

/// Largest manifest this implementation will read: 64 MiB.
pub const MAX_MANIFEST_LEN: u64 = 64 * 1024 * 1024;

/// Largest signature block: 4 KiB.
pub const MAX_SIGNATURE_LEN: u64 = 4096;

/// Exact size of the v0 Ed25519 signature block (SPEC §7).
pub const SIGNATURE_BLOCK_LEN: u64 = 128;

/// Largest number of chunks in one manifest: 2^22.
pub const MAX_CHUNKS: u64 = 4_194_304;

/// Smallest permitted uncompressed chunk length.
pub const MIN_CHUNK_ULEN: u64 = 1;

/// Largest permitted uncompressed chunk length: 16 MiB.
pub const MAX_CHUNK_ULEN: u64 = 16 * 1024 * 1024;

/// Absolute ceiling on a compressed chunk length, independent of the codec's
/// own expansion bound: 16 MiB + 64 KiB.
pub const MAX_CHUNK_CLEN: u64 = MAX_CHUNK_ULEN + 64 * 1024;

/// Largest rootfs image: 1 TiB.
pub const MAX_ROOTFS_SIZE: u64 = 1024 * 1024 * 1024 * 1024;

/// Largest number of ESP file entries.
pub const MAX_ESP_FILES: u64 = 65_536;

/// Longest ESP path, in bytes.
pub const MAX_ESP_PATH_LEN: usize = 1024;

/// Largest number of `metadata` entries.
pub const MAX_METADATA_ENTRIES: u64 = 64;

/// Longest `metadata` key, in bytes.
pub const MAX_METADATA_KEY_LEN: usize = 128;

/// Longest `metadata` value, in bytes.
pub const MAX_METADATA_VALUE_LEN: usize = 4096;

/// Largest number of `codec_params` entries.
pub const MAX_CODEC_PARAMS: u64 = 32;

/// Longest free-text manifest string field (`name`, `image_version`, `cmdline`).
pub const MAX_TEXT_FIELD_LEN: usize = 4096;

/// Maximum CBOR nesting depth.
pub const MAX_CBOR_DEPTH: u32 = 4;

/// Required alignment of the manifest, signature and chunk-data regions.
pub const REGION_ALIGN: u64 = 4096;

/// Chunking parameter bounds (SPEC §5.3.5), further narrowed by the limits of
/// the FastCDC implementation this crate uses.
pub const MIN_CHUNKING_MIN: u64 = 16 * 1024;
pub const MAX_CHUNKING_MAX: u64 = MAX_CHUNK_ULEN;
/// `fastcdc::v2020::MINIMUM_MAX`.
pub const CHUNKER_MIN_SIZE_CEILING: u64 = 1_048_576;
/// `fastcdc::v2020::AVERAGE_MAX`.
pub const CHUNKER_AVG_SIZE_CEILING: u64 = 4_194_304;
