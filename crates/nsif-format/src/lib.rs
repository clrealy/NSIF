//! # nsif-format
//!
//! The NSIF on-disk format: the payload header, the deterministic-CBOR
//! manifest, every validation rule, the codec registry, content-defined
//! chunking, and the detached Ed25519 signature.
//!
//! This crate performs **no I/O**. It takes and returns byte slices, which is
//! what lets the same code run in `nsif pack` and inside `nsif-boot`'s
//! initramfs without a filesystem.
//!
//! ## Trust
//!
//! The public key embedded in a signature block is informational only. Nothing
//! in this crate verifies a signature against it; [`sig::verify`] always takes
//! the key from the caller. See `SPEC.md` §7.2 and §12.
//!
//! ## Reading order
//!
//! The format requires checks in a specific order, because each step bounds the
//! next. [`validate::payload`] performs them correctly:
//!
//! 1. [`header::PayloadHeader::parse`] — magic, `header_len`, major version,
//!    CRC, then everything else.
//! 2. [`header::PayloadHeader::validate_regions`] — bounds, alignment,
//!    disjointness, caps.
//! 3. [`header::PayloadHeader::manifest_bytes`] — BLAKE3 against the header.
//! 4. [`manifest::Manifest::decode`] — the strict CBOR profile and field caps.
//! 5. [`validate::manifest`] — the cross-field invariants.

pub mod cbor;
pub mod chunker;
pub mod codec;
pub mod error;
pub mod fuzz;
pub mod guid;
pub mod header;
pub mod limits;
pub mod manifest;
pub mod payload;
pub mod sig;
pub mod validate;

pub use error::{CborError, Error, Result};
pub use guid::{Guid, ESP_TYPE, NSIF_PAYLOAD_TYPE, NSIF_PERSIST_TYPE};
pub use header::{PayloadHeader, MAGIC, VERSION_MAJOR, VERSION_MINOR};
pub use manifest::{Chunk, Chunking, EspFile, Manifest};
pub use payload::PayloadView;

/// The release codename of this format generation (SPEC §5.5).
pub const CODENAME: &str = "Hammer";
