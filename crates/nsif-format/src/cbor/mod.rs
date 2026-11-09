//! Deterministic CBOR, restricted to the profile in SPEC §5.1.

pub mod reader;
pub mod writer;

pub use reader::{validate_profile, Reader};
pub use writer::{key_cmp, MapWriter, Writer};
