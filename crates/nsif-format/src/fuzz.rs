//! Fuzzing entry points.
//!
//! These exist so that the `cargo-fuzz` targets in `fuzz/` and the
//! stable-toolchain smoke test in `tests/fuzz_smoke.rs` drive **exactly** the
//! same code. The contract each one asserts is the same: for arbitrary input,
//! return either `Ok` or a typed [`crate::Error`] — never panic, never abort,
//! never allocate unboundedly.

use crate::manifest::Manifest;
use crate::validate;

/// Parse and range-validate a payload header from arbitrary bytes.
///
/// `partition_size` is derived from the input so the fuzzer explores both
/// "region fits" and "region overruns" paths.
pub fn header(data: &[u8]) -> crate::Result<()> {
    let h = crate::PayloadHeader::parse(data)?;
    // Two partition sizes: the buffer we actually have, and the value the
    // header claims, so both the bounded and the over-claimed paths are hit.
    let _ = h.validate_regions(data.len() as u64);
    h.validate_regions(h.payload_used_len)?;
    let _ = h.manifest_bytes(data);
    let _ = h.signature_bytes(data);
    Ok(())
}

/// Validate the CBOR profile, decode the manifest, and run every cross-field
/// invariant on arbitrary bytes.
pub fn manifest(data: &[u8]) -> crate::Result<()> {
    crate::cbor::validate_profile(data)?;
    let m = Manifest::decode(data)?;
    validate::manifest(&m, None)?;

    // A manifest that passed validation must re-encode to the same bytes.
    // Any divergence is a canonicality bug, which is a correctness bug for
    // signatures, so it is an assertion rather than an error return.
    let reencoded = m.encode()?;
    assert_eq!(
        reencoded, data,
        "a validated manifest must re-encode to identical bytes"
    );

    // And decoding the re-encoded form must round-trip.
    let again = Manifest::decode(&reencoded)?;
    assert_eq!(again, m, "decode(encode(m)) must equal m");
    Ok(())
}

/// Open a payload region from arbitrary bytes: header, manifest, signature
/// block and chunk-data bounds, all in the order SPEC §4.2 requires.
pub fn payload(data: &[u8]) -> crate::Result<()> {
    let v = crate::PayloadView::open(data, data.len() as u64)?;
    let _ = v.signature_block();
    let _ = v.chunk_data();
    Ok(())
}
