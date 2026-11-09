//! The rejection suite. Every case asserts on a *specific* error variant, so a
//! test cannot pass merely because something failed.

mod common;

use nsif_format::cbor::validate_profile;
use nsif_format::codec::ParamValue;
use nsif_format::error::{CborError, Error};
use nsif_format::header::PayloadHeader;
use nsif_format::limits;
use nsif_format::manifest::Manifest;
use nsif_format::payload::{self, PayloadView};
use nsif_format::validate;

// ---------------------------------------------------------------- helpers

/// A minimal raw-CBOR builder that can deliberately emit non-conforming bytes.
#[derive(Default)]
struct Raw(Vec<u8>);

impl Raw {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn into_bytes(self) -> Vec<u8> {
        self.0
    }
    /// Shortest-form head.
    fn head(&mut self, major: u8, arg: u64) -> &mut Self {
        let m = major << 5;
        match arg {
            0..=23 => self.0.push(m | arg as u8),
            24..=0xFF => {
                self.0.push(m | 24);
                self.0.push(arg as u8);
            }
            0x100..=0xFFFF => {
                self.0.push(m | 25);
                self.0.extend_from_slice(&(arg as u16).to_be_bytes());
            }
            0x1_0000..=0xFFFF_FFFF => {
                self.0.push(m | 26);
                self.0.extend_from_slice(&(arg as u32).to_be_bytes());
            }
            _ => {
                self.0.push(m | 27);
                self.0.extend_from_slice(&arg.to_be_bytes());
            }
        }
        self
    }
    /// Head forced into a wider-than-necessary encoding.
    fn head_wide(&mut self, major: u8, arg: u64, ai: u8) -> &mut Self {
        let m = major << 5;
        self.0.push(m | ai);
        match ai {
            24 => self.0.push(arg as u8),
            25 => self.0.extend_from_slice(&(arg as u16).to_be_bytes()),
            26 => self.0.extend_from_slice(&(arg as u32).to_be_bytes()),
            27 => self.0.extend_from_slice(&arg.to_be_bytes()),
            _ => panic!("ai must be 24..=27"),
        }
        self
    }
    fn uint(&mut self, v: u64) -> &mut Self {
        self.head(0, v)
    }
    fn tstr(&mut self, s: &str) -> &mut Self {
        self.head(3, s.len() as u64);
        self.0.extend_from_slice(s.as_bytes());
        self
    }
    fn array(&mut self, n: u64) -> &mut Self {
        self.head(4, n)
    }
    fn map(&mut self, n: u64) -> &mut Self {
        self.head(5, n)
    }
    fn byte(&mut self, b: u8) -> &mut Self {
        self.0.push(b);
        self
    }
}

/// A valid payload, as bytes, with its partition size.
fn good_payload() -> Vec<u8> {
    let (bytes, _, _) = common::small_payload();
    bytes
}

/// Re-encode a header into an existing payload buffer.
fn put_header(buf: &mut [u8], h: &PayloadHeader) {
    buf[..limits::HEADER_LEN as usize].copy_from_slice(&h.encode());
}

/// Decode + validate a manifest struct, which is how semantic cases are driven.
fn check_manifest(m: &Manifest) -> Result<Manifest, Error> {
    let bytes = m.encode()?;
    let back = Manifest::decode(&bytes)?;
    validate::manifest(&back, None)?;
    Ok(back)
}

macro_rules! assert_err {
    ($expr:expr, $pat:pat) => {{
        let e = $expr.expect_err("expected an error");
        assert!(matches!(e, $pat), "wrong error variant: {e}");
        e
    }};
}

// ---------------------------------------------------------------- header

#[test]
fn rejects_bad_magic() {
    let mut p = good_payload();
    p[0] = b'X';
    assert_err!(PayloadHeader::parse(&p), Error::BadMagic { .. });
}

#[test]
fn rejects_short_buffer() {
    let p = good_payload();
    assert_err!(PayloadHeader::parse(&p[..100]), Error::ShortBuffer { .. });
}

#[test]
fn rejects_wrong_header_len() {
    let mut p = good_payload();
    p[12..16].copy_from_slice(&512u32.to_le_bytes());
    assert_err!(PayloadHeader::parse(&p), Error::BadHeaderLen { found: 512, .. });
}

#[test]
fn rejects_unknown_major_version() {
    let mut p = good_payload();
    p[8..10].copy_from_slice(&1u16.to_le_bytes());
    assert_err!(PayloadHeader::parse(&p), Error::UnsupportedVersion { major: 1, .. });
}

#[test]
fn rejects_future_minor_version() {
    let mut h = PayloadHeader::parse(&good_payload()).unwrap();
    let mut p = good_payload();
    h.version_minor = 2;
    put_header(&mut p, &h);
    assert_err!(PayloadHeader::parse(&p), Error::UnsupportedVersion { major: 0, minor: 2 });
}

#[test]
fn rejects_corrupt_header_crc() {
    let mut p = good_payload();
    // Flip a bit in manifest_offset without fixing the CRC.
    p[16] ^= 0x01;
    assert_err!(PayloadHeader::parse(&p), Error::HeaderCrc { .. });
}

#[test]
fn rejects_nonzero_reserved() {
    let mut p = good_payload();
    p[120] = 1; // inside reserved[116..128]
    // Recompute the CRC so the reserved check, not the CRC check, fires.
    let crc = {
        let mut scratch = p[..limits::HEADER_LEN as usize].to_vec();
        scratch[112..116].fill(0);
        crc32c::crc32c(&scratch)
    };
    p[112..116].copy_from_slice(&crc.to_le_bytes());
    assert_err!(PayloadHeader::parse(&p), Error::ReservedNotZero { field: "reserved" });
}

#[test]
fn rejects_nonzero_reserved2() {
    let mut p = good_payload();
    p[2048] = 0xFF;
    let crc = {
        let mut scratch = p[..limits::HEADER_LEN as usize].to_vec();
        scratch[112..116].fill(0);
        crc32c::crc32c(&scratch)
    };
    p[112..116].copy_from_slice(&crc.to_le_bytes());
    assert_err!(PayloadHeader::parse(&p), Error::ReservedNotZero { field: "reserved2" });
}

#[test]
fn rejects_unknown_flags() {
    let mut p = good_payload();
    let mut h = PayloadHeader::parse(&p).unwrap();
    h.flags = 0x8000_0000_0000_0000;
    put_header(&mut p, &h);
    assert_err!(PayloadHeader::parse(&p), Error::UnknownFlags { .. });
}

// ---------------------------------------------------------------- regions

#[test]
fn rejects_region_past_payload_end() {
    let p = good_payload();
    let mut h = PayloadHeader::parse(&p).unwrap();
    h.manifest_len = h.payload_used_len; // manifest_offset + this overruns
    assert_err!(
        h.validate_regions(p.len() as u64),
        Error::RegionOutOfBounds { region: "manifest", .. }
    );
}

#[test]
fn rejects_offset_length_overflow() {
    let p = good_payload();
    let mut h = PayloadHeader::parse(&p).unwrap();
    h.chunk_data_offset = (u64::MAX - 4095) & !4095; // stays 4096-aligned
    h.chunk_data_len = u64::MAX;
    let e = h.validate_regions(u64::MAX).unwrap_err();
    assert!(
        matches!(e, Error::Overflow { .. } | Error::RegionOutOfBounds { .. }),
        "wrong variant: {e}"
    );
}

#[test]
fn rejects_misaligned_region() {
    let p = good_payload();
    let mut h = PayloadHeader::parse(&p).unwrap();
    h.manifest_offset += 1;
    assert_err!(
        h.validate_regions(p.len() as u64),
        Error::Misaligned { region: "manifest", .. }
    );
}

#[test]
fn rejects_region_inside_header() {
    let p = good_payload();
    let mut h = PayloadHeader::parse(&p).unwrap();
    h.manifest_offset = 0;
    assert_err!(
        h.validate_regions(p.len() as u64),
        Error::RegionInsideHeader { region: "manifest", .. }
    );
}

#[test]
fn rejects_overlapping_regions() {
    let p = good_payload();
    let mut h = PayloadHeader::parse(&p).unwrap();
    // Point the signature at the manifest's first page.
    h.signature_offset = h.manifest_offset;
    assert_err!(h.validate_regions(p.len() as u64), Error::RegionOverlap { .. });
}

#[test]
fn rejects_manifest_len_over_cap() {
    let p = good_payload();
    let mut h = PayloadHeader::parse(&p).unwrap();
    h.manifest_len = limits::MAX_MANIFEST_LEN + 1;
    assert_err!(
        h.validate_regions(u64::MAX),
        Error::LimitExceeded { what: "manifest_len", .. }
    );
}

#[test]
fn rejects_zero_manifest_len() {
    let p = good_payload();
    let mut h = PayloadHeader::parse(&p).unwrap();
    h.manifest_len = 0;
    assert_err!(h.validate_regions(u64::MAX), Error::LimitBelow { what: "manifest_len", .. });
}

#[test]
fn rejects_payload_larger_than_partition() {
    let p = good_payload();
    let h = PayloadHeader::parse(&p).unwrap();
    assert_err!(
        h.validate_regions(h.payload_used_len - 1),
        Error::PayloadExceedsPartition { .. }
    );
}

#[test]
fn rejects_manifest_hash_mismatch() {
    let mut p = good_payload();
    let h = PayloadHeader::parse(&p).unwrap();
    // Corrupt one manifest byte; the header's stored hash no longer matches.
    p[h.manifest_offset as usize + 7] ^= 0xFF;
    assert_err!(h.manifest_bytes(&p), Error::ManifestHashMismatch { .. });
}

#[test]
fn rejects_truncated_payload() {
    let p = good_payload();
    let short = &p[..p.len() / 2];
    let e = PayloadView::open(short, short.len() as u64).unwrap_err();
    assert!(
        matches!(e, Error::RegionOutOfBounds { .. } | Error::PayloadExceedsPartition { .. }),
        "wrong variant: {e}"
    );
}

// ---------------------------------------------------------------- CBOR profile

#[test]
fn rejects_non_shortest_form() {
    let (_, m, _) = common::small_payload();
    let bytes = m.encode().unwrap();
    // "version" is encoded as 0x67 "version" followed by 0x01 (uint 1).
    let needle = {
        let mut v = vec![0x67u8];
        v.extend_from_slice(b"version");
        v.push(0x01);
        v
    };
    let at = find(&bytes, &needle).expect("version entry");
    let mut spliced = bytes.clone();
    // Replace the 1-byte uint with a 2-byte non-shortest encoding of 1.
    spliced.splice(at + needle.len() - 1..at + needle.len(), [0x18, 0x01]);
    assert_err!(
        validate_profile(&spliced),
        Error::Cbor(CborError::NonShortestForm { .. })
    );
}

#[test]
fn rejects_indefinite_length() {
    let mut r = Raw::new();
    r.map(1).tstr("a").byte(0x9F); // indefinite-length array
    assert_err!(
        validate_profile(&r.into_bytes()),
        Error::Cbor(CborError::IndefiniteLength { .. })
    );
}

#[test]
fn rejects_unsorted_map_keys() {
    // "arch" sorts before "name", so emitting name first is non-canonical.
    let mut r = Raw::new();
    r.map(2).tstr("name").tstr("x").tstr("arch").tstr("y");
    assert_err!(
        validate_profile(&r.into_bytes()),
        Error::Cbor(CborError::MapKeysUnsorted { .. })
    );
}

#[test]
fn rejects_duplicate_map_keys() {
    let mut r = Raw::new();
    r.map(2).tstr("arch").tstr("x").tstr("arch").tstr("y");
    assert_err!(
        validate_profile(&r.into_bytes()),
        Error::Cbor(CborError::DuplicateMapKey { .. })
    );
}

#[test]
fn rejects_floats() {
    let mut r = Raw::new();
    r.map(1).tstr("a").byte(0xFB); // float64 head
    for _ in 0..8 {
        r.byte(0);
    }
    assert_err!(
        validate_profile(&r.into_bytes()),
        Error::Cbor(CborError::FloatNotAllowed { .. })
    );
}

#[test]
fn rejects_tags() {
    let mut r = Raw::new();
    r.map(1).tstr("a").byte(0xC0).uint(1); // tag 0
    assert_err!(
        validate_profile(&r.into_bytes()),
        Error::Cbor(CborError::TagNotAllowed { .. })
    );
}

#[test]
fn rejects_null_and_undefined() {
    for b in [0xF6u8, 0xF7] {
        let mut r = Raw::new();
        r.map(1).tstr("a").byte(b);
        assert_err!(
            validate_profile(&r.into_bytes()),
            Error::Cbor(CborError::SimpleNotAllowed { .. })
        );
    }
}

#[test]
fn rejects_reserved_additional_info() {
    for ai in 28u8..=30 {
        let mut r = Raw::new();
        r.map(1).tstr("a").byte(ai); // major 0 with reserved ai
        assert_err!(
            validate_profile(&r.into_bytes()),
            Error::Cbor(CborError::ReservedAdditionalInfo { .. })
        );
    }
}

#[test]
fn rejects_nesting_deeper_than_four() {
    // map > array > array > array > array  == depth 5
    let mut r = Raw::new();
    r.map(1).tstr("a").array(1).array(1).array(1).array(1).uint(0);
    assert_err!(
        validate_profile(&r.into_bytes()),
        Error::Cbor(CborError::DepthExceeded { max: 4, .. })
    );
}

#[test]
fn accepts_nesting_exactly_four() {
    let mut r = Raw::new();
    r.map(1).tstr("a").array(1).array(1).array(1).uint(0);
    validate_profile(&r.into_bytes()).expect("depth 4 is legal");
}

#[test]
fn rejects_invalid_utf8() {
    let mut r = Raw::new();
    r.map(1).tstr("a");
    r.head(3, 2).byte(0xFF).byte(0xFE); // invalid UTF-8 text string
    assert_err!(
        validate_profile(&r.into_bytes()),
        Error::Cbor(CborError::InvalidUtf8 { .. })
    );
}

#[test]
fn rejects_non_text_map_key() {
    let mut r = Raw::new();
    r.map(1).uint(1).uint(2); // integer key
    assert_err!(
        validate_profile(&r.into_bytes()),
        Error::Cbor(CborError::UnexpectedMajor { .. })
    );
}

#[test]
fn rejects_length_beyond_input() {
    let mut r = Raw::new();
    r.map(1).tstr("a");
    r.head(2, 1_000_000); // byte string claiming a megabyte
    assert_err!(
        validate_profile(&r.into_bytes()),
        Error::Cbor(CborError::LengthBeyondInput { .. })
    );
}

#[test]
fn rejects_truncated_cbor() {
    let (_, m, _) = common::small_payload();
    let bytes = m.encode().unwrap();
    let e = validate_profile(&bytes[..bytes.len() - 1]).unwrap_err();
    assert!(
        matches!(
            e,
            Error::Cbor(CborError::Truncated { .. }) | Error::Cbor(CborError::LengthBeyondInput { .. })
        ),
        "wrong variant: {e}"
    );
}

#[test]
fn rejects_non_shortest_map_header() {
    let mut r = Raw::new();
    r.head_wide(5, 1, 24).tstr("a").uint(1);
    assert_err!(
        validate_profile(&r.into_bytes()),
        Error::Cbor(CborError::NonShortestForm { .. })
    );
}

// ---------------------------------------------------------------- manifest schema

#[test]
fn rejects_unknown_top_level_key() {
    let (_, m, _) = common::small_payload();
    let bytes = m.encode().unwrap();
    assert_eq!(bytes[0], 0xB0 | 17, "expected a 17-entry map header");
    let mut spliced = bytes.clone();
    spliced[0] = 0xB0 | 18;
    // A 16-byte key sorts after every real key (all are <= 15 bytes).
    spliced.push(0x70);
    spliced.extend_from_slice(b"zzzzzzzzzzzzzzzz");
    spliced.push(0x00);
    assert_err!(Manifest::decode(&spliced), Error::UnknownKey { .. });
}

#[test]
fn rejects_missing_key() {
    let (_, m, _) = common::small_payload();
    let bytes = m.encode().unwrap();
    // The last entry in canonical order is "version_ordinal".
    let needle = {
        let mut v = vec![0x6Fu8];
        v.extend_from_slice(b"version_ordinal");
        v
    };
    let at = find(&bytes, &needle).expect("version_ordinal entry");
    let mut spliced = bytes[..at].to_vec();
    spliced[0] = 0xB0 | 16;
    assert_err!(Manifest::decode(&spliced), Error::MissingKey { key: "version_ordinal" });
}

#[test]
fn rejects_wrong_format_string() {
    let (_, mut m, _) = common::small_payload();
    // `encode` always writes the constant, so patch the encoded bytes instead.
    let bytes = m.encode().unwrap();
    let needle = b"nsif-manifest";
    let at = find(&bytes, needle).expect("format value");
    let mut spliced = bytes.clone();
    spliced[at] = b'X';
    assert_err!(Manifest::decode(&spliced), Error::BadField { field: "format", .. });
    m.version = 1; // keep the binding used
}

#[test]
fn rejects_wrong_schema_version() {
    let (_, mut m, _) = common::small_payload();
    m.version = 2;
    assert_err!(check_manifest(&m), Error::BadField { field: "version", .. });
}

#[test]
fn rejects_wrong_arch() {
    let (_, mut m, _) = common::small_payload();
    m.arch = "aarch64".into();
    assert_err!(check_manifest(&m), Error::BadField { field: "arch", .. });
}

#[test]
fn rejects_unknown_codec() {
    let (_, mut m, _) = common::small_payload();
    m.codec = "lz4".into();
    m.codec_params.clear();
    assert_err!(check_manifest(&m), Error::UnsupportedCodec(_));
}

#[test]
fn rejects_unknown_codec_param() {
    let (_, mut m, _) = common::small_payload();
    m.codec_params.insert("window".into(), ParamValue::Uint(27));
    assert_err!(check_manifest(&m), Error::UnknownCodecParam { .. });
}

#[test]
fn rejects_zstd_level_out_of_range() {
    let (_, mut m, _) = common::small_payload();
    m.codec_params.insert("level".into(), ParamValue::Uint(99));
    let e = assert_err!(check_manifest(&m), Error::BadCodecParam { .. });
    assert!(e.to_string().contains("level"), "{e}");
}

#[test]
fn rejects_unknown_fstype() {
    let (_, mut m, _) = common::small_payload();
    m.rootfs_fstype = "btrfs".into();
    assert_err!(check_manifest(&m), Error::BadField { field: "rootfs_fstype", .. });
}

#[test]
fn rejects_empty_chunk_list() {
    let (_, mut m, _) = common::small_payload();
    m.chunks.clear();
    assert_err!(check_manifest(&m), Error::BadField { field: "chunks", .. });
}

#[test]
fn rejects_gap_between_chunks() {
    let (_, mut m, _) = common::small_payload();
    m.chunks[1].uoff += 1; // leaves a one-byte hole
    assert_err!(check_manifest(&m), Error::BadChunk { index: 1, .. });
}

#[test]
fn rejects_overlapping_uncompressed_ranges() {
    let (_, mut m, _) = common::small_payload();
    m.chunks[1].uoff -= 1; // overlaps chunk 0 by one byte
    assert_err!(check_manifest(&m), Error::BadChunk { index: 1, .. });
}

#[test]
fn rejects_rootfs_size_mismatch() {
    let (_, mut m, _) = common::small_payload();
    m.rootfs_size += 1;
    assert_err!(check_manifest(&m), Error::BadField { field: "rootfs_size", .. });
}

#[test]
fn rejects_zero_length_chunk() {
    let (_, mut m, _) = common::small_payload();
    let stolen = m.chunks[0].ulen;
    m.chunks[0].ulen = 0;
    m.chunks[1].uoff -= stolen;
    m.chunks[1].ulen += stolen;
    assert_err!(check_manifest(&m), Error::BadChunk { index: 0, .. });
}

#[test]
fn rejects_zero_length_compressed_extent() {
    let (_, mut m, _) = common::small_payload();
    m.chunks[0].clen = 0;
    assert_err!(check_manifest(&m), Error::BadChunk { index: 0, .. });
}

#[test]
fn rejects_clen_over_expansion_bound() {
    let (_, mut m, _) = common::small_payload();
    // Far beyond ulen + (ulen >> 8) + 64.
    m.chunks[0].clen = m.chunks[0].ulen * 2;
    assert_err!(check_manifest(&m), Error::BadChunk { index: 0, .. });
}

#[test]
fn rejects_chunk_extent_past_chunk_data() {
    let (bytes, _, _) = common::small_payload();
    let view = PayloadView::open(&bytes, bytes.len() as u64).unwrap();
    let mut m = view.manifest.clone();
    let last = m.chunks.len() - 1;
    m.chunks[last].coff = view.header.chunk_data_len; // starts at the very end
    let encoded = m.encode().unwrap();
    let back = Manifest::decode(&encoded).unwrap();
    assert_err!(
        validate::manifest(&back, Some(view.header.chunk_data_len)),
        Error::BadChunk { .. }
    );
}

#[test]
fn rejects_partially_overlapping_compressed_extents() {
    let (_, mut m, _) = common::small_payload();
    // Shift chunk 1's extent back by one byte so it straddles chunk 0's.
    assert!(m.chunks[0].clen > 2 && m.chunks[1].coff > 0);
    m.chunks[1].coff -= 1;
    assert_err!(check_manifest(&m), Error::ChunkExtentOverlap { .. });
}

#[test]
fn rejects_shared_extent_with_different_hash() {
    let (_, mut m, _) = common::small_payload();
    // Make chunk 1 point at chunk 0's extent while keeping its own hash.
    m.chunks[1].coff = m.chunks[0].coff;
    m.chunks[1].clen = m.chunks[0].clen;
    assert_err!(check_manifest(&m), Error::BadChunk { index: 1, .. });
}

#[test]
fn accepts_shared_extent_for_identical_chunks() {
    let (_, mut m, _) = common::small_payload();
    // Deduplication: identical hash *and* identical extent is legal.
    m.chunks[1].hash = m.chunks[0].hash;
    m.chunks[1].coff = m.chunks[0].coff;
    m.chunks[1].clen = m.chunks[0].clen;
    m.chunks[1].ulen = m.chunks[0].ulen;
    // Re-tile the uncompressed offsets after changing a length.
    let mut off = 0;
    let total: u64 = {
        for c in m.chunks.iter_mut() {
            c.uoff = off;
            off += c.ulen;
        }
        off
    };
    m.rootfs_size = total;
    check_manifest(&m).expect("a shared extent between identical chunks is legal");
}

#[test]
fn rejects_chunk_count_over_cap() {
    // An array header claiming more than 2^22 items, with enough bytes behind
    // it that the profile walk succeeds and the schema cap is what fires.
    let n = limits::MAX_CHUNKS + 1;
    let mut r = Raw::new();
    r.map(1).tstr("chunks").array(n);
    for _ in 0..n {
        r.uint(0);
    }
    let bytes = r.into_bytes();
    assert_err!(Manifest::decode(&bytes), Error::LimitExceeded { what: "chunk count", .. });
}

#[test]
fn rejects_malformed_chunk_tuple() {
    let mut r = Raw::new();
    r.map(1).tstr("chunks").array(1).array(4).uint(0).uint(0).uint(0).uint(0);
    assert_err!(Manifest::decode(&r.into_bytes()), Error::BadChunk { index: 0, .. });
}

#[test]
fn rejects_wrong_hash_length() {
    let mut r = Raw::new();
    r.map(1).tstr("chunks").array(1).array(5);
    r.head(2, 16); // 16-byte hash instead of 32
    for _ in 0..16 {
        r.byte(0);
    }
    r.uint(0).uint(1).uint(0).uint(1);
    assert_err!(
        Manifest::decode(&r.into_bytes()),
        Error::Cbor(CborError::WrongByteStringLength { expected: 32, .. })
    );
}

// ---------------------------------------------------------------- esp paths

#[test]
fn rejects_bad_esp_paths() {
    for bad in [
        "EFI/BOOT/BOOTX64.EFI",       // relative
        "/EFI/../BOOT/BOOTX64.EFI",   // parent component
        "/EFI/./BOOTX64.EFI",         // dot component
        "/EFI//BOOTX64.EFI",          // empty component
        "/EFI\\BOOT\\BOOTX64.EFI",    // backslash
        "/EFI/BOOT\0/X.EFI",          // NUL
        "",                           // empty
    ] {
        assert!(validate::esp_path(bad).is_err(), "{bad:?} should be rejected");
    }
    validate::esp_path("/EFI/BOOT/BOOTX64.EFI").expect("a clean path is accepted");
}

#[test]
fn rejects_case_insensitive_duplicate_esp_paths() {
    let (_, mut m, _) = common::small_payload();
    let mut dup = m.esp_files[0].clone();
    dup.path = dup.path.to_lowercase();
    m.esp_files.push(dup);
    assert_err!(check_manifest(&m), Error::BadEspFile { .. });
}

// ---------------------------------------------------------------- chunking params

#[test]
fn rejects_bad_chunking_params() {
    let (_, base, _) = common::small_payload();

    let mut m = base.clone();
    m.chunking.min = 1024; // below the 16 KiB floor
    assert_err!(check_manifest(&m), Error::BadChunkingParams(_));

    let mut m = base.clone();
    m.chunking.min = m.chunking.max + 2; // min > max
    assert_err!(check_manifest(&m), Error::BadChunkingParams(_));

    let mut m = base.clone();
    m.chunking.max = limits::MAX_CHUNKING_MAX + 2;
    assert_err!(check_manifest(&m), Error::BadChunkingParams(_));

    let mut m = base.clone();
    m.chunking.normalization = 4;
    assert_err!(check_manifest(&m), Error::BadChunkingParams(_));

    let mut m = base.clone();
    m.chunking.seed = 1;
    assert_err!(check_manifest(&m), Error::BadChunkingParams(_));

    let mut m = base.clone();
    m.chunking.min += 1; // odd
    assert_err!(check_manifest(&m), Error::BadChunkingParams(_));
}

// ---------------------------------------------------------------- pack-side guard

#[test]
fn payload_build_refuses_to_emit_an_invalid_manifest() {
    let data = common::sample_rootfs(128 * 1024);
    let c = common::zstd();
    let (mut m, store) = common::manifest_for(&data, &c);
    m.rootfs_size += 1; // now inconsistent with the chunk list
    assert_err!(
        payload::build(&m, &store.data, &common::SECRET),
        Error::BadField { field: "rootfs_size", .. }
    );
}

// ---------------------------------------------------------------- utility

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------- regressions

/// Found by `cargo fuzz run fuzz_manifest`: a CBOR negative integer (major
/// type 1) reached a major-type dispatch that had no arm for it. Both of the
/// inputs the fuzzer minimised to are kept here verbatim.
#[test]
fn rejects_negative_integers() {
    // map(1) { "a": -1 }
    assert_err!(
        validate_profile(&[0xA1, 0x61, b'a', 0x20]),
        Error::Cbor(CborError::NegativeIntNotAllowed { .. })
    );
    // a bare negative integer as the top-level item
    assert_err!(
        validate_profile(&[0x25, 0xA0, 0xA1]),
        Error::Cbor(CborError::NegativeIntNotAllowed { .. })
    );
    // and through the schema decoder
    assert_err!(
        Manifest::decode(&[0xA1, 0x61, b'a', 0x20]),
        Error::Cbor(CborError::NegativeIntNotAllowed { .. })
    );
    // every negative-integer head width
    for b in [0x20u8, 0x37, 0x38, 0x39, 0x3A, 0x3B] {
        let mut input = vec![0xA1, 0x61, b'a', b];
        input.extend_from_slice(&[0u8; 8]);
        assert_err!(
            validate_profile(&input),
            Error::Cbor(CborError::NegativeIntNotAllowed { .. })
        );
    }
}

/// No byte string of any length, fed to any parser entry point, may panic.
/// This is the stable-toolchain complement to the `cargo-fuzz` targets: it
/// drives the same `nsif_format::fuzz` entry points over a deterministic
/// pseudo-random sweep, so the no-panic contract is covered on every `cargo
/// test` run even without nightly.
#[test]
fn parsers_never_panic_on_arbitrary_input() {
    let good = good_payload();
    let (_, m, _) = common::small_payload();
    let manifest_bytes = m.encode().unwrap();

    let mut state: u64 = 0x5DEECE66D;
    let mut next = move || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        state >> 33
    };

    let mut cases: Vec<Vec<u8>> = Vec::new();

    // Truncations of valid inputs at many lengths.
    for seed in [&good[..], &manifest_bytes[..]] {
        for n in [0usize, 1, 2, 3, 4, 7, 8, 15, 16, 127, 128, 4095, 4096, 4097] {
            if n <= seed.len() {
                cases.push(seed[..n].to_vec());
            }
        }
    }

    // Single- and multi-byte mutations of valid inputs.
    for seed in [&good[..], &manifest_bytes[..]] {
        for _ in 0..3000 {
            let mut v = seed.to_vec();
            let flips = 1 + (next() % 6) as usize;
            for _ in 0..flips {
                let i = (next() as usize) % v.len();
                v[i] = (next() & 0xFF) as u8;
            }
            cases.push(v);
        }
    }

    // Pure noise, including lengths around the header size.
    for _ in 0..3000 {
        let len = (next() % 5000) as usize;
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push((next() & 0xFF) as u8);
        }
        cases.push(v);
    }

    // Noise that starts with the magic, so header parsing gets past byte 0.
    for _ in 0..2000 {
        let mut v = nsif_format::MAGIC.to_vec();
        for _ in 0..(4200 - 8) {
            v.push((next() & 0xFF) as u8);
        }
        cases.push(v);
    }

    for (i, c) in cases.iter().enumerate() {
        // Each call must return, with Ok or a typed Error. A panic fails here.
        let _ = nsif_format::fuzz::header(c);
        let _ = nsif_format::fuzz::manifest(c);
        let _ = nsif_format::fuzz::payload(c);
        let _ = validate_profile(c);
        let _ = Manifest::decode(c);
        assert!(i < cases.len());
    }
    assert!(cases.len() > 10_000, "sweep should be substantial, got {}", cases.len());
}
