//! SPEC §5.1: the deterministic CBOR profile, and the round-trip property that
//! depends on it.

mod common;

use nsif_format::cbor::{key_cmp, MapWriter, Reader, Writer};
use nsif_format::manifest::Manifest;

#[test]
fn manifest_round_trips() {
    let (_, m, _) = common::small_payload();
    let bytes = m.encode().unwrap();
    let back = Manifest::decode(&bytes).unwrap();
    assert_eq!(m, back, "decode(encode(m)) must equal m");
}

/// The property that makes a second implementation checkable: re-encoding a
/// decoded manifest must reproduce the original bytes exactly.
#[test]
fn reencode_is_byte_identical() {
    let (_, m, _) = common::small_payload();
    let first = m.encode().unwrap();
    let decoded = Manifest::decode(&first).unwrap();
    let second = decoded.encode().unwrap();
    assert_eq!(first, second, "re-encoding must be byte-identical");
}

#[test]
fn encoding_is_stable_across_calls() {
    let (_, m, _) = common::small_payload();
    assert_eq!(m.encode().unwrap(), m.encode().unwrap());
}

/// SPEC §5.1.3 orders keys by their *encoded* bytes, which for keys shorter
/// than 24 bytes means length first, then content. This is not plain
/// alphabetical order, and getting it wrong is the easiest way to produce a
/// non-canonical manifest, so it is asserted explicitly.
#[test]
fn key_order_is_length_then_bytes_not_alphabetical() {
    // "name" (4 bytes) sorts before "build_date" (10 bytes) despite 'n' > 'b'.
    assert_eq!(key_cmp("name", "build_date"), std::cmp::Ordering::Less);
    // Same length falls back to byte order.
    assert_eq!(key_cmp("arch", "name"), std::cmp::Ordering::Less);
    assert_eq!(key_cmp("rootfs_hash", "rootfs_size"), std::cmp::Ordering::Less);
    // Plain alphabetical would put "arch" before "name" before "build_date"
    // wrongly; confirm the full top-level order the writer must produce.
    let mut keys: Vec<&str> = Manifest::top_level_keys().to_vec();
    keys.sort_by(|a, b| key_cmp(a, b));
    assert_eq!(
        keys,
        vec![
            "arch",
            "name",
            "codec",
            "chunks",
            "format",
            "cmdline",
            "version",
            "chunking",
            "metadata",
            "esp_files",
            "build_date",
            "rootfs_hash",
            "rootfs_size",
            "codec_params",
            "image_version",
            "rootfs_fstype",
            "version_ordinal",
        ]
    );
}

/// The encoded manifest's keys must appear in exactly that order on the wire.
#[test]
fn encoded_manifest_keys_are_sorted_on_the_wire() {
    let (_, m, _) = common::small_payload();
    let bytes = m.encode().unwrap();
    let mut seen: Vec<String> = Vec::new();
    let mut r = Reader::new(&bytes);
    r.map(|r, k| {
        seen.push(k.to_owned());
        skip_value(r)
    })
    .unwrap();
    let mut expect = seen.clone();
    expect.sort_by(|a, b| key_cmp(a, b));
    assert_eq!(seen, expect);
    assert_eq!(seen.len(), Manifest::top_level_keys().len());
}

/// Consume one value of any shape the v0 schema can contain.
fn skip_value(r: &mut Reader<'_>) -> nsif_format::Result<()> {
    match r.peek_major()? {
        0 => {
            r.uint()?;
        }
        2 => {
            r.bstr()?;
        }
        3 => {
            r.tstr()?;
        }
        4 => {
            let n = r.array_header()?;
            for _ in 0..n {
                skip_value(r)?;
            }
        }
        5 => {
            r.map(|r, _| skip_value(r))?;
        }
        7 => {
            r.boolean()?;
        }
        _ => panic!("unexpected major type"),
    }
    Ok(())
}

#[test]
fn writer_emits_shortest_form_heads() {
    let cases: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (255, &[0x18, 0xFF]),
        (256, &[0x19, 0x01, 0x00]),
        (65535, &[0x19, 0xFF, 0xFF]),
        (65536, &[0x1A, 0x00, 0x01, 0x00, 0x00]),
        (0xFFFF_FFFF, &[0x1A, 0xFF, 0xFF, 0xFF, 0xFF]),
        (0x1_0000_0000, &[0x1B, 0, 0, 0, 1, 0, 0, 0, 0]),
    ];
    for (v, want) in cases {
        let mut w = Writer::new();
        w.uint(*v);
        assert_eq!(w.as_bytes(), *want, "uint({v})");
    }
}

#[test]
fn map_writer_sorts_and_rejects_duplicates() {
    let mut m = MapWriter::new();
    m.entry("zzz", |w| w.uint(1));
    m.entry("a", |w| w.uint(2));
    m.entry("mm", |w| w.uint(3));
    let mut out = Writer::new();
    m.finish(&mut out).unwrap();
    // "a"(1) < "mm"(2) < "zzz"(3) by encoded length.
    assert_eq!(out.as_bytes(), &[0xA3, 0x61, b'a', 0x02, 0x62, b'm', b'm', 0x03, 0x63, b'z', b'z', b'z', 0x01]);

    let mut m = MapWriter::new();
    m.entry("dup", |w| w.uint(1));
    m.entry("dup", |w| w.uint(2));
    let mut out = Writer::new();
    assert!(m.finish(&mut out).is_err(), "duplicate keys must be rejected");
}

#[test]
fn reader_rejects_trailing_bytes() {
    let (_, m, _) = common::small_payload();
    let mut bytes = m.encode().unwrap();
    bytes.push(0x00);
    let err = Manifest::decode(&bytes).unwrap_err();
    assert!(
        matches!(err, nsif_format::Error::Cbor(nsif_format::CborError::TrailingBytes { .. })),
        "got {err}"
    );
}
