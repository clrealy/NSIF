//! SPEC §3.3 (assigned GUIDs, GPT encoding) and §11.1 (derivation).

use std::str::FromStr;

use nsif_format::guid::{self, Guid};

#[test]
fn assigned_guids_print_as_specified() {
    assert_eq!(guid::ESP_TYPE.to_string(), "C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    assert_eq!(
        guid::NSIF_PAYLOAD_TYPE.to_string(),
        "285621D5-0502-4ECF-9CEE-75F40014C6B3"
    );
    assert_eq!(
        guid::NSIF_PERSIST_TYPE.to_string(),
        "9A5B35C3-3C4D-4731-9E97-0936CC569006"
    );
}

/// SPEC §3.3 gives the expected on-disk bytes for the payload type GUID.
#[test]
fn gpt_encoding_matches_the_spec_example() {
    let want: [u8; 16] = [
        0xD5, 0x21, 0x56, 0x28, 0x02, 0x05, 0xCF, 0x4E, 0x9C, 0xEE, 0x75, 0xF4, 0x00, 0x14, 0xC6,
        0xB3,
    ];
    assert_eq!(guid::NSIF_PAYLOAD_TYPE.to_gpt_bytes(), want);
    assert_eq!(Guid::from_gpt_bytes(want), guid::NSIF_PAYLOAD_TYPE);
}

#[test]
fn gpt_encoding_round_trips() {
    for g in [guid::ESP_TYPE, guid::NSIF_PAYLOAD_TYPE, guid::NSIF_PERSIST_TYPE] {
        assert_eq!(Guid::from_gpt_bytes(g.to_gpt_bytes()), g);
    }
}

#[test]
fn string_parsing_round_trips() {
    for g in [guid::ESP_TYPE, guid::NSIF_PAYLOAD_TYPE, guid::NSIF_PERSIST_TYPE] {
        assert_eq!(Guid::from_str(&g.to_string()).unwrap(), g);
    }
    assert_eq!(
        Guid::from_str("285621d5-0502-4ecf-9cee-75f40014c6b3").unwrap(),
        guid::NSIF_PAYLOAD_TYPE,
        "parsing must be case-insensitive"
    );
}

#[test]
fn rejects_malformed_guid_strings() {
    for bad in [
        "",
        "285621D5-0502-4ECF-9CEE-75F40014C6B",
        "285621D5-0502-4ECF-9CEE-75F40014C6B33",
        "285621D5_0502_4ECF_9CEE_75F40014C6B3",
        "285621D5-0502-4ECF-9CEE-75F40014C6BZ",
    ] {
        assert!(Guid::from_str(bad).is_err(), "{bad:?} should be rejected");
    }
}

#[test]
fn derivation_is_deterministic() {
    let a = Guid::derive(guid::DOMAIN_DISK, 1_762_646_400, "NSIF Test", "0.1.0");
    let b = Guid::derive(guid::DOMAIN_DISK, 1_762_646_400, "NSIF Test", "0.1.0");
    assert_eq!(a, b);
}

#[test]
fn derivation_separates_domains_and_inputs() {
    let base = Guid::derive(guid::DOMAIN_DISK, 100, "x", "1");
    assert_ne!(base, Guid::derive(guid::DOMAIN_PART_ESP, 100, "x", "1"));
    assert_ne!(base, Guid::derive(guid::DOMAIN_PART_PAYLOAD, 100, "x", "1"));
    assert_ne!(base, Guid::derive(guid::DOMAIN_DISK, 101, "x", "1"));
    assert_ne!(base, Guid::derive(guid::DOMAIN_DISK, 100, "y", "1"));
    assert_ne!(base, Guid::derive(guid::DOMAIN_DISK, 100, "x", "2"));
}

/// The NUL separators must stop `name` and `image_version` from running
/// together: ("ab", "c") and ("a", "bc") must not collide.
#[test]
fn derivation_is_not_ambiguous_across_field_boundaries() {
    assert_ne!(
        Guid::derive(guid::DOMAIN_DISK, 0, "ab", "c"),
        Guid::derive(guid::DOMAIN_DISK, 0, "a", "bc")
    );
}

#[test]
fn derived_guids_are_well_formed_uuid4() {
    for i in 0..64u64 {
        let g = Guid::derive(guid::DOMAIN_DISK, i, "n", "v");
        assert_eq!(g.0[6] & 0xF0, 0x40, "version nibble must be 4");
        assert_eq!(g.0[8] & 0xC0, 0x80, "variant bits must be 10");
        assert!(!g.is_zero());
    }
}

#[test]
fn disk_derived_persistence_guid_is_stable_per_disk() {
    let disk = Guid::derive(guid::DOMAIN_DISK, 7, "n", "v");
    let a = Guid::derive_from_disk(guid::DOMAIN_PART_PERSIST, disk);
    let b = Guid::derive_from_disk(guid::DOMAIN_PART_PERSIST, disk);
    assert_eq!(a, b);
    let other = Guid::derive(guid::DOMAIN_DISK, 8, "n", "v");
    assert_ne!(a, Guid::derive_from_disk(guid::DOMAIN_PART_PERSIST, other));
}
