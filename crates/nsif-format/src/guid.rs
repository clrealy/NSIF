//! GUIDs: the assigned partition type GUIDs (SPEC §3.3), the mixed-endian GPT
//! byte encoding, and the deterministic derivation from SPEC §11.1.

use core::fmt;

use crate::error::{Error, Result};

/// A GUID held in *string order*: the bytes in the order their hex digits are
/// printed. The GPT on-disk encoding is produced by [`Guid::to_gpt_bytes`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Guid(pub [u8; 16]);

/// Parse a canonical `8-4-4-4-12` GUID string at compile time.
///
/// Panics at compile time on a malformed literal, which is what we want for
/// the assigned constants below.
pub const fn guid(s: &str) -> Guid {
    let b = s.as_bytes();
    assert!(b.len() == 36, "GUID literal must be 36 characters");
    let mut out = [0u8; 16];
    let mut i = 0; // index into out
    let mut j = 0; // index into b
    while i < 16 {
        if b[j] == b'-' {
            j += 1;
            continue;
        }
        out[i] = hex_nibble(b[j]) << 4 | hex_nibble(b[j + 1]);
        i += 1;
        j += 2;
    }
    assert!(j == 36, "GUID literal has misplaced hyphens");
    Guid(out)
}

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("non-hex character in GUID literal"),
    }
}

/// EFI System Partition, defined by UEFI.
pub const ESP_TYPE: Guid = guid("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
/// NSIF payload partition, assigned by SPEC §3.3.
pub const NSIF_PAYLOAD_TYPE: Guid = guid("285621D5-0502-4ECF-9CEE-75F40014C6B3");
/// NSIF persistence partition, assigned by SPEC §3.3.
pub const NSIF_PERSIST_TYPE: Guid = guid("9A5B35C3-3C4D-4731-9E97-0936CC569006");

/// BLAKE3 derivation context for every GUID this format derives (SPEC §11.1).
const GUID_CONTEXT: &str = "nsif.v0.guid";

/// Derivation domains (SPEC §11.1).
pub const DOMAIN_DISK: &[u8] = b"nsif.disk";
pub const DOMAIN_PART_ESP: &[u8] = b"nsif.part.esp";
pub const DOMAIN_PART_PAYLOAD: &[u8] = b"nsif.part.payload";
pub const DOMAIN_PART_PERSIST: &[u8] = b"nsif.part.persist";
pub const DOMAIN_FAT_VOLID: &[u8] = b"nsif.fat.volid";

impl Guid {
    pub const ZERO: Guid = Guid([0u8; 16]);

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }

    /// Mixed-endian GPT encoding: the first three fields little-endian, the
    /// last two as-is (UEFI 2.10 appendix A).
    pub fn to_gpt_bytes(self) -> [u8; 16] {
        let s = self.0;
        [
            s[3], s[2], s[1], s[0], // time_low, LE
            s[5], s[4], // time_mid, LE
            s[7], s[6], // time_hi_and_version, LE
            s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15],
        ]
    }

    /// Inverse of [`Guid::to_gpt_bytes`].
    pub fn from_gpt_bytes(b: [u8; 16]) -> Self {
        Guid([
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13],
            b[14], b[15],
        ])
    }

    /// SPEC §11.1: derive a stable GUID from a domain plus the image identity.
    ///
    /// `material = domain || 0x00 || u64le(build_date) || name || 0x00 ||
    /// image_version || 0x00`
    pub fn derive(domain: &[u8], build_date: u64, name: &str, image_version: &str) -> Self {
        let mut material = Vec::with_capacity(domain.len() + name.len() + image_version.len() + 11);
        material.extend_from_slice(domain);
        material.push(0);
        material.extend_from_slice(&build_date.to_le_bytes());
        material.extend_from_slice(name.as_bytes());
        material.push(0);
        material.extend_from_slice(image_version.as_bytes());
        material.push(0);
        let key = blake3::derive_key(GUID_CONTEXT, &material);
        Self::from_random_bytes(&key[..16])
    }

    /// SPEC §8.1 step 6: the persistence partition GUID is derived at boot from
    /// the on-disk `DiskGUID`, so it needs no manifest.
    pub fn derive_from_disk(domain: &[u8], disk_guid: Guid) -> Self {
        let mut material = Vec::with_capacity(domain.len() + 17);
        material.extend_from_slice(domain);
        material.push(0);
        material.extend_from_slice(&disk_guid.0);
        let key = blake3::derive_key(GUID_CONTEXT, &material);
        Self::from_random_bytes(&key[..16])
    }

    /// Stamp 16 random bytes into a well-formed version-4 variant-1 UUID.
    pub fn from_random_bytes(b: &[u8]) -> Self {
        debug_assert!(b.len() >= 16);
        let mut out = [0u8; 16];
        out.copy_from_slice(&b[..16]);
        out[6] = (out[6] & 0x0F) | 0x40; // version 4
        out[8] = (out[8] & 0x3F) | 0x80; // variant 10x (RFC 4122)
        Guid(out)
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-\
             {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
            b[13], b[14], b[15]
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl core::str::FromStr for Guid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        if b.len() != 36 {
            return Err(Error::BadField {
                field: "guid",
                problem: format!("expected 36 characters, got {}", b.len()),
            });
        }
        let mut out = [0u8; 16];
        let mut i = 0;
        let mut j = 0;
        while i < 16 {
            if b[j] == b'-' {
                j += 1;
                continue;
            }
            if j + 1 >= b.len() {
                return Err(Error::BadField {
                    field: "guid",
                    problem: "truncated".to_string(),
                });
            }
            let hi = (b[j] as char).to_digit(16).ok_or_else(|| Error::BadField {
                field: "guid",
                problem: format!("non-hex character {:?}", b[j] as char),
            })?;
            let lo = (b[j + 1] as char).to_digit(16).ok_or_else(|| Error::BadField {
                field: "guid",
                problem: format!("non-hex character {:?}", b[j + 1] as char),
            })?;
            out[i] = ((hi << 4) | lo) as u8;
            i += 1;
            j += 2;
        }
        if j != 36 {
            return Err(Error::BadField {
                field: "guid",
                problem: "misplaced hyphens".to_string(),
            });
        }
        Ok(Guid(out))
    }
}
