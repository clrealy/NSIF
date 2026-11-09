//! The 4096-byte payload header (SPEC §4.1) and its mandatory range
//! validation (SPEC §4.2).

use crate::error::{Error, HexBytes, Result};
use crate::limits;

pub const MAGIC: [u8; 8] = *b"NSIFPAY\0";
pub const VERSION_MAJOR: u16 = 0;
pub const VERSION_MINOR: u16 = 1;

/// Byte offset of `header_crc32c` within the header.
const CRC_OFF: usize = 112;

/// Parsed payload header. All offsets are relative to the start of the payload
/// partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadHeader {
    pub version_major: u16,
    pub version_minor: u16,
    pub header_len: u32,
    pub manifest_offset: u64,
    pub manifest_len: u64,
    pub signature_offset: u64,
    pub signature_len: u64,
    pub chunk_data_offset: u64,
    pub chunk_data_len: u64,
    pub manifest_hash: [u8; 32],
    pub payload_used_len: u64,
    pub flags: u64,
}

impl PayloadHeader {
    /// Serialise to exactly `HEADER_LEN` bytes, computing the CRC.
    pub fn encode(&self) -> [u8; limits::HEADER_LEN as usize] {
        let mut b = [0u8; limits::HEADER_LEN as usize];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..10].copy_from_slice(&self.version_major.to_le_bytes());
        b[10..12].copy_from_slice(&self.version_minor.to_le_bytes());
        b[12..16].copy_from_slice(&self.header_len.to_le_bytes());
        b[16..24].copy_from_slice(&self.manifest_offset.to_le_bytes());
        b[24..32].copy_from_slice(&self.manifest_len.to_le_bytes());
        b[32..40].copy_from_slice(&self.signature_offset.to_le_bytes());
        b[40..48].copy_from_slice(&self.signature_len.to_le_bytes());
        b[48..56].copy_from_slice(&self.chunk_data_offset.to_le_bytes());
        b[56..64].copy_from_slice(&self.chunk_data_len.to_le_bytes());
        b[64..96].copy_from_slice(&self.manifest_hash);
        b[96..104].copy_from_slice(&self.payload_used_len.to_le_bytes());
        b[104..112].copy_from_slice(&self.flags.to_le_bytes());
        // bytes 112..116 stay zero while the CRC is computed
        let crc = crc32c::crc32c(&b[..self.header_len as usize]);
        b[CRC_OFF..CRC_OFF + 4].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Parse and check the header.
    ///
    /// Check order follows SPEC §4.1.1: only `magic`, `header_len` and
    /// `version_major` may be consulted before the CRC is verified.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < limits::HEADER_LEN as usize {
            return Err(Error::ShortBuffer {
                need: u64::from(limits::HEADER_LEN),
                have: buf.len() as u64,
            });
        }

        // 1. magic
        if buf[0..8] != MAGIC {
            return Err(Error::BadMagic { found: HexBytes::new(&buf[0..8]) });
        }

        // 2. header_len
        let header_len = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        if header_len != limits::HEADER_LEN {
            return Err(Error::BadHeaderLen { found: header_len, expected: limits::HEADER_LEN });
        }

        // 3. version_major
        let version_major = u16::from_le_bytes(buf[8..10].try_into().unwrap());
        let version_minor = u16::from_le_bytes(buf[10..12].try_into().unwrap());
        if version_major != VERSION_MAJOR {
            return Err(Error::UnsupportedVersion { major: version_major, minor: version_minor });
        }

        // 4. CRC, before anything else is trusted
        let stored = u32::from_le_bytes(buf[CRC_OFF..CRC_OFF + 4].try_into().unwrap());
        let mut scratch = buf[..header_len as usize].to_vec();
        scratch[CRC_OFF..CRC_OFF + 4].fill(0);
        let computed = crc32c::crc32c(&scratch);
        if stored != computed {
            return Err(Error::HeaderCrc { stored, computed });
        }

        // 5. version_minor: format 0.x makes no forward-compatibility promise
        if version_minor > VERSION_MINOR {
            return Err(Error::UnsupportedVersion { major: version_major, minor: version_minor });
        }

        // 6. reserved space must be zero
        if buf[116..128].iter().any(|&x| x != 0) {
            return Err(Error::ReservedNotZero { field: "reserved" });
        }
        if buf[128..header_len as usize].iter().any(|&x| x != 0) {
            return Err(Error::ReservedNotZero { field: "reserved2" });
        }

        let flags = u64::from_le_bytes(buf[104..112].try_into().unwrap());
        if flags != 0 {
            return Err(Error::UnknownFlags { bits: flags });
        }

        let mut manifest_hash = [0u8; 32];
        manifest_hash.copy_from_slice(&buf[64..96]);

        Ok(Self {
            version_major,
            version_minor,
            header_len,
            manifest_offset: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            manifest_len: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            signature_offset: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            signature_len: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            chunk_data_offset: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
            chunk_data_len: u64::from_le_bytes(buf[56..64].try_into().unwrap()),
            manifest_hash,
            payload_used_len: u64::from_le_bytes(buf[96..104].try_into().unwrap()),
            flags,
        })
    }

    /// The three declared regions, in a fixed order for error reporting.
    fn regions(&self) -> [(&'static str, u64, u64); 3] {
        [
            ("manifest", self.manifest_offset, self.manifest_len),
            ("signature", self.signature_offset, self.signature_len),
            ("chunk_data", self.chunk_data_offset, self.chunk_data_len),
        ]
    }

    /// SPEC §4.2 steps 1–4. `partition_size` is the payload partition size in
    /// bytes, taken from the GPT. Pass `u64::MAX` when validating a bare
    /// payload blob with no containing partition.
    pub fn validate_regions(&self, partition_size: u64) -> Result<()> {
        let hl = u64::from(self.header_len);
        let used = self.payload_used_len;

        // 1. payload_used_len
        if used > partition_size {
            return Err(Error::PayloadExceedsPartition { used, partition: partition_size });
        }
        if used < hl {
            return Err(Error::LimitBelow { what: "payload_used_len", value: used, min: hl });
        }

        // 4. caps first, so a wild length cannot drive a huge read
        if self.manifest_len > limits::MAX_MANIFEST_LEN {
            return Err(Error::LimitExceeded {
                what: "manifest_len",
                value: self.manifest_len,
                limit: limits::MAX_MANIFEST_LEN,
            });
        }
        if self.manifest_len == 0 {
            return Err(Error::LimitBelow { what: "manifest_len", value: 0, min: 1 });
        }
        if self.signature_len > limits::MAX_SIGNATURE_LEN {
            return Err(Error::LimitExceeded {
                what: "signature_len",
                value: self.signature_len,
                limit: limits::MAX_SIGNATURE_LEN,
            });
        }

        // 2. each region in bounds, aligned, and outside the header
        for (name, off, len) in self.regions() {
            if off < hl {
                return Err(Error::RegionInsideHeader { region: name, off, header_len: hl });
            }
            if off % limits::REGION_ALIGN != 0 {
                return Err(Error::Misaligned { region: name, off, align: limits::REGION_ALIGN });
            }
            let end = off
                .checked_add(len)
                .ok_or(Error::Overflow { what: "region offset + length" })?;
            if end > used {
                return Err(Error::RegionOutOfBounds { region: name, off, len, limit: used });
            }
        }

        // 3. pairwise disjoint
        let r = self.regions();
        for i in 0..r.len() {
            for j in (i + 1)..r.len() {
                let (an, ao, al) = r[i];
                let (bn, bo, bl) = r[j];
                if al == 0 || bl == 0 {
                    continue;
                }
                let ae = ao + al;
                let be = bo + bl;
                if ao < be && bo < ae {
                    return Err(Error::RegionOverlap {
                        a: an,
                        a_off: ao,
                        a_end: ae,
                        b: bn,
                        b_off: bo,
                        b_end: be,
                    });
                }
            }
        }
        Ok(())
    }

    /// SPEC §4.2 step 5. `payload` must be the payload partition contents, at
    /// least `payload_used_len` bytes long.
    pub fn manifest_bytes<'a>(&self, payload: &'a [u8]) -> Result<&'a [u8]> {
        let off = usize::try_from(self.manifest_offset)
            .map_err(|_| Error::Overflow { what: "manifest_offset as usize" })?;
        let len = usize::try_from(self.manifest_len)
            .map_err(|_| Error::Overflow { what: "manifest_len as usize" })?;
        let end = off.checked_add(len).ok_or(Error::Overflow { what: "manifest range" })?;
        if end > payload.len() {
            return Err(Error::ShortBuffer { need: end as u64, have: payload.len() as u64 });
        }
        let bytes = &payload[off..end];
        let actual = blake3::hash(bytes);
        if actual.as_bytes() != &self.manifest_hash {
            return Err(Error::ManifestHashMismatch {
                expected: HexBytes::new(self.manifest_hash),
                actual: HexBytes::new(actual.as_bytes()),
            });
        }
        Ok(bytes)
    }

    /// The signature block bytes, bounds-checked. No hash is involved; the
    /// signature authenticates the manifest, not itself.
    pub fn signature_bytes<'a>(&self, payload: &'a [u8]) -> Result<&'a [u8]> {
        let off = usize::try_from(self.signature_offset)
            .map_err(|_| Error::Overflow { what: "signature_offset as usize" })?;
        let len = usize::try_from(self.signature_len)
            .map_err(|_| Error::Overflow { what: "signature_len as usize" })?;
        let end = off.checked_add(len).ok_or(Error::Overflow { what: "signature range" })?;
        if end > payload.len() {
            return Err(Error::ShortBuffer { need: end as u64, have: payload.len() as u64 });
        }
        Ok(&payload[off..end])
    }
}
