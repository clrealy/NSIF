//! The detached Ed25519 signature block (SPEC §7).
//!
//! The public key stored in the block is **informational only**. Verification
//! always takes the key from the caller; see [`verify`] and SPEC §7.2.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::{Error, Result};
use crate::limits;

pub const SIG_MAGIC: [u8; 4] = *b"NSG1";
pub const SIG_ALGO_ED25519: u8 = 1;
pub const BLOCK_LEN: usize = limits::SIGNATURE_BLOCK_LEN as usize;

/// Domain-separation prefix (SPEC §7.1). The trailing NUL is part of it.
pub const SIG_DOMAIN: &[u8; 12] = b"NSIF-SIG-v1\0";

/// Build the exact byte string that gets signed (SPEC §7.1):
/// `"NSIF-SIG-v1\0" || u16le(major) || u16le(minor) || u64le(len) || manifest`
pub fn signed_message(version_major: u16, version_minor: u16, manifest: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + 12 + manifest.len());
    m.extend_from_slice(SIG_DOMAIN);
    m.extend_from_slice(&version_major.to_le_bytes());
    m.extend_from_slice(&version_minor.to_le_bytes());
    m.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
    m.extend_from_slice(manifest);
    m
}

/// The parsed signature block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBlock {
    pub algo: u8,
    /// Informational only. Never use this to verify. See SPEC §7.2.
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl SignatureBlock {
    pub fn encode(&self) -> [u8; BLOCK_LEN] {
        let mut b = [0u8; BLOCK_LEN];
        b[0..4].copy_from_slice(&SIG_MAGIC);
        b[4] = self.algo;
        b[5] = 0;
        b[6..8].copy_from_slice(&64u16.to_le_bytes());
        b[8..40].copy_from_slice(&self.public_key);
        b[40..104].copy_from_slice(&self.signature);
        b
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < BLOCK_LEN {
            return Err(Error::BadSignatureBlock(format!(
                "need {BLOCK_LEN} bytes, have {}",
                buf.len()
            )));
        }
        if buf[0..4] != SIG_MAGIC {
            return Err(Error::BadSignatureBlock(format!(
                "bad magic {:02x?}, expected \"NSG1\"",
                &buf[0..4]
            )));
        }
        let algo = buf[4];
        if algo != SIG_ALGO_ED25519 {
            return Err(Error::UnsupportedSigAlgo(algo));
        }
        if buf[5] != 0 {
            return Err(Error::BadSignatureBlock("reserved byte 5 must be zero".into()));
        }
        let sig_len = u16::from_le_bytes([buf[6], buf[7]]);
        if sig_len != 64 {
            return Err(Error::BadSignatureBlock(format!(
                "sig_len is {sig_len}, must be 64 for Ed25519"
            )));
        }
        if buf[104..BLOCK_LEN].iter().any(|&x| x != 0) {
            return Err(Error::BadSignatureBlock("reserved2 must be zero".into()));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&buf[8..40]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[40..104]);
        Ok(Self { algo, public_key, signature })
    }

    /// Fingerprint of the embedded key, for display. Carries no authority.
    pub fn key_fingerprint(&self) -> String {
        let h = blake3::hash(&self.public_key);
        hex::encode(&h.as_bytes()[..8])
    }
}

/// Sign a manifest. `secret` is the 32-byte Ed25519 seed.
pub fn sign(secret: &[u8; 32], version_major: u16, version_minor: u16, manifest: &[u8]) -> SignatureBlock {
    let sk = SigningKey::from_bytes(secret);
    let msg = signed_message(version_major, version_minor, manifest);
    let sig = sk.sign(&msg);
    SignatureBlock {
        algo: SIG_ALGO_ED25519,
        public_key: sk.verifying_key().to_bytes(),
        signature: sig.to_bytes(),
    }
}

/// Verify a manifest signature with a **caller-supplied** public key.
///
/// Uses `verify_strict`, which rejects non-canonical encodings and small-order
/// public keys, so one signature cannot be valid under more than one key
/// (SPEC §7.1).
pub fn verify(
    public_key: &[u8; 32],
    block: &SignatureBlock,
    version_major: u16,
    version_minor: u16,
    manifest: &[u8],
) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| Error::MalformedPublicKey)?;
    let sig = Signature::from_bytes(&block.signature);
    let msg = signed_message(version_major, version_minor, manifest);
    vk.verify_strict(&msg, &sig).map_err(|_| Error::SignatureInvalid)
}

/// Derive the public key from a 32-byte seed, for `nsif keygen`.
pub fn public_key_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}
