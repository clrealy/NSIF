//! SPEC §7: the detached Ed25519 signature, its domain separation, and the
//! trust boundary in §7.2.

mod common;

use nsif_format::error::Error;
use nsif_format::payload::PayloadView;
use nsif_format::sig::{self, SignatureBlock};

#[test]
fn verifies_with_the_right_key() {
    let (bytes, _, _) = common::small_payload();
    let v = PayloadView::open(&bytes, bytes.len() as u64).unwrap();
    v.verify_signature(&common::public_key()).expect("valid signature");
}

#[test]
fn rejects_the_wrong_key() {
    let (bytes, _, _) = common::small_payload();
    let v = PayloadView::open(&bytes, bytes.len() as u64).unwrap();
    let e = v.verify_signature(&common::other_public_key()).unwrap_err();
    assert!(matches!(e, Error::SignatureInvalid), "{e}");
}

#[test]
fn rejects_a_tampered_manifest() {
    let (mut bytes, _, _) = common::small_payload();
    let v = PayloadView::open(&bytes, bytes.len() as u64).unwrap();
    let (moff, mlen) = (v.header.manifest_offset as usize, v.header.manifest_len as usize);
    let manifest_bytes = bytes[moff..moff + mlen].to_vec();
    let block = v.signature_block().unwrap();
    drop(v);

    // Flip a manifest byte and recompute the header hash, so the *signature* is
    // what catches the change rather than the BLAKE3 check.
    let mut tampered = manifest_bytes.clone();
    tampered[mlen / 2] ^= 0x01;
    bytes[moff..moff + mlen].copy_from_slice(&tampered);
    let new_hash = *blake3::hash(&tampered).as_bytes();
    let mut h = nsif_format::PayloadHeader::parse(&bytes).unwrap();
    h.manifest_hash = new_hash;
    bytes[..4096].copy_from_slice(&h.encode());

    let e = sig::verify(&common::public_key(), &block, 0, 1, &tampered).unwrap_err();
    assert!(matches!(e, Error::SignatureInvalid), "{e}");
}

/// The domain prefix and the length field are inside the signed message, so a
/// signature made for one version or length cannot be replayed for another.
#[test]
fn domain_separation_binds_version_and_length() {
    let manifest = b"some manifest bytes";
    let block = sig::sign(&common::SECRET, 0, 1, manifest);
    let pk = common::public_key();

    sig::verify(&pk, &block, 0, 1, manifest).expect("same inputs verify");

    // Different minor version.
    assert!(matches!(
        sig::verify(&pk, &block, 0, 2, manifest).unwrap_err(),
        Error::SignatureInvalid
    ));
    // Different major version.
    assert!(matches!(
        sig::verify(&pk, &block, 1, 1, manifest).unwrap_err(),
        Error::SignatureInvalid
    ));
    // Same bytes, shorter slice.
    assert!(matches!(
        sig::verify(&pk, &block, 0, 1, &manifest[..manifest.len() - 1]).unwrap_err(),
        Error::SignatureInvalid
    ));
}

#[test]
fn signed_message_has_the_specified_layout() {
    let m = sig::signed_message(0, 1, b"ab");
    let mut want = Vec::new();
    want.extend_from_slice(b"NSIF-SIG-v1\0");
    want.extend_from_slice(&0u16.to_le_bytes());
    want.extend_from_slice(&1u16.to_le_bytes());
    want.extend_from_slice(&2u64.to_le_bytes());
    want.extend_from_slice(b"ab");
    assert_eq!(m, want);
    assert_eq!(&m[..12], b"NSIF-SIG-v1\0");
}

#[test]
fn signature_block_round_trips() {
    let block = sig::sign(&common::SECRET, 0, 1, b"x");
    let encoded = block.encode();
    assert_eq!(encoded.len(), 128);
    assert_eq!(&encoded[0..4], b"NSG1");
    let back = SignatureBlock::parse(&encoded).unwrap();
    assert_eq!(block, back);
}

#[test]
fn rejects_malformed_signature_blocks() {
    let good = sig::sign(&common::SECRET, 0, 1, b"x").encode();

    let mut b = good;
    b[0] = b'X';
    assert!(matches!(SignatureBlock::parse(&b), Err(Error::BadSignatureBlock(_))));

    let mut b = good;
    b[4] = 9; // unknown algorithm
    assert!(matches!(SignatureBlock::parse(&b), Err(Error::UnsupportedSigAlgo(9))));

    let mut b = good;
    b[5] = 1; // reserved byte
    assert!(matches!(SignatureBlock::parse(&b), Err(Error::BadSignatureBlock(_))));

    let mut b = good;
    b[6..8].copy_from_slice(&32u16.to_le_bytes()); // wrong sig_len
    assert!(matches!(SignatureBlock::parse(&b), Err(Error::BadSignatureBlock(_))));

    let mut b = good;
    b[120] = 1; // reserved2
    assert!(matches!(SignatureBlock::parse(&b), Err(Error::BadSignatureBlock(_))));

    assert!(matches!(SignatureBlock::parse(&good[..64]), Err(Error::BadSignatureBlock(_))));
}

/// SPEC §7.2: the embedded key is informational. Verification must not fall
/// back to it, so an image signed by an attacker's key must fail against the
/// publisher's key even though the file carries the attacker's key.
#[test]
fn embedded_public_key_grants_no_authority() {
    let data = common::sample_rootfs(128 * 1024);
    let c = common::zstd();
    let (m, store) = common::manifest_for(&data, &c);
    // Signed with the "attacker" key; the block embeds that key.
    let bytes = nsif_format::payload::build(&m, &store.data, &common::OTHER_SECRET).unwrap();
    let v = PayloadView::open(&bytes, bytes.len() as u64).unwrap();
    let block = v.signature_block().unwrap();
    assert_eq!(block.public_key, common::other_public_key());

    // Self-consistent against its own embedded key...
    sig::verify(&block.public_key.clone(), &block, 0, 1, v.manifest_bytes).unwrap();
    // ...but rejected against the key the user actually trusts.
    let e = v.verify_signature(&common::public_key()).unwrap_err();
    assert!(matches!(e, Error::SignatureInvalid), "{e}");
}

#[test]
fn rejects_a_malformed_public_key() {
    let block = sig::sign(&common::SECRET, 0, 1, b"x");
    // All-zero is not a valid compressed Edwards point of the right order.
    let bad = [0u8; 32];
    let e = sig::verify(&bad, &block, 0, 1, b"x").unwrap_err();
    assert!(
        matches!(e, Error::MalformedPublicKey | Error::SignatureInvalid),
        "{e}"
    );
}

#[test]
fn key_fingerprint_is_stable() {
    let block = sig::sign(&common::SECRET, 0, 1, b"x");
    let a = block.key_fingerprint();
    let b = block.key_fingerprint();
    assert_eq!(a, b);
    assert_eq!(a.len(), 16, "8 bytes of hex");
}
