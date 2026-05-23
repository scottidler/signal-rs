//! verify_and_decrypt round-trips against a hand-built encrypted blob.
//! The cipher format is the contract that signal-cli (server-side) and
//! signal-rs (client-side) agree on; these tests pin our half so a future
//! refactor that breaks the layout fails locally rather than as a CDN
//! download silently producing garbage plaintext.

use super::*;

use aes::Aes256;
use cbc::Encryptor;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use hmac::Mac;
use sha2::{Digest, Sha256};

type Aes256CbcEnc = Encryptor<Aes256>;

fn encrypt_attachment(plaintext: &[u8], aes_key: &[u8], hmac_key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256CbcEnc::new_from_slices(aes_key, iv).unwrap();
    // PKCS#7 needs room for a full block of padding past the plaintext.
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ciphertext = cipher
        .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
        .unwrap()
        .to_vec();

    let mut signed = Vec::with_capacity(iv.len() + ciphertext.len() + 32);
    signed.extend_from_slice(iv);
    signed.extend_from_slice(&ciphertext);

    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(hmac_key).unwrap();
    mac.update(&signed);
    let mac_bytes = mac.finalize().into_bytes();

    signed.extend_from_slice(&mac_bytes);
    signed
}

#[test]
fn verify_and_decrypt_round_trips_a_hand_built_blob() {
    let aes_key = [0xAA_u8; 32];
    let hmac_key = [0x55_u8; 32];
    let iv = [0x11_u8; 16];
    let plaintext = b"hello attachment world".to_vec();

    let mut attachment_key = Vec::with_capacity(64);
    attachment_key.extend_from_slice(&aes_key);
    attachment_key.extend_from_slice(&hmac_key);

    let blob = encrypt_attachment(&plaintext, &aes_key, &hmac_key, &iv);
    let digest = Sha256::digest(&blob).to_vec();

    let decrypted = verify_and_decrypt(&blob, &attachment_key, &digest).expect("HMAC + digest + decrypt all pass");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn verify_and_decrypt_rejects_hmac_tampering() {
    let aes_key = [0xAA_u8; 32];
    let hmac_key = [0x55_u8; 32];
    let iv = [0x11_u8; 16];
    let plaintext = b"hello attachment world".to_vec();

    let mut attachment_key = Vec::with_capacity(64);
    attachment_key.extend_from_slice(&aes_key);
    attachment_key.extend_from_slice(&hmac_key);

    let mut blob = encrypt_attachment(&plaintext, &aes_key, &hmac_key, &iv);
    // Flip a single bit in the ciphertext.
    let tamper_idx = blob.len() / 2;
    blob[tamper_idx] ^= 0x01;

    let err = verify_and_decrypt(&blob, &attachment_key, &[]).expect_err("HMAC must reject tampered ciphertext");
    assert!(matches!(err, AttachmentError::HmacMismatch));
}

#[test]
fn verify_and_decrypt_rejects_digest_mismatch() {
    let aes_key = [0xAA_u8; 32];
    let hmac_key = [0x55_u8; 32];
    let iv = [0x11_u8; 16];
    let plaintext = b"hello attachment world".to_vec();

    let mut attachment_key = Vec::with_capacity(64);
    attachment_key.extend_from_slice(&aes_key);
    attachment_key.extend_from_slice(&hmac_key);

    let blob = encrypt_attachment(&plaintext, &aes_key, &hmac_key, &iv);
    let wrong_digest = vec![0xDE_u8; 32];

    let err = verify_and_decrypt(&blob, &attachment_key, &wrong_digest)
        .expect_err("digest mismatch must be reported even if HMAC passes");
    assert!(matches!(err, AttachmentError::DigestMismatch));
}

#[test]
fn verify_and_decrypt_skips_digest_check_when_expected_is_empty() {
    let aes_key = [0xAA_u8; 32];
    let hmac_key = [0x55_u8; 32];
    let iv = [0x11_u8; 16];
    let plaintext = b"empty-digest-ok".to_vec();

    let mut attachment_key = Vec::with_capacity(64);
    attachment_key.extend_from_slice(&aes_key);
    attachment_key.extend_from_slice(&hmac_key);

    let blob = encrypt_attachment(&plaintext, &aes_key, &hmac_key, &iv);

    let decrypted = verify_and_decrypt(&blob, &attachment_key, &[]).expect("empty expected_digest skips check");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn verify_and_decrypt_rejects_blob_too_small() {
    let attachment_key = vec![0u8; 64];
    let blob = vec![0u8; 32];
    let err = verify_and_decrypt(&blob, &attachment_key, &[]).expect_err("blob below minimum size must be rejected");
    assert!(matches!(err, AttachmentError::BlobTooSmall(32)));
}

#[test]
fn verify_and_decrypt_rejects_wrong_key_len() {
    let attachment_key = vec![0u8; 63];
    let blob = vec![0u8; 100];
    let err = verify_and_decrypt(&blob, &attachment_key, &[]).expect_err("key below required len must be rejected");
    assert!(matches!(
        err,
        AttachmentError::BadKeyLen {
            expected: 64,
            actual: 63
        }
    ));
}

#[test]
fn build_cdn_url_dispatches_by_cdn_number() {
    let mut p = AttachmentPointer {
        cdn_id: 42,
        cdn_key: Some("foo".to_string()),
        cdn_number: 0,
        content_type: None,
        size: None,
        digest: Vec::new(),
        key: Vec::new(),
        file_name: None,
        caption: None,
        width: None,
        height: None,
        voice_note: false,
        borderless: false,
        gif: false,
        upload_timestamp: None,
        blurhash: None,
    };
    assert_eq!(
        super::build_cdn_url(&p).unwrap(),
        "https://cdn.signal.org/attachments/42"
    );
    p.cdn_number = 2;
    assert_eq!(
        super::build_cdn_url(&p).unwrap(),
        "https://cdn2.signal.org/attachments/foo"
    );
    p.cdn_number = 3;
    assert_eq!(
        super::build_cdn_url(&p).unwrap(),
        "https://cdn3.signal.org/attachments/foo"
    );
    p.cdn_number = 5;
    assert!(matches!(
        super::build_cdn_url(&p).expect_err("unsupported cdn rejected"),
        AttachmentError::UnsupportedCdn(5)
    ));
}
