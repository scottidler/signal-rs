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

// --- Phase 6 (send-side) round-trip tests ---------------------------------
//
// upload::encrypt_attachment_blob is the inverse of verify_and_decrypt. Pinning
// the contract here means a refactor of either side that breaks the cipher
// format fails locally instead of on a live CDN.

use super::upload::{bucket_padded_size, encrypt_attachment_blob};

#[test]
fn encrypt_attachment_blob_round_trips_through_verify_and_decrypt() {
    let aes_key = [0xA1_u8; 32];
    let hmac_key = [0x9C_u8; 32];
    let iv = [0x71_u8; 16];

    let plaintext = b"phase 6 send-side payload".to_vec();
    let bucket = bucket_padded_size(plaintext.len());
    let mut padded = plaintext.clone();
    padded.resize(bucket, 0u8);

    let blob = encrypt_attachment_blob(&padded, &aes_key, &hmac_key, &iv);
    let digest = Sha256::digest(&blob).to_vec();

    let mut key_full = Vec::with_capacity(64);
    key_full.extend_from_slice(&aes_key);
    key_full.extend_from_slice(&hmac_key);

    let decrypted = verify_and_decrypt(&blob, &key_full, &digest).expect("send-side blob decrypts cleanly");

    // Decrypted is the padded plaintext; the receive path truncates to
    // pointer.size before writing dest. Verify the first plaintext.len()
    // bytes match and the trailing pad is the zero bytes we wrote.
    assert_eq!(&decrypted[..plaintext.len()], &plaintext[..]);
    assert_eq!(decrypted.len(), bucket);
    assert!(decrypted[plaintext.len()..].iter().all(|&b| b == 0));
}

#[test]
fn bucket_padded_size_floor_is_541() {
    // Bucket floor mirrors signal-cli's PaddingInputStream: anything
    // <= 541 bytes pads up to 541 bytes exactly, so a tiny send doesn't
    // tell the server "this was a one-character message".
    assert_eq!(bucket_padded_size(0), 541);
    assert_eq!(bucket_padded_size(1), 541);
    assert_eq!(bucket_padded_size(541), 541);
}

#[test]
fn bucket_padded_size_matches_signal_android_curve_at_known_points() {
    // Pin specific values against signal-android's
    // PaddingInputStream.getPaddedSize formula:
    //   max(541, floor(1.05 ^ ceil(log_1.05(size))))
    //
    // The values below were computed off the canonical Java formula
    // (note: `floor` on the outside, not `ceil`). If a future refactor
    // accidentally flips floor->ceil here, every signal-rs ciphertext
    // would land one byte above the canonical Signal bucket and become
    // fingerprintable as non-signal-android traffic on the CDN. These
    // tests pin the exact post-floor values to catch that regression.
    assert_eq!(bucket_padded_size(542), 568);
    assert_eq!(bucket_padded_size(1000), 1020);
    assert_eq!(bucket_padded_size(4096), 4201);
    assert_eq!(bucket_padded_size(65_536), 67_789);
    assert_eq!(bucket_padded_size(1_000_000), 1_041_743);
}

#[test]
fn bucket_padded_size_grows_monotonically_above_floor() {
    // Above the floor, the bucket grows on the 1.05^N curve. We don't
    // pin exact values (they're floating-point dependent) but require:
    // - strictly larger than the floor
    // - >= plaintext length (otherwise the encrypt would truncate)
    // - monotonically non-decreasing.
    let sizes = [542_usize, 1000, 4096, 65_536, 1_000_000];
    let mut prev = 541_usize;
    for s in sizes {
        let b = bucket_padded_size(s);
        assert!(b >= s, "bucket={b} < plaintext={s}");
        assert!(b >= prev, "bucket={b} < prev={prev} (not monotonic)");
        prev = b;
    }
}

#[test]
fn download_truncates_padded_plaintext_to_pointer_size() {
    // The Phase 6 send path pads plaintext up to a bucket. Phase 4
    // download must trust pointer.size and write only the unpadded
    // bytes to dest. This test exercises verify_and_decrypt + the
    // truncation contract directly on a hand-built bucket-padded blob.
    let aes_key = [0x37_u8; 32];
    let hmac_key = [0x5E_u8; 32];
    let iv = [0x99_u8; 16];

    let plaintext = b"five small bytes".to_vec();
    let bucket = bucket_padded_size(plaintext.len());
    let mut padded = plaintext.clone();
    padded.resize(bucket, 0u8);

    let blob = encrypt_attachment_blob(&padded, &aes_key, &hmac_key, &iv);
    let digest = Sha256::digest(&blob).to_vec();
    let mut key_full = Vec::with_capacity(64);
    key_full.extend_from_slice(&aes_key);
    key_full.extend_from_slice(&hmac_key);

    let mut decrypted = verify_and_decrypt(&blob, &key_full, &digest).unwrap();
    // Simulate Phase 4's truncation step.
    decrypted.truncate(plaintext.len());
    assert_eq!(decrypted, plaintext);
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
