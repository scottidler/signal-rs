use super::*;
use libsignal_protocol::IdentityKeyPair;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Deterministic round-trip. Generates a fixed identity keypair from a
/// seeded RNG, encrypts a name with a separate fixed ephemeral keypair,
/// decrypts using only the identity keypair (no shared state with the
/// encrypt side), asserts the plaintext matches.
#[test]
fn round_trip_with_seeded_keys() {
    let mut id_rng = ChaCha20Rng::seed_from_u64(0x1234_5678_9abc_def0);
    let identity = IdentityKeyPair::generate(&mut id_rng);

    let mut eph_rng = ChaCha20Rng::seed_from_u64(0xfedc_ba98_7654_3210);
    let ephemeral = KeyPair::generate(&mut eph_rng);

    let plaintext = "signal-rs phone-on-the-couch";
    let encrypted = encrypt_device_name_with(plaintext.as_bytes(), &identity, &ephemeral).unwrap();
    let decrypted = decrypt_device_name(&encrypted, &identity).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Plaintext that crosses the 16-byte AES block boundary. Catches the
/// "wrong counter endianness" class of bug: with `Ctr128LE` the second
/// block decrypts to different bytes than with `Ctr128BE`. (Pure
/// counter-width bugs — `Ctr32BE` vs `Ctr128BE` — produce the same
/// keystream when IV=zero and the message is short, so they are NOT
/// caught here; only the phone-UI smoke in Phase 10 truly validates
/// that.) Round-tripping ≥17 bytes is the simplest way to surface the
/// endianness discrepancy without a Java cross-check vector.
#[test]
fn round_trip_crosses_aes_block_boundary() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let identity = IdentityKeyPair::generate(&mut rng);
    let plaintext = "0123456789abcdefxxxxxxxx"; // 24 bytes, crosses one block
    let encrypted = encrypt_device_name(plaintext, &identity).unwrap();
    let decrypted = decrypt_device_name(&encrypted, &identity).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Encrypt output is base64 of a `DeviceName` protobuf with the
/// expected field shapes: 33-byte type-prefixed ephemeral pub
/// (`0x05 || raw32`), 16-byte synthetic IV, ciphertext length ==
/// plaintext length. Catches the "encoded raw 32-byte ephemeralPublic
/// instead of serialize()'s 33-byte form" bug that would leave the
/// primary device unable to decrypt.
#[test]
fn wire_shape_matches_signal_android() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let identity = IdentityKeyPair::generate(&mut rng);
    let plaintext = "signal-rs";

    let encrypted = encrypt_device_name(plaintext, &identity).unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.decode(&encrypted).unwrap();
    let msg = proto::DeviceName::decode(&*encoded).unwrap();

    let eph = msg.ephemeral_public.as_ref().unwrap();
    assert_eq!(eph.len(), 33, "ephemeralPublic must be 33-byte type-prefixed form");
    assert_eq!(eph[0], 0x05, "ephemeralPublic must carry curve25519 type byte 0x05");

    assert_eq!(msg.synthetic_iv.as_ref().unwrap().len(), 16);
    assert_eq!(
        msg.ciphertext.as_ref().unwrap().len(),
        plaintext.len(),
        "AES-CTR ciphertext length must equal plaintext length"
    );
}

/// Tampering the ciphertext after encrypt must cause decrypt to fail
/// the synthetic-IV verification step. Without this guarantee a hostile
/// primary device could pin an arbitrary string on the linked-devices
/// UI of the secondary's own status output.
#[test]
fn tampered_ciphertext_is_rejected() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let identity = IdentityKeyPair::generate(&mut rng);

    let encrypted = encrypt_device_name("legit-name", &identity).unwrap();
    let mut encoded = base64::engine::general_purpose::STANDARD.decode(&encrypted).unwrap();
    let mut msg = proto::DeviceName::decode(&*encoded).unwrap();
    // Flip a byte in the middle of the ciphertext.
    if let Some(ct) = msg.ciphertext.as_mut() {
        let mid = ct.len() / 2;
        ct[mid] ^= 0x01;
    }
    encoded = msg.encode_to_vec();
    let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(encoded);

    let err = decrypt_device_name(&tampered_b64, &identity).unwrap_err();
    assert!(matches!(err, DeviceNameError::SyntheticIvMismatch));
}

/// The wrong identity keypair must fail decryption. Cross-account
/// device-name leakage would be a privacy regression.
#[test]
fn wrong_identity_keypair_fails() {
    let mut rng_a = ChaCha20Rng::seed_from_u64(100);
    let identity_a = IdentityKeyPair::generate(&mut rng_a);
    let mut rng_b = ChaCha20Rng::seed_from_u64(200);
    let identity_b = IdentityKeyPair::generate(&mut rng_b);

    let encrypted = encrypt_device_name("name-for-a", &identity_a).unwrap();
    let result = decrypt_device_name(&encrypted, &identity_b);
    assert!(result.is_err(), "decrypt with wrong identity must fail");
}
