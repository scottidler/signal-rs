use super::*;
use aes::Aes256;
use cbc::Encryptor;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use libsignal_protocol::KeyPair;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

type Aes256CbcEnc = Encryptor<Aes256>;

fn cbc_encrypt(aes_key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let enc = Aes256CbcEnc::new_from_slices(aes_key, iv).unwrap();
    // encrypt_padded needs a buffer with room for one extra block of padding.
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    enc.encrypt_padded::<Pkcs7>(&mut buf, plaintext.len()).unwrap().to_vec()
}

/// Build a valid encrypted ProvisionEnvelope from a known plaintext.
///
/// Mirrors signal-service-android's `ProvisioningCipher` send-side logic so
/// we can exercise the decrypt path end-to-end without a real linking session.
fn make_envelope(
    our_recipient_pub: &PublicKey,
    sender: &KeyPair,
    plaintext: &ProvisionMessage,
    iv: [u8; 16],
) -> Vec<u8> {
    let shared = sender
        .private_key
        .calculate_agreement(our_recipient_pub)
        .expect("agreement")
        .to_vec();

    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut keys = [0u8; 64];
    hk.expand(PROVISIONING_INFO, &mut keys).unwrap();
    let (aes_key, mac_key) = keys.split_at(32);

    let plaintext_bytes = plaintext.encode_to_vec();
    let ciphertext = cbc_encrypt(aes_key, &iv, &plaintext_bytes);

    let mut body = Vec::with_capacity(1 + 16 + ciphertext.len() + 32);
    body.push(1u8); // version
    body.extend_from_slice(&iv);
    body.extend_from_slice(&ciphertext);

    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(mac_key).unwrap();
    mac.update(&body);
    let mac_tag = mac.finalize().into_bytes();
    body.extend_from_slice(&mac_tag);

    let envelope = ProvisionEnvelope {
        public_key: Some(sender.public_key.serialize().to_vec()),
        body: Some(body),
    };
    envelope.encode_to_vec()
}

fn sample_message() -> ProvisionMessage {
    ProvisionMessage {
        aci_identity_key_public: Some(vec![0x05; 33]),
        aci_identity_key_private: Some(vec![0xAA; 32]),
        pni_identity_key_public: Some(vec![0x05; 33]),
        pni_identity_key_private: Some(vec![0xBB; 32]),
        aci: Some("11111111-2222-3333-4444-555555555555".into()),
        pni: Some("66666666-7777-8888-9999-aaaaaaaaaaaa".into()),
        number: Some("+15555555555".into()),
        provisioning_code: Some("ABCDEFGH".into()),
        user_agent: Some("signal-rs-test".into()),
        profile_key: Some(vec![0xCD; 32]),
        read_receipts: Some(true),
        provisioning_version: Some(1),
        ephemeral_backup_key: Some(vec![0xEF; 32]),
        account_entropy_pool: Some("entropy-pool".into()),
        media_root_backup_key: Some(vec![0x10; 32]),
        aci_binary: Some(vec![0x11; 16]),
        pni_binary: Some(vec![0x22; 16]),
    }
}

fn rng_seeded(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// Round-trip: encrypt with the test sender, decrypt with our receiver.
/// Stands in for the "known plaintext/ciphertext vector" Phase 10 will capture.
#[test]
fn happy_path_round_trip_with_synthesized_envelope() {
    let recipient = ProvisioningKeyPair::generate(&mut rng_seeded(1));
    let sender = KeyPair::generate(&mut rng_seeded(2));
    let msg = sample_message();
    let iv: [u8; 16] = [0x77; 16];
    let envelope_bytes = make_envelope(&recipient.key_pair().public_key, &sender, &msg, iv);

    let decrypted = decrypt_envelope(&recipient, &envelope_bytes).expect("decrypt");
    assert_eq!(decrypted.number, msg.number);
    assert_eq!(decrypted.account_entropy_pool, msg.account_entropy_pool);
    assert_eq!(decrypted.profile_key, msg.profile_key);
}

#[test]
fn mac_bit_flip_in_ciphertext_is_rejected_as_mac_mismatch() {
    let recipient = ProvisioningKeyPair::generate(&mut rng_seeded(1));
    let sender = KeyPair::generate(&mut rng_seeded(2));
    let msg = sample_message();
    let mut envelope_bytes = make_envelope(&recipient.key_pair().public_key, &sender, &msg, [0x88; 16]);

    let envelope = ProvisionEnvelope::decode(envelope_bytes.as_slice()).unwrap();
    let mut body = envelope.body.unwrap();
    // Flip a bit inside the ciphertext region (skip version(1) + iv(16)).
    body[1 + 16 + 5] ^= 0x01;
    let modified = ProvisionEnvelope {
        public_key: envelope.public_key,
        body: Some(body),
    };
    envelope_bytes = modified.encode_to_vec();

    match decrypt_envelope(&recipient, &envelope_bytes) {
        Err(ProvisioningCipherError::MacMismatch) => {}
        other => panic!("expected MacMismatch, got {:?}", other),
    }
}

#[test]
fn mac_bit_flip_in_iv_is_rejected_as_mac_mismatch() {
    let recipient = ProvisioningKeyPair::generate(&mut rng_seeded(1));
    let sender = KeyPair::generate(&mut rng_seeded(2));
    let msg = sample_message();
    let mut envelope_bytes = make_envelope(&recipient.key_pair().public_key, &sender, &msg, [0x33; 16]);

    let envelope = ProvisionEnvelope::decode(envelope_bytes.as_slice()).unwrap();
    let mut body = envelope.body.unwrap();
    body[1] ^= 0x80;
    let modified = ProvisionEnvelope {
        public_key: envelope.public_key,
        body: Some(body),
    };
    envelope_bytes = modified.encode_to_vec();

    match decrypt_envelope(&recipient, &envelope_bytes) {
        Err(ProvisioningCipherError::MacMismatch) => {}
        other => panic!("expected MacMismatch (IV is MAC-covered), got {:?}", other),
    }
}

#[test]
fn wrong_recipient_keypair_fails_with_mac_mismatch() {
    let real_recipient = ProvisioningKeyPair::generate(&mut rng_seeded(1));
    let wrong_recipient = ProvisioningKeyPair::generate(&mut rng_seeded(99));
    let sender = KeyPair::generate(&mut rng_seeded(2));
    let msg = sample_message();
    let envelope_bytes = make_envelope(&real_recipient.key_pair().public_key, &sender, &msg, [0x55; 16]);

    match decrypt_envelope(&wrong_recipient, &envelope_bytes) {
        Err(ProvisioningCipherError::MacMismatch) => {}
        other => panic!("expected MacMismatch (wrong key derives wrong MAC), got {:?}", other),
    }
}

#[test]
fn body_shorter_than_minimum_is_rejected_without_panic() {
    let recipient = ProvisioningKeyPair::generate(&mut rng_seeded(1));
    let sender = KeyPair::generate(&mut rng_seeded(2));
    for n in [0usize, 15, 17, 32, 48] {
        let envelope = ProvisionEnvelope {
            public_key: Some(sender.public_key.serialize().to_vec()),
            body: Some(vec![0u8; n]),
        };
        match decrypt_envelope(&recipient, &envelope.encode_to_vec()) {
            Err(ProvisioningCipherError::BodyTooShort(_, _)) => {}
            Err(ProvisioningCipherError::UnsupportedVersion(_)) => {}
            other => panic!("n={n}: expected BodyTooShort/UnsupportedVersion, got {:?}", other),
        }
    }
}

#[test]
fn unsupported_version_byte_is_rejected() {
    let recipient = ProvisioningKeyPair::generate(&mut rng_seeded(1));
    let sender = KeyPair::generate(&mut rng_seeded(2));
    let msg = sample_message();
    let mut envelope_bytes = make_envelope(&recipient.key_pair().public_key, &sender, &msg, [0x12; 16]);
    let envelope = ProvisionEnvelope::decode(envelope_bytes.as_slice()).unwrap();
    let mut body = envelope.body.unwrap();
    body[0] = 0x02;
    let modified = ProvisionEnvelope {
        public_key: envelope.public_key,
        body: Some(body),
    };
    envelope_bytes = modified.encode_to_vec();

    match decrypt_envelope(&recipient, &envelope_bytes) {
        Err(ProvisioningCipherError::UnsupportedVersion(0x02)) => {}
        other => panic!("expected UnsupportedVersion(2), got {:?}", other),
    }
}

#[test]
fn padding_without_mac_failure_returns_bad_padding_after_mac_passes() {
    // Construct an envelope where the MAC is valid (covers the ciphertext)
    // but the plaintext is not protobuf-encoded - the decryption succeeds,
    // returning garbage bytes that prost::decode rejects.
    let recipient = ProvisioningKeyPair::generate(&mut rng_seeded(1));
    let sender = KeyPair::generate(&mut rng_seeded(2));

    let shared = sender
        .private_key
        .calculate_agreement(&recipient.key_pair().public_key)
        .unwrap()
        .to_vec();
    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut keys = [0u8; 64];
    hk.expand(PROVISIONING_INFO, &mut keys).unwrap();
    let (aes_key, mac_key) = keys.split_at(32);

    // Random AES-CBC plaintext that is NOT a valid ProvisionMessage.
    let plaintext = b"not a protobuf message at all yeah".to_vec();
    let iv = [0x42u8; 16];
    let ciphertext = cbc_encrypt(aes_key, &iv, &plaintext);

    let mut body = Vec::with_capacity(1 + 16 + ciphertext.len() + 32);
    body.push(1u8);
    body.extend_from_slice(&iv);
    body.extend_from_slice(&ciphertext);
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(mac_key).unwrap();
    mac.update(&body);
    let mac_tag = mac.finalize().into_bytes();
    body.extend_from_slice(&mac_tag);

    let envelope = ProvisionEnvelope {
        public_key: Some(sender.public_key.serialize().to_vec()),
        body: Some(body),
    };

    match decrypt_envelope(&recipient, &envelope.encode_to_vec()) {
        Err(ProvisioningCipherError::EnvelopeDecode(_)) => {}
        other => panic!("expected EnvelopeDecode (garbage plaintext), got {:?}", other),
    }
}

/// Placeholder for the known-vector test the design doc calls out. The vector
/// will be captured during Phase 10's manual smoke test (a real linking
/// session against a Signal staging account). Until then, marking #[ignore]
/// to document the gap honestly rather than skipping silently.
#[test]
#[ignore = "Phase 10 must capture a real (keypair, envelope, plaintext) triple before this can run"]
fn known_vector_from_real_linking_session() {
    panic!("Phase 10 fixture not yet captured");
}
