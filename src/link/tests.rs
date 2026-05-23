use super::*;
use crate::crypto::provisioning::proto::{ProvisionEnvelope, ProvisionMessage};
use crate::storage::{SqliteStore, Store};
use aes::Aes256;
use cbc::Encryptor;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use hkdf::Hkdf;
use hmac::Hmac;
use libsignal_protocol::{IdentityKeyPair, KeyPair};
use prost::Message as _;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

type Aes256CbcEnc = Encryptor<Aes256>;

fn rng_seeded(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn make_real_provision_message(rng: &mut ChaCha20Rng, number: &str) -> ProvisionMessage {
    let ikp = IdentityKeyPair::generate(rng);
    ProvisionMessage {
        aci_identity_key_public: Some(ikp.identity_key().serialize().to_vec()),
        aci_identity_key_private: Some(ikp.private_key().serialize().to_vec()),
        pni_identity_key_public: Some(ikp.identity_key().serialize().to_vec()),
        pni_identity_key_private: Some(ikp.private_key().serialize().to_vec()),
        aci: Some("11111111-2222-3333-4444-555555555555".into()),
        pni: Some("66666666-7777-8888-9999-aaaaaaaaaaaa".into()),
        number: Some(number.into()),
        provisioning_code: Some("ABCDEFGH".into()),
        user_agent: Some("signal-rs-test".into()),
        profile_key: Some(vec![0xCD; 32]),
        read_receipts: Some(true),
        provisioning_version: Some(2),
        ephemeral_backup_key: Some(vec![0xEF; 32]),
        account_entropy_pool: Some("entropy-pool".into()),
        media_root_backup_key: Some(vec![0x10; 32]),
        aci_binary: Some(vec![0x11; 16]),
        pni_binary: Some(vec![0x22; 16]),
    }
}

fn synthesize_envelope(
    recipient_pub: &libsignal_protocol::PublicKey,
    sender: &KeyPair,
    msg: &ProvisionMessage,
) -> Vec<u8> {
    let shared = sender.private_key.calculate_agreement(recipient_pub).unwrap().to_vec();
    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut keys = [0u8; 64];
    hk.expand(b"TextSecure Provisioning Message", &mut keys).unwrap();
    let (aes_key, mac_key) = keys.split_at(32);

    let plaintext = msg.encode_to_vec();
    let iv = [0x11u8; 16];
    let enc = Aes256CbcEnc::new_from_slices(aes_key, &iv).unwrap();
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(&plaintext);
    let ciphertext = enc.encrypt_padded::<Pkcs7>(&mut buf, plaintext.len()).unwrap().to_vec();

    let mut body = Vec::with_capacity(1 + 16 + ciphertext.len() + 32);
    body.push(1u8);
    body.extend_from_slice(&iv);
    body.extend_from_slice(&ciphertext);
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(mac_key).unwrap();
    hmac::Mac::update(&mut mac, &body);
    let tag = hmac::Mac::finalize(mac).into_bytes();
    body.extend_from_slice(&tag);

    let envelope = ProvisionEnvelope {
        public_key: Some(sender.public_key.serialize().to_vec()),
        body: Some(body),
    };
    envelope.encode_to_vec()
}

#[test]
fn provisioning_uri_format_is_sgnl_with_required_query_params() {
    let pubkey = vec![0x05, 0xAA, 0xBB, 0xCC];
    let uri = build_provisioning_uri(&pubkey, "opaque-address-string");
    assert!(uri.starts_with("sgnl://linkdevice?"), "uri={uri}");
    assert!(uri.contains("uuid=opaque-address-string"), "uri={uri}");
    assert!(uri.contains("pub_key="), "uri={uri}");
}

#[test]
fn provisioning_uri_percent_encodes_special_chars_in_address() {
    let pubkey = vec![0x05];
    let uri = build_provisioning_uri(&pubkey, "addr with spaces & =");
    // spaces -> %20, ampersand -> %26, equals -> %3D, etc.
    assert!(uri.contains("addr%20with%20spaces%20%26%20%3D"), "uri={uri}");
}

#[tokio::test]
async fn persist_provision_message_writes_identity_at_status_identity_persisted() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = rng_seeded(7);
    let msg = make_real_provision_message(&mut rng, "+15555550100");

    let outcome = persist_provision_message(&store, &msg).await.unwrap();
    assert_eq!(outcome.account_number, "+15555550100");

    // load_identity returns the identity with its current status; callers
    // decide whether to refuse (Client::open) or resume (link()).
    let partial = store.load_identity().await.unwrap();
    assert_eq!(partial.link_status, LinkStatus::IdentityPersisted);
    assert_eq!(partial.account_number, "+15555550100");

    mark_linked(&store).await.unwrap();
    let loaded = store.load_identity().await.unwrap();
    assert_eq!(loaded.account_number, "+15555550100");
    assert_eq!(loaded.link_status, LinkStatus::Linked);
}

#[tokio::test]
async fn persist_provision_message_errors_on_missing_aci_identity_key_public() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = rng_seeded(8);
    let mut msg = make_real_provision_message(&mut rng, "+15555550100");
    msg.aci_identity_key_public = None;

    match persist_provision_message(&store, &msg).await {
        Err(LinkError::MissingField("aciIdentityKeyPublic")) => {}
        other => panic!("expected MissingField(aciIdentityKeyPublic), got {:?}", other),
    }
}

#[tokio::test]
async fn persist_provision_message_errors_on_missing_number() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = rng_seeded(8);
    let mut msg = make_real_provision_message(&mut rng, "+15555550100");
    msg.number = None;

    match persist_provision_message(&store, &msg).await {
        Err(LinkError::MissingField("number")) => {}
        other => panic!("expected MissingField(number), got {:?}", other),
    }
}

#[tokio::test]
async fn persist_provision_message_errors_on_garbage_aci_public_key() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = rng_seeded(8);
    let mut msg = make_real_provision_message(&mut rng, "+15555550100");
    msg.aci_identity_key_public = Some(vec![0xFF; 8]);

    match persist_provision_message(&store, &msg).await {
        Err(LinkError::InvalidIdentityKey(_)) => {}
        other => panic!("expected InvalidIdentityKey, got {:?}", other),
    }
}

#[tokio::test]
async fn finalize_link_decrypts_then_persists_end_to_end() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng_recipient = rng_seeded(1);
    let mut rng_sender = rng_seeded(2);
    let mut rng_msg = rng_seeded(3);

    let recipient_kp = ProvisioningKeyPair::generate(&mut rng_recipient);
    let sender = KeyPair::generate(&mut rng_sender);
    let msg = make_real_provision_message(&mut rng_msg, "+15555550199");

    let envelope = synthesize_envelope(&recipient_kp.key_pair().public_key, &sender, &msg);
    let outcome = finalize_link(&store, &recipient_kp, &envelope).await.unwrap();
    assert_eq!(outcome.account_number, "+15555550199");

    mark_linked(&store).await.unwrap();
    let loaded = store.load_identity().await.unwrap();
    assert_eq!(loaded.account_number, "+15555550199");
}

#[tokio::test]
async fn finalize_link_with_tampered_envelope_fails_at_mac_and_does_not_persist() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng_recipient = rng_seeded(1);
    let mut rng_sender = rng_seeded(2);
    let mut rng_msg = rng_seeded(3);

    let recipient_kp = ProvisioningKeyPair::generate(&mut rng_recipient);
    let sender = KeyPair::generate(&mut rng_sender);
    let msg = make_real_provision_message(&mut rng_msg, "+15555550199");

    let mut envelope = synthesize_envelope(&recipient_kp.key_pair().public_key, &sender, &msg);
    let env_decoded = ProvisionEnvelope::decode(envelope.as_slice()).unwrap();
    let mut body = env_decoded.body.unwrap();
    let mac_byte_idx = body.len() - 16;
    body[mac_byte_idx] ^= 0x01; // tamper inside the MAC region
    let modified = ProvisionEnvelope {
        public_key: env_decoded.public_key,
        body: Some(body),
    };
    envelope = modified.encode_to_vec();

    match finalize_link(&store, &recipient_kp, &envelope).await {
        Err(LinkError::Cipher(_)) => {}
        other => panic!("expected Cipher error, got {:?}", other),
    }
    // Nothing should be persisted - the cipher fails before we touch storage.
    match store.load_identity().await {
        Err(StoreError::NotLinked) => {}
        other => panic!("expected NotLinked (no partial write), got {:?}", other),
    }
}

// link() against live Signal servers cannot be unit-tested without a
// phone scan; Phase 10's manual smoke test covers it. The
// `persist_provision_message` / `finalize_link` integration tests above
// exercise the post-decrypt path with synthesized envelopes.

#[tokio::test]
async fn link_persists_aci_and_pni_batches_without_collision() {
    // This is the integration test required by the per-identity-prekey
    // design doc. The full `finalize_after_persist` path issues a live
    // /v1/devices/link PUT, which we cannot exercise without a server.
    // What we CAN exercise (and what the design cares about for the
    // collision-prevention guarantee) is the local persistence
    // sub-sequence: generate ACI + PNI batches starting at id=1,
    // generate a distinct PNI registration id, persist both batches
    // and the PNI reg id; then assert both signed-prekey rows at
    // id=101 survive in their own (identity_kind, id) partitions and
    // the two registration ids differ.
    use crate::crypto::prekeys::{IdentityKind, generate_batch, persist_batch};
    use libsignal_protocol::{GenericSignedPreKey, IdentityKeyStore, SignedPreKeyStore};

    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = rng_seeded(0xBA5E);
    let msg = make_real_provision_message(&mut rng, "+15555550111");
    persist_provision_message(&store, &msg).await.unwrap();

    // Both batches start at next_id=1; before the per-identity scoping
    // landed, this overwrote ACI's signed_prekey at id=101 with PNI's.
    let aci_batch = generate_batch(&mut rng, &store, IdentityKind::Aci, 1).await.unwrap();
    let pni_batch = generate_batch(&mut rng, &store, IdentityKind::Pni, 1).await.unwrap();
    assert_eq!(aci_batch.signed_prekey_id, 101);
    assert_eq!(pni_batch.signed_prekey_id, 101);

    // Distinct PNI registration id (signal-cli pattern).
    use rand::Rng as _;
    let pni_registration_id: u32 = rng.random_range(1..=16380);
    store.set_pni_registration_id(pni_registration_id).await.unwrap();

    persist_batch(&store, &aci_batch, IdentityKind::Aci).await.unwrap();
    persist_batch(&store, &pni_batch, IdentityKind::Pni).await.unwrap();

    // Both signed_prekey rows at id=101 must exist and round-trip to
    // the correct private halves through their scoped stores.
    let aci_scoped = store.scoped(IdentityKind::Aci);
    let pni_scoped = store.scoped(IdentityKind::Pni);
    let signed_id_101 = libsignal_protocol::SignedPreKeyId::from(101u32);
    let aci_loaded = SignedPreKeyStore::get_signed_pre_key(&aci_scoped, signed_id_101)
        .await
        .unwrap();
    let pni_loaded = SignedPreKeyStore::get_signed_pre_key(&pni_scoped, signed_id_101)
        .await
        .unwrap();
    assert_eq!(
        aci_loaded.serialize().unwrap(),
        aci_batch.signed_record.serialize().unwrap(),
        "ACI signed prekey at id=101 must match the generated ACI record"
    );
    assert_eq!(
        pni_loaded.serialize().unwrap(),
        pni_batch.signed_record.serialize().unwrap(),
        "PNI signed prekey at id=101 must match the generated PNI record"
    );
    // The bug we are preventing: the two records must NOT be equal.
    assert_ne!(
        aci_loaded.serialize().unwrap(),
        pni_loaded.serialize().unwrap(),
        "ACI and PNI signed prekeys at the same id must differ"
    );

    // Both registration ids must be persisted and distinct.
    let aci_reg = aci_scoped.get_local_registration_id().await.unwrap();
    let pni_reg = pni_scoped.get_local_registration_id().await.unwrap();
    assert_ne!(
        aci_reg, pni_reg,
        "ACI and PNI registration ids must be independently generated"
    );
    assert_eq!(pni_reg, pni_registration_id);
}
