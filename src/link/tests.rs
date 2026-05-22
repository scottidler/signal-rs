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

    // load_identity refuses to return until Linked - confirm the half-linked path.
    match store.load_identity().await {
        Err(StoreError::PartiallyLinked {
            status: LinkStatus::IdentityPersisted,
        }) => {}
        other => panic!("expected PartiallyLinked, got {:?}", other),
    }

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

#[tokio::test]
async fn live_server_link_returns_not_implemented_error() {
    let tmp = tempfile::tempdir().unwrap();
    match link(tmp.path(), "test-device", |_| {}).await {
        Err(LinkError::LiveServerNotImplemented) => {}
        other => panic!("expected LiveServerNotImplemented, got {:?}", other),
    }
}
