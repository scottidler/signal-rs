use super::*;
use libsignal_protocol::{
    DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair, KeyPair, KyberPreKeyRecord, PreKeyId, PreKeyRecord,
    ProtocolAddress, SessionRecord, SignedPreKeyId, SignedPreKeyRecord, Timestamp, kem,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn fixed_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(0xDEADBEEF)
}

fn fixed_identity_keypair() -> IdentityKeyPair {
    let mut rng = fixed_rng();
    IdentityKeyPair::generate(&mut rng)
}

fn fixed_address() -> ProtocolAddress {
    ProtocolAddress::new("+15555555555".to_string(), DeviceId::new(1).unwrap())
}

#[tokio::test]
async fn save_and_load_identity_bundle_roundtrip() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let kp = fixed_identity_keypair();
    store
        .save_identity_bundle(&kp, 12345, "+15555555555", 2, LinkStatus::Linked)
        .await
        .unwrap();
    let loaded = store.load_identity().await.unwrap();
    assert_eq!(loaded.registration_id, 12345);
    assert_eq!(loaded.account_number, "+15555555555");
    assert_eq!(loaded.device_id, 2);
    assert_eq!(loaded.link_status, LinkStatus::Linked);
    assert_eq!(
        loaded.identity_keypair.identity_key().serialize(),
        kp.identity_key().serialize()
    );
}

#[tokio::test]
async fn load_identity_on_empty_store_errors_not_linked() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    match store.load_identity().await {
        Err(StoreError::NotLinked) => {}
        other => panic!("expected NotLinked, got {:?}", other),
    }
}

#[tokio::test]
async fn load_identity_on_partial_link_returns_ok_with_identity_persisted_status() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let kp = fixed_identity_keypair();
    store
        .save_identity_bundle(&kp, 1, "+15555555555", 1, LinkStatus::IdentityPersisted)
        .await
        .unwrap();
    let partial = store
        .load_identity()
        .await
        .expect("load_identity must return Ok for partial state");
    assert_eq!(partial.link_status, LinkStatus::IdentityPersisted);
    assert_eq!(partial.account_number, "+15555555555");
    assert_eq!(partial.registration_id, 1);
    store.set_link_status(LinkStatus::Linked).await.unwrap();
    let loaded = store.load_identity().await.unwrap();
    assert_eq!(loaded.link_status, LinkStatus::Linked);
}

#[tokio::test]
async fn libsignal_identity_key_store_round_trips_through_sqlite() {
    let mut store = SqliteStore::open_in_memory().await.unwrap();
    let kp = fixed_identity_keypair();
    store
        .save_identity_bundle(&kp, 99, "+15555555555", 1, LinkStatus::Linked)
        .await
        .unwrap();
    let returned = store.get_identity_key_pair().await.unwrap();
    assert_eq!(returned.identity_key().serialize(), kp.identity_key().serialize());
    assert_eq!(store.get_local_registration_id().await.unwrap(), 99);

    let peer_kp = IdentityKeyPair::generate(&mut fixed_rng());
    let peer_addr = fixed_address();
    let change = store.save_identity(&peer_addr, peer_kp.identity_key()).await.unwrap();
    assert_eq!(change, IdentityChange::NewOrUnchanged);

    let trusted = store
        .is_trusted_identity(&peer_addr, peer_kp.identity_key(), Direction::Receiving)
        .await
        .unwrap();
    assert!(trusted);

    let other = IdentityKeyPair::generate(&mut ChaCha20Rng::seed_from_u64(99));
    let trusted_other = store
        .is_trusted_identity(&peer_addr, other.identity_key(), Direction::Receiving)
        .await
        .unwrap();
    assert!(!trusted_other);
}

#[tokio::test]
async fn libsignal_session_store_round_trip() {
    let mut store = SqliteStore::open_in_memory().await.unwrap();
    let addr = fixed_address();
    assert!(store.load_session(&addr).await.unwrap().is_none());

    let record = SessionRecord::new_fresh();
    store.store_session(&addr, &record).await.unwrap();
    let loaded = store.load_session(&addr).await.unwrap().unwrap();
    assert_eq!(loaded.serialize().unwrap(), record.serialize().unwrap());
}

#[tokio::test]
async fn libsignal_prekey_store_save_get_remove() {
    let mut store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = fixed_rng();
    let kp = KeyPair::generate(&mut rng);
    let id = PreKeyId::from(1u32);
    let record = PreKeyRecord::new(id, &kp);
    store.save_pre_key(id, &record).await.unwrap();

    let loaded = store.get_pre_key(id).await.unwrap();
    assert_eq!(loaded.serialize().unwrap(), record.serialize().unwrap());

    store.remove_pre_key(id).await.unwrap();
    assert!(store.get_pre_key(id).await.is_err());
}

#[tokio::test]
async fn libsignal_signed_prekey_store_round_trip() {
    let mut store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = fixed_rng();
    let kp = KeyPair::generate(&mut rng);
    let id = SignedPreKeyId::from(42u32);
    let signature = vec![0xCAu8; 64];
    let record = SignedPreKeyRecord::new(id, Timestamp::from_epoch_millis(1_700_000_000_000), &kp, &signature);
    store.save_signed_pre_key(id, &record).await.unwrap();
    let loaded = store.get_signed_pre_key(id).await.unwrap();
    assert_eq!(loaded.serialize().unwrap(), record.serialize().unwrap());
}

#[tokio::test]
async fn libsignal_kyber_prekey_store_round_trip_and_mark_used() {
    let mut store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = fixed_rng();
    let ec_kp = KeyPair::generate(&mut rng);
    let signing_key = ec_kp.private_key;
    let id = KyberPreKeyId::from(7u32);
    let record = KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, id, &signing_key).unwrap();
    store.save_kyber_pre_key(id, &record).await.unwrap();
    let loaded = store.get_kyber_pre_key(id).await.unwrap();
    assert_eq!(loaded.serialize().unwrap(), record.serialize().unwrap());

    let dummy_ec_id = SignedPreKeyId::from(0u32);
    let base_key = ec_kp.public_key;
    store.mark_kyber_pre_key_used(id, dummy_ec_id, &base_key).await.unwrap();
    assert!(store.get_kyber_pre_key(id).await.is_err());
}

#[tokio::test]
async fn identity_key_decode_path_handles_compressed_form() {
    let mut store = SqliteStore::open_in_memory().await.unwrap();
    let addr = fixed_address();
    let kp = IdentityKeyPair::generate(&mut fixed_rng());
    store.save_identity(&addr, kp.identity_key()).await.unwrap();
    let loaded: Option<IdentityKey> = store.get_identity(&addr).await.unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().serialize(), kp.identity_key().serialize());
}
