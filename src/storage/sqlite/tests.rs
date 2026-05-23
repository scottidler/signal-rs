use super::*;
use crate::crypto::prekeys::IdentityKind;
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
async fn identity_scoped_store_aci_returns_aci_keypair_and_reg_id() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let kp = fixed_identity_keypair();
    store
        .save_identity_bundle(&kp, 99, "+15555555555", 1, LinkStatus::Linked)
        .await
        .unwrap();
    let aci_scoped = store.scoped(IdentityKind::Aci);
    let returned = aci_scoped.get_identity_key_pair().await.unwrap();
    assert_eq!(returned.identity_key().serialize(), kp.identity_key().serialize());
    assert_eq!(aci_scoped.get_local_registration_id().await.unwrap(), 99);
}

#[tokio::test]
async fn identity_scoped_store_pni_returns_pni_keypair_and_reg_id() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let aci_kp = IdentityKeyPair::generate(&mut ChaCha20Rng::seed_from_u64(1));
    let pni_kp = IdentityKeyPair::generate(&mut ChaCha20Rng::seed_from_u64(2));
    store
        .save_identity_bundle(&aci_kp, 99, "+15555555555", 1, LinkStatus::Linked)
        .await
        .unwrap();
    store.set_pni_identity_keypair(&pni_kp).await.unwrap();
    store.set_pni_registration_id(777).await.unwrap();
    let pni_scoped = store.scoped(IdentityKind::Pni);
    let returned = pni_scoped.get_identity_key_pair().await.unwrap();
    // PNI keypair must come back, NOT the ACI one.
    assert_eq!(returned.identity_key().serialize(), pni_kp.identity_key().serialize());
    assert_ne!(returned.identity_key().serialize(), aci_kp.identity_key().serialize());
    assert_eq!(pni_scoped.get_local_registration_id().await.unwrap(), 777);
}

#[tokio::test]
async fn identity_scoped_store_peer_identity_round_trip() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let kp = fixed_identity_keypair();
    store
        .save_identity_bundle(&kp, 99, "+15555555555", 1, LinkStatus::Linked)
        .await
        .unwrap();
    let mut scoped = store.scoped(IdentityKind::Aci);

    let peer_kp = IdentityKeyPair::generate(&mut fixed_rng());
    let peer_addr = fixed_address();
    let change = scoped.save_identity(&peer_addr, peer_kp.identity_key()).await.unwrap();
    assert_eq!(change, IdentityChange::NewOrUnchanged);

    let trusted = scoped
        .is_trusted_identity(&peer_addr, peer_kp.identity_key(), Direction::Receiving)
        .await
        .unwrap();
    assert!(trusted);

    let other = IdentityKeyPair::generate(&mut ChaCha20Rng::seed_from_u64(99));
    let trusted_other = scoped
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
async fn aci_and_pni_prekey_at_same_id_round_trip_independently() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = fixed_rng();
    let aci_kp = KeyPair::generate(&mut rng);
    let pni_kp = KeyPair::generate(&mut rng);
    let id = PreKeyId::from(42u32);
    let aci_record = PreKeyRecord::new(id, &aci_kp);
    let pni_record = PreKeyRecord::new(id, &pni_kp);

    let mut aci_scoped = store.scoped(IdentityKind::Aci);
    let mut pni_scoped = store.scoped(IdentityKind::Pni);
    aci_scoped.save_pre_key(id, &aci_record).await.unwrap();
    pni_scoped.save_pre_key(id, &pni_record).await.unwrap();

    let aci_loaded = aci_scoped.get_pre_key(id).await.unwrap();
    let pni_loaded = pni_scoped.get_pre_key(id).await.unwrap();
    assert_eq!(aci_loaded.serialize().unwrap(), aci_record.serialize().unwrap());
    assert_eq!(pni_loaded.serialize().unwrap(), pni_record.serialize().unwrap());
    // The bug we are preventing: ACI's load must NOT return the PNI record.
    assert_ne!(aci_loaded.serialize().unwrap(), pni_record.serialize().unwrap());

    // Remove the ACI row; the PNI row at the same id must survive.
    aci_scoped.remove_pre_key(id).await.unwrap();
    assert!(aci_scoped.get_pre_key(id).await.is_err());
    assert!(pni_scoped.get_pre_key(id).await.is_ok());
}

#[tokio::test]
async fn aci_and_pni_signed_prekey_at_same_id_round_trip_independently() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = fixed_rng();
    let aci_kp = KeyPair::generate(&mut rng);
    let pni_kp = KeyPair::generate(&mut rng);
    let id = SignedPreKeyId::from(101u32);
    let sig = vec![0xCAu8; 64];
    let aci_record = SignedPreKeyRecord::new(id, Timestamp::from_epoch_millis(1), &aci_kp, &sig);
    let pni_record = SignedPreKeyRecord::new(id, Timestamp::from_epoch_millis(1), &pni_kp, &sig);

    let mut aci_scoped = store.scoped(IdentityKind::Aci);
    let mut pni_scoped = store.scoped(IdentityKind::Pni);
    aci_scoped.save_signed_pre_key(id, &aci_record).await.unwrap();
    pni_scoped.save_signed_pre_key(id, &pni_record).await.unwrap();

    let aci_loaded = aci_scoped.get_signed_pre_key(id).await.unwrap();
    let pni_loaded = pni_scoped.get_signed_pre_key(id).await.unwrap();
    assert_eq!(aci_loaded.serialize().unwrap(), aci_record.serialize().unwrap());
    assert_eq!(pni_loaded.serialize().unwrap(), pni_record.serialize().unwrap());
    assert_ne!(aci_loaded.serialize().unwrap(), pni_record.serialize().unwrap());
}

#[tokio::test]
async fn aci_and_pni_kyber_prekey_at_same_id_round_trip_independently() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = fixed_rng();
    let aci_ec = KeyPair::generate(&mut rng);
    let pni_ec = KeyPair::generate(&mut rng);
    let id = KyberPreKeyId::from(102u32);
    let aci_record = KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, id, &aci_ec.private_key).unwrap();
    let pni_record = KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, id, &pni_ec.private_key).unwrap();

    let mut aci_scoped = store.scoped(IdentityKind::Aci);
    let mut pni_scoped = store.scoped(IdentityKind::Pni);
    aci_scoped.save_kyber_pre_key(id, &aci_record).await.unwrap();
    pni_scoped.save_kyber_pre_key(id, &pni_record).await.unwrap();

    let aci_loaded = aci_scoped.get_kyber_pre_key(id).await.unwrap();
    let pni_loaded = pni_scoped.get_kyber_pre_key(id).await.unwrap();
    assert_eq!(aci_loaded.serialize().unwrap(), aci_record.serialize().unwrap());
    assert_eq!(pni_loaded.serialize().unwrap(), pni_record.serialize().unwrap());
    assert_ne!(aci_loaded.serialize().unwrap(), pni_record.serialize().unwrap());

    // mark-used deletes only the kind's row.
    let dummy_ec_id = SignedPreKeyId::from(0u32);
    let base_key = aci_ec.public_key;
    aci_scoped
        .mark_kyber_pre_key_used(id, dummy_ec_id, &base_key)
        .await
        .unwrap();
    assert!(aci_scoped.get_kyber_pre_key(id).await.is_err());
    assert!(pni_scoped.get_kyber_pre_key(id).await.is_ok());
}

#[tokio::test]
async fn identity_key_decode_path_handles_compressed_form() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let kp = fixed_identity_keypair();
    store
        .save_identity_bundle(&kp, 1, "+15555555555", 1, LinkStatus::Linked)
        .await
        .unwrap();
    let mut scoped = store.scoped(IdentityKind::Aci);
    let addr = fixed_address();
    scoped.save_identity(&addr, kp.identity_key()).await.unwrap();
    let loaded: Option<IdentityKey> = scoped.get_identity(&addr).await.unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().serialize(), kp.identity_key().serialize());
}
