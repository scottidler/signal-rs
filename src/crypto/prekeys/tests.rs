use super::*;
use crate::SqliteStore;
use crate::link::{mark_linked, persist_provision_message};
use libsignal_protocol::IdentityKeyPair;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

async fn linked_store() -> SqliteStore {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(0xABCD);
    let ikp = IdentityKeyPair::generate(&mut rng);
    let msg = crate::crypto::provisioning::proto::ProvisionMessage {
        aci_identity_key_public: Some(ikp.identity_key().serialize().to_vec()),
        aci_identity_key_private: Some(ikp.private_key().serialize().to_vec()),
        pni_identity_key_public: Some(ikp.identity_key().serialize().to_vec()),
        pni_identity_key_private: Some(ikp.private_key().serialize().to_vec()),
        aci: None,
        pni: None,
        number: Some("+15555550100".into()),
        provisioning_code: None,
        user_agent: None,
        profile_key: None,
        read_receipts: None,
        provisioning_version: None,
        ephemeral_backup_key: None,
        account_entropy_pool: None,
        media_root_backup_key: None,
        aci_binary: None,
        pni_binary: None,
    };
    persist_provision_message(&store, &msg).await.unwrap();
    mark_linked(&store).await.unwrap();
    store
}

#[tokio::test]
async fn generate_and_persist_batch_writes_all_records() {
    let store = linked_store().await;
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let batch = generate_and_persist_batch(&mut rng, &store, 1).await.unwrap();
    assert_eq!(batch.one_time_prekey_ids.len(), PREKEY_BATCH_SIZE as usize);
    assert_eq!(batch.one_time_prekey_ids[0], 1);
    assert_eq!(batch.signed_prekey_id, 1 + PREKEY_BATCH_SIZE);
    assert_eq!(batch.kyber_prekey_id, 1 + PREKEY_BATCH_SIZE + 1);

    // Spot-check: the first one-time prekey is fetchable from the store.
    let first_id = PreKeyId::from(batch.one_time_prekey_ids[0]);
    let s = store.clone();
    let record = PreKeyStore::get_pre_key(&s, first_id).await.unwrap();
    assert!(!record.serialize().unwrap().is_empty());
}

#[tokio::test]
async fn second_batch_uses_disjoint_ids() {
    let store = linked_store().await;
    let mut rng = ChaCha20Rng::seed_from_u64(8);
    let first = generate_and_persist_batch(&mut rng, &store, 1).await.unwrap();
    let next_start = first.kyber_prekey_id + 1;
    let second = generate_and_persist_batch(&mut rng, &store, next_start).await.unwrap();

    let first_set: std::collections::HashSet<u32> = first.one_time_prekey_ids.iter().copied().collect();
    let second_set: std::collections::HashSet<u32> = second.one_time_prekey_ids.iter().copied().collect();
    assert!(first_set.is_disjoint(&second_set), "ID ranges must not overlap");
    assert_ne!(first.signed_prekey_id, second.signed_prekey_id);
    assert_ne!(first.kyber_prekey_id, second.kyber_prekey_id);
}

#[tokio::test]
async fn upload_batch_returns_not_implemented_until_phase_10() {
    let store = linked_store().await;
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let batch = generate_and_persist_batch(&mut rng, &store, 1).await.unwrap();
    match upload_batch(&store, &batch).await {
        Err(PrekeyError::UploadNotImplemented) => {}
        other => panic!("expected UploadNotImplemented, got {:?}", other),
    }
}
