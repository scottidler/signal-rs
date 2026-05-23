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
async fn generate_batch_produces_records_in_memory_only() {
    let store = linked_store().await;
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let batch = generate_batch(&mut rng, &store, IdentityKind::Aci, 1).await.unwrap();

    assert_eq!(batch.one_time_prekey_ids.len(), PREKEY_BATCH_SIZE as usize);
    assert_eq!(batch.one_time_prekey_ids[0], 1);
    assert_eq!(batch.signed_prekey_id, 1 + PREKEY_BATCH_SIZE);
    assert_eq!(batch.kyber_prekey_id, 1 + PREKEY_BATCH_SIZE + 1);
    assert_eq!(batch.one_time_records.len(), PREKEY_BATCH_SIZE as usize);

    // signal-cli's ordering: generate produces in-memory records ONLY,
    // does NOT touch the local store. The store must not yet have the
    // prekey we just generated.
    let first_id = PreKeyId::from(batch.one_time_prekey_ids[0]);
    let s = store.clone();
    assert!(
        PreKeyStore::get_pre_key(&s, first_id).await.is_err(),
        "generate_batch must not write to the store - persist_batch does that after upload"
    );
}

#[tokio::test]
async fn persist_batch_writes_after_upload_success() {
    // The signal-cli order: generate -> upload -> persist. We can't
    // run upload in tests (no live server), so simulate the success
    // path by calling persist_batch directly. After persist, the
    // records are visible via PreKeyStore::get_pre_key.
    let store = linked_store().await;
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let batch = generate_batch(&mut rng, &store, IdentityKind::Aci, 1).await.unwrap();
    persist_batch(&store, &batch).await.unwrap();

    let first_id = PreKeyId::from(batch.one_time_prekey_ids[0]);
    let s = store.clone();
    let record = PreKeyStore::get_pre_key(&s, first_id).await.unwrap();
    assert!(!record.serialize().unwrap().is_empty());
}

#[tokio::test]
async fn second_batch_uses_disjoint_ids() {
    let store = linked_store().await;
    let mut rng = ChaCha20Rng::seed_from_u64(8);
    let first = generate_batch(&mut rng, &store, IdentityKind::Aci, 1).await.unwrap();
    let next_start = first.kyber_prekey_id + 1;
    let second = generate_batch(&mut rng, &store, IdentityKind::Aci, next_start)
        .await
        .unwrap();

    let first_set: std::collections::HashSet<u32> = first.one_time_prekey_ids.iter().copied().collect();
    let second_set: std::collections::HashSet<u32> = second.one_time_prekey_ids.iter().copied().collect();
    assert!(first_set.is_disjoint(&second_set), "ID ranges must not overlap");
    assert_ne!(first.signed_prekey_id, second.signed_prekey_id);
    assert_ne!(first.kyber_prekey_id, second.kyber_prekey_id);
}

#[tokio::test]
async fn upload_batch_against_missing_credentials_errors_without_polluting_store() {
    // signal-cli's ordering: a failed upload must NOT leave orphan
    // prekeys in the local store. Generate, attempt upload (fails
    // because no aci/password in the in-memory store), confirm that
    // no prekey row was written.
    let store = linked_store().await;
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let batch = generate_batch(&mut rng, &store, IdentityKind::Aci, 1).await.unwrap();
    match upload_batch(&store, &batch, IdentityKind::Aci).await {
        Err(PrekeyError::Upload(msg)) => assert!(
            msg.contains("aci") || msg.contains("password") || msg.contains("missing"),
            "expected credential message, got {msg}"
        ),
        other => panic!("expected Upload(missing-credential) error, got {:?}", other),
    }
    // The store must still NOT have the prekey - upload failed, no
    // persist should have occurred.
    let first_id = PreKeyId::from(batch.one_time_prekey_ids[0]);
    let s = store.clone();
    assert!(
        PreKeyStore::get_pre_key(&s, first_id).await.is_err(),
        "failed upload must not leave orphan prekey in the local store"
    );
}
