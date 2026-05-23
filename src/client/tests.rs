use super::*;
use crate::link::{mark_linked, persist_provision_message};
use crate::storage::SqliteStore;

// Builds a minimal real ProvisionMessage, persists it via Phase 5's
// path, marks the store Linked, and returns the state directory path.
async fn linked_state_dir() -> (tempfile::TempDir, SqliteStore) {
    let tmp = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&tmp.path().join("store.db")).await.unwrap();

    use crate::crypto::provisioning::proto::ProvisionMessage;
    use libsignal_protocol::IdentityKeyPair;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    let mut rng = ChaCha20Rng::seed_from_u64(0x5151);
    let ikp = IdentityKeyPair::generate(&mut rng);
    let msg = ProvisionMessage {
        aci_identity_key_public: Some(ikp.identity_key().serialize().to_vec()),
        aci_identity_key_private: Some(ikp.private_key().serialize().to_vec()),
        pni_identity_key_public: Some(ikp.identity_key().serialize().to_vec()),
        pni_identity_key_private: Some(ikp.private_key().serialize().to_vec()),
        aci: Some("11111111-2222-3333-4444-555555555555".into()),
        pni: Some("66666666-7777-8888-9999-aaaaaaaaaaaa".into()),
        number: Some("+15555550100".into()),
        provisioning_code: Some("ABCDEFGH".into()),
        user_agent: Some("signal-rs-test".into()),
        profile_key: Some(vec![0xCD; 32]),
        read_receipts: Some(false),
        provisioning_version: Some(1),
        ephemeral_backup_key: None,
        account_entropy_pool: None,
        media_root_backup_key: None,
        aci_binary: None,
        pni_binary: None,
    };
    persist_provision_message(&store, &msg).await.unwrap();
    mark_linked(&store).await.unwrap();
    (tmp, store)
}

#[tokio::test]
async fn open_on_empty_state_dir_returns_not_linked() {
    let tmp = tempfile::tempdir().unwrap();
    match Client::open(tmp.path()).await {
        Err(OpenError::NotLinked) => {}
        other => panic!("expected NotLinked, got {:?}", other),
    }
}

#[tokio::test]
async fn open_on_partially_linked_state_dir_returns_partially_linked() {
    use crate::link::persist_provision_message;
    let tmp = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&tmp.path().join("store.db")).await.unwrap();

    use crate::crypto::provisioning::proto::ProvisionMessage;
    use libsignal_protocol::IdentityKeyPair;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    let mut rng = ChaCha20Rng::seed_from_u64(0x5252);
    let ikp = IdentityKeyPair::generate(&mut rng);
    let msg = ProvisionMessage {
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
    // Don't mark_linked - leaves state at IdentityPersisted.
    drop(store);

    match Client::open(tmp.path()).await {
        Err(OpenError::PartiallyLinked) => {}
        other => panic!("expected PartiallyLinked, got {:?}", other),
    }
}

#[tokio::test]
async fn open_succeeds_on_linked_state_dir_and_exposes_account_number() {
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    assert_eq!(client.account_number(), "+15555550100");
}

#[tokio::test]
async fn send_returns_live_send_not_implemented_until_phase_10() {
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    match client.send("+15555550199", "hello").await {
        Err(SendError::LiveSendNotImplemented) => {}
        other => panic!("expected LiveSendNotImplemented, got {:?}", other),
    }
}

#[tokio::test]
async fn run_receive_loop_returns_live_loop_not_implemented_until_phase_10() {
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    match client.run_receive_loop().await {
        Err(ReceiveError::LiveLoopNotImplemented) => {}
        other => panic!("expected LiveLoopNotImplemented, got {:?}", other),
    }
}

#[tokio::test]
async fn receive_returns_a_subscriber_even_before_loop_is_running() {
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    let mut rx = client.receive();
    // No producer yet, so the channel is empty - try_recv must say so.
    assert!(rx.try_recv().is_err(), "no envelopes yet");
}
