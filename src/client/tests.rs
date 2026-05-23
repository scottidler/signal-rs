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
async fn send_to_non_note_to_self_target_returns_target_unsupported() {
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    match client.send("+15555550199", "hello").await {
        Err(SendError::TargetUnsupported(t)) => assert_eq!(t, "+15555550199"),
        other => panic!("expected TargetUnsupported, got {:?}", other),
    }
}

// run_receive_loop now opens a real chat WebSocket against Signal's
// production servers; it cannot be exercised in unit tests without a
// live account. Coverage moves to Phase 10's manual smoke test.

#[tokio::test]
async fn receive_returns_a_subscriber_even_before_loop_is_running() {
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    let mut rx = client.receive();
    // No producer yet, so the channel is empty - try_recv must say so.
    assert!(rx.try_recv().is_err(), "no envelopes yet");
}

// =============================================================================
// route_envelope_to_identity: PNI vs ACI routing on inbound envelopes
// =============================================================================
//
// process_envelope's full path requires a synthesized encrypted envelope,
// which in turn requires pre-established sessions for ACI and PNI. The
// routing decision itself was extracted to a pure free function so it
// can be tested directly. The Phase 5 smoke is necessary but not
// sufficient (primary-to-linked sync traffic is ACI-addressed); these
// tests are the unit-level proxy for the PNI receive path.

use crate::client::route_envelope_to_identity;
use crate::crypto::prekeys::IdentityKind;

const ACI: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const PNI: &str = "pppppppp-pppp-pppp-pppp-pppppppppppp";

#[test]
fn route_pni_destination_routes_to_pni_scope() {
    let (kind, local_service_id) = route_envelope_to_identity(Some(PNI), ACI, Some(PNI));
    assert_eq!(kind, IdentityKind::Pni);
    assert_eq!(local_service_id, PNI);
}

#[test]
fn route_aci_destination_routes_to_aci_scope() {
    let (kind, local_service_id) = route_envelope_to_identity(Some(ACI), ACI, Some(PNI));
    assert_eq!(kind, IdentityKind::Aci);
    assert_eq!(local_service_id, ACI);
}

#[test]
fn route_missing_destination_defaults_to_aci() {
    let (kind, local_service_id) = route_envelope_to_identity(None, ACI, Some(PNI));
    assert_eq!(kind, IdentityKind::Aci);
    assert_eq!(local_service_id, ACI);
}

#[test]
fn route_unknown_destination_defaults_to_aci() {
    let unknown = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";
    let (kind, local_service_id) = route_envelope_to_identity(Some(unknown), ACI, Some(PNI));
    assert_eq!(kind, IdentityKind::Aci);
    assert_eq!(local_service_id, ACI);
}

#[test]
fn route_pni_destination_without_local_pni_falls_through_to_aci() {
    // No PNI persisted yet (early-link bootstrap or single-identity
    // account). A destination that doesn't match ACI should route to
    // ACI with a warn rather than mis-route to PNI scope.
    let (kind, local_service_id) = route_envelope_to_identity(Some(PNI), ACI, None);
    assert_eq!(kind, IdentityKind::Aci);
    assert_eq!(local_service_id, ACI);
}

#[test]
fn route_aci_destination_works_without_local_pni() {
    let (kind, local_service_id) = route_envelope_to_identity(Some(ACI), ACI, None);
    assert_eq!(kind, IdentityKind::Aci);
    assert_eq!(local_service_id, ACI);
}
