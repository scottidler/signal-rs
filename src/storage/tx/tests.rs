//! TxStore atomicity tests.
//!
//! These exercise the load-bearing invariant of the receive pipeline:
//! a libsignal-protocol storage-trait call sequence inside a transaction
//! must either commit as a whole or be invisible. Without TxStore
//! wrapping the transaction, every libsignal call would check out a
//! fresh connection from the pool and writes would be visible mid-flight.
//!
//! Per-identity scoping: each prekey / identity sub-store carries an
//! `IdentityKind`. The same SQL queries are used as the pool-backed
//! `IdentityScopedStore` (via module-level `const`s in
//! `storage::sqlite`), so the two access patterns cannot diverge over
//! time.

use super::*;
use crate::crypto::prekeys::IdentityKind;
use crate::storage::{SqliteStore, Store};
use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair, ProtocolAddress, SessionRecord};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn fixed_address() -> ProtocolAddress {
    ProtocolAddress::new(
        "+15555550100".to_string(),
        libsignal_protocol::DeviceId::new(1).unwrap(),
    )
}

#[tokio::test]
async fn rollback_discards_all_writes_atomically() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let addr = fixed_address();
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let peer_kp = IdentityKeyPair::generate(&mut rng);

    let tx = store.pool().begin().await.unwrap();
    {
        let tx_store = TxStore::new(tx);
        let mut sub_session = tx_store.session_store();
        let mut sub_identity = tx_store.identity_store(IdentityKind::Aci);
        let record = SessionRecord::new_fresh();
        sub_session.store_session(&addr, &record).await.unwrap();
        sub_identity.save_identity(&addr, peer_kp.identity_key()).await.unwrap();
        // Drop tx_store without commit; all writes should be rolled
        // back when the Transaction inside drops.
    }

    let session = SessionStore::load_session(&store.clone(), &addr).await.unwrap();
    let identity: Option<IdentityKey> = store.scoped(IdentityKind::Aci).get_identity(&addr).await.unwrap();

    assert!(session.is_none(), "session must be rolled back");
    assert!(identity.is_none(), "identity write must be rolled back");
}

#[tokio::test]
async fn reads_via_txstore_observe_transaction_local_writes() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let addr = fixed_address();

    let tx = store.pool().begin().await.unwrap();
    let mut tx_store = TxStore::new(tx);
    let record = SessionRecord::new_fresh();

    assert!(tx_store.load_session(&addr).await.unwrap().is_none());
    tx_store.store_session(&addr, &record).await.unwrap();
    // Same transaction, second read sees its own write.
    let loaded = tx_store.load_session(&addr).await.unwrap();
    assert!(
        loaded.is_some(),
        "read-after-write inside one transaction must see the write"
    );
}

#[tokio::test]
async fn prekey_consumption_and_session_update_commit_together() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let kp = KeyPair::generate(&mut rng);
    let addr = fixed_address();

    // Pre-populate a prekey via the scoped pool-backed store.
    let id = libsignal_protocol::PreKeyId::from(7u32);
    let record = libsignal_protocol::PreKeyRecord::new(id, &kp);
    let mut aci_scoped = store.scoped(IdentityKind::Aci);
    PreKeyStore::save_pre_key(&mut aci_scoped, id, &record).await.unwrap();
    assert!(
        PreKeyStore::get_pre_key(&aci_scoped, id).await.is_ok(),
        "fixture: prekey must be present before transaction"
    );

    // In one transaction, simulate the receive-loop critical section:
    // consume the ACI prekey + write a new session.
    let tx = store.pool().begin().await.unwrap();
    let tx_store = TxStore::new(tx);
    {
        let mut sub_pre_key = tx_store.pre_key_store(IdentityKind::Aci);
        let mut sub_session = tx_store.session_store();
        sub_pre_key.remove_pre_key(id).await.unwrap();
        let session = SessionRecord::new_fresh();
        sub_session.store_session(&addr, &session).await.unwrap();
    }
    tx_store.commit().await.unwrap();

    // Both effects are now visible at the pool.
    assert!(
        PreKeyStore::get_pre_key(&store.scoped(IdentityKind::Aci), id)
            .await
            .is_err(),
        "prekey must be deleted post-commit"
    );
    assert!(
        SessionStore::load_session(&store.clone(), &addr)
            .await
            .unwrap()
            .is_some(),
        "session must be present post-commit"
    );
}

#[tokio::test]
async fn prekey_consumption_rolls_back_if_session_write_is_dropped() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let kp = KeyPair::generate(&mut rng);

    let id = libsignal_protocol::PreKeyId::from(7u32);
    let record = libsignal_protocol::PreKeyRecord::new(id, &kp);
    let mut aci_scoped = store.scoped(IdentityKind::Aci);
    PreKeyStore::save_pre_key(&mut aci_scoped, id, &record).await.unwrap();

    let tx = store.pool().begin().await.unwrap();
    {
        let tx_store = TxStore::new(tx);
        let mut sub_pre_key = tx_store.pre_key_store(IdentityKind::Aci);
        sub_pre_key.remove_pre_key(id).await.unwrap();
        // Drop tx_store without commit() - simulating a panic mid-
        // decrypt before the session write would have happened.
    }

    // The prekey must still exist - if rollback didn't fire, the next
    // boot would replay the envelope but the prekey would be gone.
    assert!(
        PreKeyStore::get_pre_key(&store.scoped(IdentityKind::Aci), id)
            .await
            .is_ok(),
        "prekey must be restored after rollback"
    );
}

#[tokio::test]
async fn tx_pre_key_consumption_respects_identity_kind() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let aci_kp = KeyPair::generate(&mut rng);
    let pni_kp = KeyPair::generate(&mut rng);
    let id = libsignal_protocol::PreKeyId::from(42u32);

    // Persist ACI and PNI prekeys at the SAME id via the scoped pool
    // store. With single-id-keyed tables this used to overwrite; the
    // per-identity scoping must keep them distinct.
    let aci_record = libsignal_protocol::PreKeyRecord::new(id, &aci_kp);
    let pni_record = libsignal_protocol::PreKeyRecord::new(id, &pni_kp);
    let mut aci_scoped = store.scoped(IdentityKind::Aci);
    let mut pni_scoped = store.scoped(IdentityKind::Pni);
    PreKeyStore::save_pre_key(&mut aci_scoped, id, &aci_record)
        .await
        .unwrap();
    PreKeyStore::save_pre_key(&mut pni_scoped, id, &pni_record)
        .await
        .unwrap();

    // Consume the ACI row inside a transaction; PNI row at the same
    // id must survive.
    let tx = store.pool().begin().await.unwrap();
    let tx_store = TxStore::new(tx);
    {
        let mut sub_pre_key = tx_store.pre_key_store(IdentityKind::Aci);
        sub_pre_key.remove_pre_key(id).await.unwrap();
    }
    tx_store.commit().await.unwrap();

    assert!(
        PreKeyStore::get_pre_key(&store.scoped(IdentityKind::Aci), id)
            .await
            .is_err(),
        "ACI row should be deleted"
    );
    assert!(
        PreKeyStore::get_pre_key(&store.scoped(IdentityKind::Pni), id)
            .await
            .is_ok(),
        "PNI row at the same id must survive"
    );
}

#[tokio::test]
async fn tx_identity_keypair_returns_pni_when_scoped_pni() {
    let store = SqliteStore::open_in_memory().await.unwrap();
    let aci_kp = IdentityKeyPair::generate(&mut ChaCha20Rng::seed_from_u64(1));
    let pni_kp = IdentityKeyPair::generate(&mut ChaCha20Rng::seed_from_u64(2));
    store
        .save_identity_bundle(&aci_kp, 99, "+15555550100", 1, crate::storage::LinkStatus::Linked)
        .await
        .unwrap();
    store.set_pni_identity_keypair(&pni_kp).await.unwrap();
    store.set_pni_registration_id(123).await.unwrap();

    let tx = store.pool().begin().await.unwrap();
    let tx_store = TxStore::new(tx);
    let aci_sub = tx_store.identity_store(IdentityKind::Aci);
    let pni_sub = tx_store.identity_store(IdentityKind::Pni);

    let aci_loaded = aci_sub.get_identity_key_pair().await.unwrap();
    let pni_loaded = pni_sub.get_identity_key_pair().await.unwrap();
    assert_eq!(aci_loaded.identity_key().serialize(), aci_kp.identity_key().serialize());
    assert_eq!(pni_loaded.identity_key().serialize(), pni_kp.identity_key().serialize());
    assert_ne!(pni_loaded.identity_key().serialize(), aci_kp.identity_key().serialize());

    assert_eq!(aci_sub.get_local_registration_id().await.unwrap(), 99);
    assert_eq!(pni_sub.get_local_registration_id().await.unwrap(), 123);
}
