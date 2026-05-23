//! TxStore atomicity tests.
//!
//! These exercise the load-bearing invariant of Phase 6's receive pipeline:
//! a libsignal-protocol storage-trait call sequence inside a transaction
//! must either commit as a whole or be invisible. Without TxStore wrapping
//! the transaction, every libsignal call would check out a fresh
//! connection from the pool and writes would be visible mid-flight.

use super::*;
use crate::storage::SqliteStore;
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
        let mut tx_store = TxStore::new(tx);
        let record = SessionRecord::new_fresh();
        tx_store.store_session(&addr, &record).await.unwrap();
        tx_store.save_identity(&addr, peer_kp.identity_key()).await.unwrap();
        // Drop tx_store without commit - all writes should be rolled
        // back when the Transaction inside drops.
    }

    let session = SessionStore::load_session(&store.clone(), &addr).await.unwrap();
    let identity: Option<IdentityKey> = IdentityKeyStore::get_identity(&store.clone(), &addr).await.unwrap();

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

    // Pre-populate a prekey via the pool-backed store.
    let id = libsignal_protocol::PreKeyId::from(7u32);
    let record = libsignal_protocol::PreKeyRecord::new(id, &kp);
    PreKeyStore::save_pre_key(&mut store.clone(), id, &record)
        .await
        .unwrap();
    assert!(
        PreKeyStore::get_pre_key(&store.clone(), id).await.is_ok(),
        "fixture: prekey must be present before transaction"
    );

    // In one transaction, simulate the receive-loop critical section:
    // consume the prekey + write a new session.
    let tx = store.pool().begin().await.unwrap();
    let tx_store = TxStore::new(tx);
    {
        let mut sub_pre_key = tx_store.pre_key_store();
        let mut sub_session = tx_store.session_store();
        sub_pre_key.remove_pre_key(id).await.unwrap();
        let session = SessionRecord::new_fresh();
        sub_session.store_session(&addr, &session).await.unwrap();
    }
    tx_store.commit().await.unwrap();

    // Both effects are now visible at the pool.
    assert!(
        PreKeyStore::get_pre_key(&store.clone(), id).await.is_err(),
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
    PreKeyStore::save_pre_key(&mut store.clone(), id, &record)
        .await
        .unwrap();

    let tx = store.pool().begin().await.unwrap();
    {
        let tx_store = TxStore::new(tx);
        let mut sub_pre_key = tx_store.pre_key_store();
        sub_pre_key.remove_pre_key(id).await.unwrap();
        // Drop tx_store without commit() - simulating a panic mid-
        // decrypt before the session write would have happened.
    }

    // The prekey must still exist - if rollback didn't fire, the next
    // boot would replay the envelope but the prekey would be gone.
    assert!(
        PreKeyStore::get_pre_key(&store.clone(), id).await.is_ok(),
        "prekey must be restored after rollback"
    );
}
