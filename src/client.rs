//! The public `Client`: borg's primary entry. Holds the SQLite pool +
//! a broadcast channel for received envelopes. The live ChatConnection
//! wiring is Phase 10 work; v0.1 ships the surface borg compiles
//! against, with send/receive operating in a "structural" mode that
//! returns clear NotImplemented errors until Phase 10.

use std::path::Path;
use std::sync::Arc;

use log::{debug, info, warn};
use thiserror::Error;
use tokio::sync::broadcast;

use crate::envelope::Envelope;
use crate::storage::{Identity, SqliteStore, Store, StoreError};

const RECEIVE_CHANNEL_CAPACITY: usize = 256;

#[derive(Error, Debug)]
pub enum OpenError {
    #[error("storage error: {0}")]
    Storage(#[from] StoreError),

    #[error("state directory has not been linked - run `signal-rs link` first")]
    NotLinked,

    #[error("state directory is partially linked - re-run linking to resume")]
    PartiallyLinked,

    #[error("state directory is locked by another signal-rs process")]
    AlreadyOpen,

    #[error("device has been deauthorized from the primary's Linked Devices list")]
    Deauthorized,
}

#[derive(Error, Debug)]
pub enum ReceiveError {
    #[error(
        "live receive loop is not yet wired up; \
         Phase 10 manual smoke test will exercise libsignal-net::chat"
    )]
    LiveLoopNotImplemented,

    #[error("device has been deauthorized")]
    Deauthorized,

    #[error("storage error: {0}")]
    Storage(#[from] StoreError),
}

#[derive(Error, Debug)]
pub enum SendError {
    #[error(
        "live send is not yet wired up; \
         Phase 10 manual smoke test will exercise libsignal-net-chat::AuthenticatedChatApi"
    )]
    LiveSendNotImplemented,

    #[error("device has been deauthorized")]
    Deauthorized,

    #[error("storage error: {0}")]
    Storage(#[from] StoreError),

    #[error("libsignal-protocol error: {0}")]
    Signal(#[from] libsignal_protocol::SignalProtocolError),
}

/// The Signal client. One per state directory. Owns the SQLite pool
/// for its lifetime. Once Phase 10 wires up the live chat connection,
/// the receive loop is a single broadcast producer and `receive`
/// callers are subscribers.
pub struct Client {
    inner: Arc<ClientInner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("account_number", &self.inner.identity.account_number)
            .field("device_id", &self.inner.identity.device_id)
            .finish_non_exhaustive()
    }
}

struct ClientInner {
    store: SqliteStore,
    identity: Identity,
    receive_tx: broadcast::Sender<Envelope>,
}

impl Client {
    /// Open an existing state directory. Loads identity. Refuses if the
    /// state isn't Linked. Does NOT perform any network I/O - that
    /// happens when `receive()` or `send()` is called.
    pub async fn open(state_dir: &Path) -> Result<Self, OpenError> {
        debug!("Client::open: state_dir={}", state_dir.display());
        let db_path = state_dir.join("store.db");
        let store = SqliteStore::open(&db_path).await?;

        let identity = match store.load_identity().await {
            Ok(id) => id,
            Err(StoreError::NotLinked) => return Err(OpenError::NotLinked),
            Err(StoreError::PartiallyLinked { .. }) => return Err(OpenError::PartiallyLinked),
            Err(e) => return Err(OpenError::Storage(e)),
        };

        let (receive_tx, _) = broadcast::channel(RECEIVE_CHANNEL_CAPACITY);
        info!(
            "Client::open: opened state_dir={} account={} device_id={}",
            state_dir.display(),
            identity.account_number,
            identity.device_id
        );
        Ok(Self {
            inner: Arc::new(ClientInner {
                store,
                identity,
                receive_tx,
            }),
        })
    }

    /// The account's own E.164 number. borg uses this to apply the
    /// Note-to-Self filter on incoming SyncMessage::Sent.
    pub fn account_number(&self) -> &str {
        &self.inner.identity.account_number
    }

    /// Subscribe to incoming envelopes. Multiple subscribers are
    /// allowed (they share the underlying WebSocket via broadcast).
    /// Slow subscribers that fall behind get a `Lagged` error from the
    /// stream; the stream resumes from the next available envelope.
    pub fn receive(&self) -> broadcast::Receiver<Envelope> {
        self.inner.receive_tx.subscribe()
    }

    /// Returns a clone of the underlying store, intended for callers
    /// that need to drive libsignal-protocol storage traits directly
    /// (e.g. an out-of-band prekey replenishment task). The pool is
    /// shared internally; cloning is cheap.
    pub fn store(&self) -> SqliteStore {
        self.inner.store.clone()
    }

    /// Send a 1:1 text message. `target` is an E.164 number. Pass the
    /// account's own number to fan out a Note-to-Self.
    ///
    /// **Returns `SendError::LiveSendNotImplemented` in v0.1.** Phase 10
    /// wires this to libsignal-net-chat::AuthenticatedChatApi.
    pub async fn send(&self, target: &str, body: &str) -> Result<(), SendError> {
        warn!(
            "Client::send: target={} body_len={} - live send is Phase 10",
            target,
            body.len()
        );
        Err(SendError::LiveSendNotImplemented)
    }

    /// Run the receive loop (consume libsignal-net::chat ListenerEvents,
    /// decrypt, persist atomically via TxStore, broadcast).
    ///
    /// **Returns `ReceiveError::LiveLoopNotImplemented` in v0.1.** Phase 10
    /// wires this to libsignal-net::chat::ChatConnection.
    pub async fn run_receive_loop(&self) -> Result<(), ReceiveError> {
        warn!("Client::run_receive_loop: live loop is Phase 10");
        Err(ReceiveError::LiveLoopNotImplemented)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
