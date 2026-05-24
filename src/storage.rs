//! Storage backend abstractions and SQLite implementation.
//!
//! `Store` is signal-rs's own identity-level API (account number, device id,
//! link status, identity keypair). The five libsignal-protocol storage traits
//! (`IdentityKeyStore`, `SessionStore`, `PreKeyStore`, `SignedPreKeyStore`,
//! `KyberPreKeyStore`) are implemented on the same backing store so the
//! libsignal-protocol session cipher can drive it directly.

pub mod sqlite;
pub mod tx;

pub use sqlite::SqliteStore;
pub use tx::TxStore;

use libsignal_protocol::IdentityKeyPair;
use serde::Serialize;
use thiserror::Error;

/// The handshake state of the linked device, persisted under `identity.link_status`.
///
/// `IdentityPersisted` means [`link`] wrote the device's keys but the initial
/// prekey upload to Signal's keyserver never completed; the device is silently
/// unreachable by new peers and the operator must re-run linking to finish.
/// `Linked` is the steady state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkStatus {
    IdentityPersisted,
    Linked,
}

impl LinkStatus {
    /// On-disk form. PascalCase is the historical encoding written to
    /// the `identity.link_status` row; changing it would require a
    /// migration. Use [`std::fmt::Display`] for user-facing output -
    /// that produces the snake_case form that matches the serde JSON.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            LinkStatus::IdentityPersisted => "IdentityPersisted",
            LinkStatus::Linked => "Linked",
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            "IdentityPersisted" => Some(LinkStatus::IdentityPersisted),
            "Linked" => Some(LinkStatus::Linked),
            _ => None,
        }
    }
}

impl std::fmt::Display for LinkStatus {
    /// Snake-case rendering for human-facing output. Mirrors the
    /// `#[serde(rename_all = "snake_case")]` form so `signal-rs status`
    /// reads the same in text and JSON modes. The on-disk encoding
    /// (PascalCase via [`LinkStatus::as_str`]) is unchanged.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            LinkStatus::IdentityPersisted => "identity_persisted",
            LinkStatus::Linked => "linked",
        };
        f.write_str(s)
    }
}

/// Identity-level state Phase 5 writes during linking and `Client::open` reads.
///
/// Stored as five separate rows in the `identity` singleton table. Loaded
/// atomically via [`Store::load_identity`] so callers see a consistent view.
#[derive(Clone)]
pub struct Identity {
    pub identity_keypair: IdentityKeyPair,
    pub registration_id: u32,
    pub account_number: String,
    pub device_id: u32,
    pub link_status: LinkStatus,
}

// IdentityKeyPair does not implement Debug (libsignal hides private-key material
// from Debug output by design). We provide a Debug impl that elides the keypair
// so identity records can still flow through assertion macros.
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("identity_keypair", &"<elided>")
            .field("registration_id", &self.registration_id)
            .field("account_number", &self.account_number)
            .field("device_id", &self.device_id)
            .field("link_status", &self.link_status)
            .finish()
    }
}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("sqlx migrate error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("libsignal protocol error: {0}")]
    Signal(#[from] libsignal_protocol::SignalProtocolError),

    #[error("identity not persisted - this state dir has not been linked")]
    NotLinked,

    #[error("identity is partially persisted (link_status={status:?}); re-run link to resume")]
    PartiallyLinked { status: LinkStatus },

    #[error("corrupt storage: {0}")]
    Corrupt(String),
}

/// signal-rs's own identity-level API. The libsignal-protocol storage traits
/// are implemented separately on `SqliteStore`.
#[async_trait::async_trait(?Send)]
pub trait Store {
    /// Persist a fresh identity record. Called once at link time.
    async fn save_identity_bundle(
        &self,
        identity_keypair: &IdentityKeyPair,
        registration_id: u32,
        account_number: &str,
        device_id: u32,
        link_status: LinkStatus,
    ) -> Result<(), StoreError>;

    /// Load the identity bundle. Errors with `NotLinked` if no bundle is
    /// persisted, or `PartiallyLinked` if the bundle exists but
    /// `link_status != Linked`.
    async fn load_identity(&self) -> Result<Identity, StoreError>;

    /// Transition the link_status row. Used by Phase 5 to move
    /// IdentityPersisted -> Linked once the initial prekey upload succeeds.
    async fn set_link_status(&self, status: LinkStatus) -> Result<(), StoreError>;
}
