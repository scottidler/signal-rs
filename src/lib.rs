#![deny(clippy::unwrap_used)]
#![deny(dead_code)]
#![deny(unused_variables)]

//! signal-rs - native-Rust Signal client. v0.1 ships the surface borg
//! needs to link as a secondary device, receive Signal envelopes (with
//! Note-to-Self filtering via `SyncMessage::Sent::destination`), and
//! send a 1:1 text message. Live network paths are wired in Phase 10.
//!
//! Public surface:
//! - [`Client`] - the primary entry; one per state directory.
//! - [`Envelope`] / [`SyncMessage`] / [`Recipient`] / [`ReceiptKind`] /
//!   [`ReadReceipt`] / [`AttachmentPointer`] - what `Client::receive`
//!   yields. JSON-serializable for line-delimited stdout consumption.
//! - [`SqliteStore`] / [`Store`] / [`TxStore`] - storage backends.
//! - [`link`], [`finalize_link`], [`persist_provision_message`] -
//!   provisioning helpers; usable directly by consumers who drive
//!   `libsignal-net`'s `ProvisioningConnection` themselves.
//! - [`crypto`] - the ProvisioningCipher port + prekey helpers.

pub mod api;
pub mod client;
pub mod config;
pub mod crypto;
pub mod envelope;
pub mod link;
pub mod net;
pub mod storage;

pub use client::{Client, OpenError, ReceiveError, SendError};
pub use config::Config;
pub use envelope::{AttachmentPointer, Envelope, ReadReceipt, ReceiptKind, Recipient, SyncMessage};
pub use link::{LinkError, LinkOutcome, finalize_link, mark_linked, persist_provision_message, prepare_link_session};
pub use storage::{Identity, LinkStatus, SqliteStore, Store, StoreError, TxStore};
