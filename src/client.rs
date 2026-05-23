//! The public `Client`: opens a state directory, exposes
//! [`Client::run_receive_loop`] / [`Client::send`] over a single
//! authenticated chat WebSocket, broadcasts decoded envelopes through a
//! tokio broadcast channel.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use libsignal_net::chat::server_requests::ServerEvent;
use libsignal_net::chat::{AuthenticatedChatHeaders, ChatConnection, LanguageList, ReceiveStories};
use libsignal_protocol::{
    Aci, CiphertextMessage, DeviceId, PreKeySignalMessage, ProtocolAddress, SessionStore, SignalMessage,
};
use log::{debug, info, warn};
use prost::Message as _;
use thiserror::Error;
use tokio::sync::broadcast;

use crate::crypto::provisioning::proto;
use crate::envelope::Envelope;
use crate::net::{self, Environment as NetEnv, NetError};
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
    #[error("libsignal-net connect error: {0}")]
    Net(#[from] NetError),

    #[error("device has been deauthorized")]
    Deauthorized,

    #[error("storage error: {0}")]
    Storage(#[from] StoreError),

    #[error("libsignal-protocol error: {0}")]
    Signal(#[from] libsignal_protocol::SignalProtocolError),

    #[error("missing credential in store: {0}")]
    MissingCredential(&'static str),

    #[error("invalid ACI in store: {0}")]
    InvalidAci(String),

    #[error("chat connection stopped: {0}")]
    Stopped(String),
}

#[derive(Error, Debug)]
pub enum SendError {
    #[error("device has been deauthorized")]
    Deauthorized,

    #[error("storage error: {0}")]
    Storage(#[from] StoreError),

    #[error("libsignal-protocol error: {0}")]
    Signal(#[from] libsignal_protocol::SignalProtocolError),

    #[error("libsignal-net connect error: {0}")]
    Net(#[from] NetError),

    #[error("send failed: {0}")]
    Server(String),

    #[error("missing credential in store: {0}")]
    MissingCredential(&'static str),

    #[error(
        "non-Note-to-Self sends require E.164 -> ACI resolution via the \
         attested CDSI service, which is out of scope for v0.1. Sending to \
         the account's own number (Note-to-Self via send_sync_message) is \
         supported. target={0}"
    )]
    TargetUnsupported(String),
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
    /// v0.1's CLI surface accepts E.164 because the operator already
    /// knows the number; resolving it to an ACI requires the attested
    /// CDSI service (libsignal-net::cdsi, SGX-attested), which is out
    /// of v0.1 scope. Callers that already know the recipient's ACI
    /// and access-key should use [`Client::send_to_aci`] directly.
    ///
    /// Behavior:
    /// - target == own E.164 number -> Note-to-Self via send_sync_message
    /// - target != own E.164 number -> SendError::TargetUnsupported
    pub async fn send(&self, target: &str, body: &str) -> Result<(), SendError> {
        debug!("Client::send: target={} body_len={}", target, body.len());

        if !self.is_note_to_self(target) {
            return Err(SendError::TargetUnsupported(target.to_string()));
        }
        self.send_note_to_self(body).await
    }

    /// Send a 1:1 text message to a known ACI. The caller must supply
    /// the recipient's `access_key` (16 bytes, derived from their
    /// profile key) so the unauthenticated prekey-bundle fetch can
    /// authorize. For Note-to-Self use [`Client::send`] with the
    /// account's own E.164 number, or [`Client::send_note_to_self`]
    /// directly; that path uses `send_sync_message` and does not need
    /// an access key.
    ///
    /// The flow:
    /// 1. If no session exists for `target`, open an unauthenticated
    ///    chat WebSocket and fetch the prekey bundle via
    ///    `UnauthenticatedChatApi::get_pre_keys`. Process each device's
    ///    bundle into a fresh session via `process_prekey_bundle`.
    /// 2. Encrypt the message via libsignal-protocol's `message_encrypt`.
    /// 3. Open an authenticated chat WebSocket and dispatch via
    ///    `AuthenticatedChatApi::send_message`.
    ///
    /// Atomicity: encrypt + session-state persist + outbound-record
    /// happen inside one `sqlx::Transaction` (mirrors the receive
    /// pipeline's contract).
    pub async fn send_to_aci(
        &self,
        target: Aci,
        body: &str,
        access_key: [u8; zkgroup::ACCESS_KEY_LEN],
    ) -> Result<(), SendError> {
        use libsignal_net_chat::api::keys::{DeviceSpecifier, UnauthenticatedChatApi};
        use libsignal_net_chat::api::messages::{AuthenticatedChatApi, SingleOutboundUnsealedMessage};
        use libsignal_net_chat::api::{Auth, Unauth, UserBasedAuthorization};
        use libsignal_protocol::ServiceId;

        debug!(
            "Client::send_to_aci: target={} body_len={}",
            target.service_id_string(),
            body.len()
        );

        let aci_string = self
            .inner
            .store
            .get_aci()
            .await?
            .ok_or(SendError::MissingCredential("aci"))?;
        let local_device_id = device_id_from_u32(self.inner.identity.device_id)
            .map_err(|e| SendError::Server(format!("device_id: {e}")))?;
        let local_address = ProtocolAddress::new(aci_string.clone(), local_device_id);

        // 1. Check whether we already hold any session for the target's
        //    ACI. If we do, skip the unauthenticated `get_pre_keys`
        //    fetch entirely — fetching consumes a one-time prekey from
        //    the recipient's server-side pool, so repeatedly sending to
        //    a known recipient would burn through their prekeys.
        //    Per the design doc: "If no session exists for the target,
        //    fetch their prekey bundle".
        let target_service_id_string = target.service_id_string();
        let known_device_ids = self
            .inner
            .store
            .session_device_ids_for_service_id(&target_service_id_string)
            .await?;

        let bundles_to_process: Option<Vec<libsignal_protocol::PreKeyBundle>> = if known_device_ids.is_empty() {
            // Cold path: no sessions yet. Fetch all device bundles.
            let (unauth_chat, unauth_events) = net::connect_chat_unauthenticated(NetEnv::Production)
                .await
                .map_err(|e| SendError::Server(format!("open unauth chat: {e}")))?;
            drop(unauth_events);
            let unauth = Unauth(unauth_chat);
            let (_, bundles) = unauth
                .get_pre_keys(
                    UserBasedAuthorization::AccessKey(access_key),
                    ServiceId::from(target),
                    DeviceSpecifier::AllDevices,
                )
                .await
                .map_err(|e| SendError::Server(format!("get_pre_keys: {e:?}")))?;
            unauth.0.disconnect().await;
            if bundles.is_empty() {
                return Err(SendError::Server("get_pre_keys returned no device bundles".to_string()));
            }
            Some(bundles)
        } else {
            None
        };

        // 2. Encrypt one ciphertext per recipient device, threading
        //    session-state writes through one transaction. TxStore owns
        //    the transaction; sub-stores share it via Arc<Mutex<_>>.
        let pool = self.inner.store.pool().clone();
        let tx = pool.begin().await.map_err(StoreError::from)?;
        let tx_store = crate::storage::tx::TxStore::new(tx);
        let mut session = tx_store.session_store();
        let mut identity = tx_store.identity_store();
        let mut outbound: Vec<SingleOutboundUnsealedMessage<CiphertextMessage>> = Vec::new();

        if let Some(bundles) = bundles_to_process {
            // Cold path: process each fetched bundle into a session, then
            // encrypt for that device.
            for bundle in bundles.iter() {
                let device_id = bundle.device_id().map_err(SendError::Signal)?;
                let registration_id = bundle.registration_id().map_err(SendError::Signal)?;
                let remote_address = ProtocolAddress::new(target_service_id_string.clone(), device_id);

                libsignal_protocol::process_prekey_bundle(
                    &remote_address,
                    &local_address,
                    &mut session,
                    &mut identity,
                    bundle,
                    std::time::SystemTime::now(),
                    &mut rand::rng(),
                )
                .await?;

                let content_bytes = build_one_to_one_content(body, now_millis());
                let ciphertext = libsignal_protocol::message_encrypt(
                    &content_bytes,
                    &remote_address,
                    &local_address,
                    &mut session,
                    &mut identity,
                    std::time::SystemTime::now(),
                    &mut rand::rng(),
                )
                .await?;
                outbound.push(SingleOutboundUnsealedMessage {
                    device_id,
                    registration_id,
                    contents: ciphertext,
                });
            }
        } else {
            // Hot path: encrypt against existing sessions, no bundle
            // fetch. If the recipient added a new device since we last
            // talked, send_message will return MismatchedDevices and the
            // caller can retry with a fresh fetch.
            for device_id_u32 in &known_device_ids {
                let device_id =
                    device_id_from_u32(*device_id_u32).map_err(|e| SendError::Server(format!("device_id: {e}")))?;
                let remote_address = ProtocolAddress::new(target_service_id_string.clone(), device_id);
                let session_record = SessionStore::load_session(&session, &remote_address)
                    .await?
                    .ok_or_else(|| SendError::Server(format!("session row for device {device_id} disappeared")))?;
                let registration_id = session_record.remote_registration_id().map_err(SendError::Signal)?;

                let content_bytes = build_one_to_one_content(body, now_millis());
                let ciphertext = libsignal_protocol::message_encrypt(
                    &content_bytes,
                    &remote_address,
                    &local_address,
                    &mut session,
                    &mut identity,
                    std::time::SystemTime::now(),
                    &mut rand::rng(),
                )
                .await?;
                outbound.push(SingleOutboundUnsealedMessage {
                    device_id,
                    registration_id,
                    contents: ciphertext,
                });
            }
        }
        drop(session);
        drop(identity);
        tx_store.commit().await.map_err(StoreError::from)?;

        // 3. Dispatch over the authenticated chat WebSocket.
        let (auth_chat, auth_events) = self
            .open_authenticated_chat()
            .await
            .map_err(|e| SendError::Server(format!("open auth chat: {e}")))?;
        drop(auth_events);
        let auth = Auth(auth_chat);
        auth.send_message(
            ServiceId::from(target),
            libsignal_protocol::Timestamp::from_epoch_millis(now_millis()),
            &outbound,
            false, // online_only
            true,  // urgent
        )
        .await
        .map_err(|e| SendError::Server(format!("send_message: {e:?}")))?;

        info!("send_to_aci: dispatched to {} devices", outbound.len());
        Ok(())
    }

    fn is_note_to_self(&self, target: &str) -> bool {
        target == self.inner.identity.account_number
    }

    /// Encrypt a Note-to-Self transcript to each of the user's OTHER
    /// linked devices and dispatch via `send_sync_message`. The chat
    /// server fans the encrypted blobs to those devices; the user's
    /// other devices decode and surface them as `SyncMessage::Sent`.
    ///
    /// Routing: Signal's sync-message contract is "encrypt the same
    /// transcript once per other-device, addressed `own_aci.device_id`".
    /// We must NOT include our own device_id in the contents — the chat
    /// server rejects that. For v0.1, the set of "other devices" is
    /// inferred from existing sessions under the own-ACI prefix, or
    /// defaults to the primary device (id=1) when no sync sessions
    /// exist yet (we are the secondary, so the primary is always the
    /// other end).
    ///
    /// Atomicity: encrypt + session-state persist run inside one
    /// `sqlx::Transaction` via TxStore, matching the receive-side
    /// contract. On dispatch failure the transaction commits (we did
    /// the work; the server retry will re-dispatch, not re-encrypt).
    async fn send_note_to_self(&self, body: &str) -> Result<(), SendError> {
        use libsignal_net_chat::api::Auth;
        use libsignal_net_chat::api::messages::{AuthenticatedChatApi, SingleOutboundUnsealedMessage};

        let aci_string = self
            .inner
            .store
            .get_aci()
            .await?
            .ok_or(SendError::MissingCredential("aci"))?;
        let own_aci =
            Aci::parse_from_service_id_string(&aci_string).ok_or(SendError::MissingCredential("aci-parse"))?;
        let local_device_id = device_id_from_u32(self.inner.identity.device_id)
            .map_err(|e| SendError::Server(format!("device_id: {e}")))?;
        let local_device_id_u32 = self.inner.identity.device_id;
        let local_address = ProtocolAddress::new(aci_string.clone(), local_device_id);

        // Enumerate the user's OTHER device IDs.  Filter out self.
        let mut other_device_ids: Vec<u32> = self
            .inner
            .store
            .session_device_ids_for_service_id(&aci_string)
            .await?
            .into_iter()
            .filter(|id| *id != local_device_id_u32)
            .collect();
        if other_device_ids.is_empty() {
            // No persisted sync sessions yet. As a secondary, the primary
            // phone is device_id=1; encrypt to it. If 1 == self (i.e. we
            // are the primary), there are no other devices and the sync
            // is a no-op.
            if local_device_id_u32 != 1 {
                other_device_ids.push(1);
            }
        }
        if other_device_ids.is_empty() {
            info!("send_note_to_self: no other devices to sync to (we are the only device); no-op");
            return Ok(());
        }

        let content_bytes = build_sync_self_content(body, &aci_string, now_millis());

        // Encrypt one ciphertext per other-device inside a single
        // transaction so session-state writes commit or roll back as a
        // unit (atomicity contract from Phase 6).
        let pool = self.inner.store.pool().clone();
        let tx = pool.begin().await.map_err(StoreError::from)?;
        let tx_store = crate::storage::tx::TxStore::new(tx);
        let mut session = tx_store.session_store();
        let mut identity = tx_store.identity_store();
        let mut outbound: Vec<SingleOutboundUnsealedMessage<CiphertextMessage>> =
            Vec::with_capacity(other_device_ids.len());

        for device_id_u32 in &other_device_ids {
            let device_id =
                device_id_from_u32(*device_id_u32).map_err(|e| SendError::Server(format!("device_id: {e}")))?;
            let remote_address = ProtocolAddress::new(aci_string.clone(), device_id);

            // We don't process_prekey_bundle here: linking already
            // established the session with the primary, and if it
            // hasn't, the message_encrypt below will return
            // SessionNotFound. Callers handle that by re-linking.
            let ciphertext = libsignal_protocol::message_encrypt(
                &content_bytes,
                &remote_address,
                &local_address,
                &mut session,
                &mut identity,
                std::time::SystemTime::now(),
                &mut rand::rng(),
            )
            .await?;

            // Look up the registration_id for this device from its
            // session record so the chat server can route the
            // ciphertext. If we somehow don't have a session, fall back
            // to our own registration_id (signal-cli does the same as a
            // last resort for sync targets).
            let registration_id = SessionStore::load_session(&session, &remote_address)
                .await?
                .and_then(|r| r.remote_registration_id().ok())
                .unwrap_or(self.inner.identity.registration_id);

            outbound.push(SingleOutboundUnsealedMessage {
                device_id,
                registration_id,
                contents: ciphertext,
            });
        }

        drop(session);
        drop(identity);
        tx_store.commit().await.map_err(StoreError::from)?;

        let (auth_chat, events) = self
            .open_authenticated_chat()
            .await
            .map_err(|e| SendError::Server(format!("open auth chat: {e}")))?;
        drop(events); // Receive-side listener channel is not used by send.
        let api = Auth(auth_chat);
        api.send_sync_message(
            libsignal_protocol::Timestamp::from_epoch_millis(now_millis()),
            &outbound,
            true, // urgent
        )
        .await
        .map_err(|e| SendError::Server(format!("send_sync_message: {e:?}")))?;

        let _ = own_aci; // ACI is implicit in the auth headers.
        info!(
            "send_note_to_self: dispatched body_len={} to {} other device(s)",
            body.len(),
            outbound.len()
        );
        Ok(())
    }

    /// Run the receive loop. Opens an authenticated chat WebSocket with
    /// the persisted credentials, consumes `ws::ListenerEvent`s from
    /// libsignal-net, decrypts each `IncomingMessage`'s envelope via
    /// libsignal-protocol against a transaction-scoped [`TxStore`],
    /// broadcasts the decoded [`Envelope`] to subscribers, and ACKs
    /// each message to the server only after the transaction commits.
    ///
    /// Per the design doc's atomicity contract:
    /// - decrypt + session-state persist happen inside a single
    ///   `sqlx::Transaction` so a crash between yield and persist cannot
    ///   desync the ratchet.
    /// - decrypt failures (Bad MAC, unknown prekey, identity mismatch)
    ///   log WARN, drop the envelope, and do NOT tear down the
    ///   connection.
    pub async fn run_receive_loop(&self) -> Result<(), ReceiveError> {
        let (chat, mut events) = self.open_authenticated_chat().await?;
        debug!("run_receive_loop: authenticated chat connected, entering event loop");

        let local_aci = self
            .inner
            .store
            .get_aci()
            .await?
            .ok_or(ReceiveError::MissingCredential("aci"))?;
        let local_address = ProtocolAddress::new(local_aci.clone(), device_id_from_u32(self.inner.identity.device_id)?);

        while let Some(raw) = events.recv().await {
            let event = match ServerEvent::try_from(raw) {
                Ok(e) => e,
                Err(e) => {
                    warn!("run_receive_loop: unparseable server event: {e}");
                    continue;
                }
            };
            match event {
                ServerEvent::QueueEmpty => {
                    info!("run_receive_loop: server reports queue empty");
                    // Best-effort prekey replenishment trigger - if our
                    // remaining one-time prekey count looks low, generate
                    // and upload a fresh batch.
                    if let Err(e) = self.maybe_replenish_prekeys().await {
                        warn!("run_receive_loop: prekey replenishment failed: {e}; will retry on next batch");
                    }
                }
                ServerEvent::Alerts(alerts) => {
                    for a in alerts {
                        warn!("run_receive_loop: server alert: {a}");
                    }
                }
                ServerEvent::Stopped(cause) => {
                    let msg = format!("{cause:?}");
                    warn!("run_receive_loop: chat connection stopped: {msg}");
                    return Err(ReceiveError::Stopped(msg));
                }
                ServerEvent::IncomingMessage { envelope, send_ack, .. } => {
                    match self.process_envelope(&envelope, &local_address).await {
                        Ok(Some(decoded)) => {
                            let _ = self.inner.receive_tx.send(decoded);
                            let _ = send_ack(http::StatusCode::OK);
                        }
                        Ok(None) => {
                            // Receipt or other non-payload envelope; ack only.
                            let _ = send_ack(http::StatusCode::OK);
                        }
                        Err(e) => {
                            warn!(
                                "run_receive_loop: dropping envelope after decrypt failure: {e}; \
                                 connection remains open per design contract"
                            );
                            // Ack with 400 so the server marks the message as
                            // processed; we cannot do anything further with a
                            // garbled envelope.
                            let _ = send_ack(http::StatusCode::BAD_REQUEST);
                        }
                    }
                }
            }
        }

        info!("run_receive_loop: event channel closed; disconnecting chat");
        chat.disconnect().await;
        Ok(())
    }

    /// Open an authenticated chat WebSocket from persisted credentials.
    async fn open_authenticated_chat(
        &self,
    ) -> Result<
        (
            ChatConnection,
            tokio::sync::mpsc::UnboundedReceiver<libsignal_net::chat::ws::ListenerEvent>,
        ),
        ReceiveError,
    > {
        let aci_string = self
            .inner
            .store
            .get_aci()
            .await?
            .ok_or(ReceiveError::MissingCredential("aci"))?;
        let aci = Aci::parse_from_service_id_string(&aci_string)
            .ok_or_else(|| ReceiveError::InvalidAci(aci_string.clone()))?;
        let password = self
            .inner
            .store
            .get_password()
            .await?
            .ok_or(ReceiveError::MissingCredential("password"))?;

        let headers = AuthenticatedChatHeaders {
            aci,
            device_id: device_id_from_u32(self.inner.identity.device_id)?,
            password,
            receive_stories: ReceiveStories::from(false),
            languages: LanguageList::default(),
        };
        let conn = net::connect_chat_authenticated(NetEnv::Production, headers).await?;
        Ok(conn)
    }

    /// Decode one envelope's ciphertext, decrypt it through libsignal-
    /// protocol's session cipher in a single `sqlx::Transaction` via
    /// the per-trait `TxStore` sub-stores, commit, then broadcast.
    ///
    /// Atomicity contract (design doc § Phase 6):
    /// - Decrypt + session-state persist + prekey consumption happen
    ///   inside one `sqlx::Transaction`. If anything fails before the
    ///   commit, the transaction is rolled back and the envelope is
    ///   reprocessed cleanly on the next connect.
    /// - Decrypt failures (Bad MAC, unknown prekey, identity mismatch)
    ///   return Err here and the receive loop logs WARN and drops the
    ///   envelope without disconnecting.
    async fn process_envelope(
        &self,
        envelope_bytes: &[u8],
        local_address: &ProtocolAddress,
    ) -> Result<Option<Envelope>, ReceiveError> {
        let wire = proto::Envelope::decode(envelope_bytes).map_err(|e| {
            ReceiveError::Signal(libsignal_protocol::SignalProtocolError::InvalidArgument(format!(
                "envelope decode: {e}"
            )))
        })?;

        let envelope_type = wire.r#type();
        let content = match wire.content.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => {
                debug!("process_envelope: envelope has no content (type={envelope_type:?}); skipping");
                return Ok(None);
            }
        };

        let ciphertext = match envelope_type {
            proto::envelope::Type::Ciphertext => CiphertextMessage::SignalMessage(SignalMessage::try_from(content)?),
            proto::envelope::Type::PrekeyBundle => {
                CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(content)?)
            }
            other => {
                debug!("process_envelope: ignoring envelope type {other:?} for v0.1");
                return Ok(None);
            }
        };

        let source_service_id = wire
            .source_service_id
            .as_deref()
            .ok_or(ReceiveError::MissingCredential("source_service_id"))?;
        let source_device = wire.source_device.unwrap_or(1);
        let remote_address = ProtocolAddress::new(source_service_id.to_string(), device_id_from_u32(source_device)?);

        let pool = self.inner.store.pool().clone();
        let tx = pool.begin().await.map_err(StoreError::from)?;
        let tx_store = crate::storage::tx::TxStore::new(tx);
        let mut session = tx_store.session_store();
        let mut identity = tx_store.identity_store();
        let mut pre_key = tx_store.pre_key_store();
        let signed_pre_key = tx_store.signed_pre_key_store();
        let mut kyber = tx_store.kyber_pre_key_store();

        let plaintext = libsignal_protocol::message_decrypt(
            &ciphertext,
            &remote_address,
            local_address,
            &mut session,
            &mut identity,
            &mut pre_key,
            &signed_pre_key,
            &mut kyber,
            &mut rand::rng(),
        )
        .await?;

        drop(session);
        drop(identity);
        drop(pre_key);
        drop(signed_pre_key);
        drop(kyber);
        tx_store.commit().await.map_err(StoreError::from)?;

        let decoded = decode_content(&plaintext, &wire);
        Ok(decoded)
    }
}

/// Translate decrypted Signal Content protobuf bytes into our public
/// [`Envelope`] enum. v0.1 surfaces DataMessage and SyncMessage::Sent;
/// everything else is dropped.
fn decode_content(plaintext: &[u8], wire: &proto::Envelope) -> Option<Envelope> {
    use crate::envelope::{DataMessage, SyncMessage};

    let content = decode_top_level_content(plaintext)?;

    if let Some(dm_bytes) = content.data_message_bytes.as_deref() {
        // v0.1 surfaces just the body + timestamp; richer DataMessage fields
        // (attachments, mentions, etc.) land in a future release.
        let body = decode_data_message_body(dm_bytes);
        let timestamp = wire.timestamp.unwrap_or(0);
        let source = wire.source_service_id.clone().unwrap_or_default();
        let dm = DataMessage { body, timestamp };
        return Some(Envelope::DataMessage {
            source,
            timestamp,
            message: dm,
        });
    }

    if let Some(sm_bytes) = content.sync_message_bytes.as_deref()
        && let Some(sent) = decode_sync_sent(sm_bytes)
    {
        let dm = DataMessage {
            body: sent.body,
            timestamp: sent.timestamp,
        };
        return Some(Envelope::SyncMessage(SyncMessage::Sent {
            destination: sent.destination,
            timestamp: sent.timestamp,
            message: dm,
        }));
    }

    None
}

/// The relevant slice of Signal's `Content` protobuf for v0.1: the bytes
/// of `data_message` and `sync_message`, decoded lazily by their callers.
#[derive(prost::Message)]
struct TopLevelContent {
    #[prost(bytes, optional, tag = "1")]
    data_message_bytes: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "2")]
    sync_message_bytes: Option<Vec<u8>>,
}

fn decode_top_level_content(bytes: &[u8]) -> Option<TopLevelContent> {
    use prost::Message as _;
    TopLevelContent::decode(bytes).ok()
}

/// Best-effort: pull the `body` field out of a serialized DataMessage. We
/// avoid vendoring the full DataMessage proto by reaching for prost's
/// Message::merge on a minimal shape; failures fall back to empty.
fn decode_data_message_body(bytes: &[u8]) -> Option<String> {
    #[derive(prost::Message)]
    struct MinimalDataMessage {
        #[prost(string, optional, tag = "1")]
        body: Option<String>,
    }
    MinimalDataMessage::decode(bytes).ok().and_then(|m| m.body)
}

struct SentSlice {
    destination: String,
    timestamp: u64,
    body: Option<String>,
}

/// Best-effort: pull `destination_service_id`, `timestamp`, and
/// `message.body` out of a serialized SyncMessage's `sent` field. The
/// shape Signal uses is `SyncMessage { sent: Sent { destination, timestamp,
/// message: DataMessage { body, ... } } }`.
fn decode_sync_sent(bytes: &[u8]) -> Option<SentSlice> {
    #[derive(prost::Message)]
    struct MinimalSent {
        #[prost(string, optional, tag = "7")]
        destination_service_id: Option<String>,
        #[prost(uint64, optional, tag = "2")]
        timestamp: Option<u64>,
        #[prost(bytes, optional, tag = "1")]
        message: Option<Vec<u8>>,
    }
    #[derive(prost::Message)]
    struct MinimalSyncMessage {
        #[prost(bytes, optional, tag = "1")]
        sent: Option<Vec<u8>>,
    }
    let sm = MinimalSyncMessage::decode(bytes).ok()?;
    let sent_bytes = sm.sent?;
    let sent = MinimalSent::decode(sent_bytes.as_slice()).ok()?;
    let destination = sent.destination_service_id.unwrap_or_default();
    let timestamp = sent.timestamp.unwrap_or(0);
    let body = sent.message.as_deref().and_then(decode_data_message_body);
    Some(SentSlice {
        destination,
        timestamp,
        body,
    })
}

#[allow(dead_code)]
const RECEIVE_LOOP_RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Current epoch milliseconds. Wire protocol uses uint64 ms.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Client {
    /// Phase 8 prekey replenishment. Counts the persisted one-time
    /// prekey rows; if below the design-doc's `PREKEY_LOW_WATERMARK`,
    /// generates and uploads a fresh batch.
    ///
    /// This is the consumer trigger described in Phase 8: the receive
    /// loop's batch-ack cycle (a `QueueEmpty` event) is the canonical
    /// signal that we've successfully processed everything the server
    /// had, which is a good time to ensure the next inbound peer has
    /// keys to start a session.
    async fn maybe_replenish_prekeys(&self) -> Result<(), ReceiveError> {
        use crate::crypto::prekeys::{PREKEY_LOW_WATERMARK, generate_and_persist_batch, upload_batch};

        let pool = self.inner.store.pool().clone();
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM prekeys")
            .fetch_one(&pool)
            .await
            .map_err(StoreError::from)?;
        let remaining = row.0 as u32;
        debug!(
            "maybe_replenish_prekeys: remaining={} watermark={}",
            remaining, PREKEY_LOW_WATERMARK
        );
        if remaining >= PREKEY_LOW_WATERMARK {
            return Ok(());
        }

        let next_id: (Option<i64>,) = sqlx::query_as("SELECT MAX(id) FROM prekeys")
            .fetch_one(&pool)
            .await
            .map_err(StoreError::from)?;
        let next_id = next_id.0.map(|v| v as u32).unwrap_or(0).saturating_add(1);

        let mut rng = rand::rng();
        let batch = generate_and_persist_batch(&mut rng, &self.inner.store, next_id)
            .await
            .map_err(|e| ReceiveError::Stopped(format!("generate_and_persist_batch: {e}")))?;
        upload_batch(&self.inner.store, &batch)
            .await
            .map_err(|e| ReceiveError::Stopped(format!("upload_batch: {e}")))?;

        info!("maybe_replenish_prekeys: uploaded batch starting at id={}", next_id);
        Ok(())
    }
}

/// Build the inner Content protobuf for a 1:1 send: a DataMessage with
/// the body and timestamp, wrapped in the top-level Content.
fn build_one_to_one_content(body: &str, timestamp: u64) -> Vec<u8> {
    use prost::Message as _;

    #[derive(prost::Message)]
    struct MinimalDataMessage {
        #[prost(string, optional, tag = "1")]
        body: Option<String>,
        #[prost(uint64, optional, tag = "3")]
        timestamp: Option<u64>,
    }
    #[derive(prost::Message)]
    struct MinimalContent {
        #[prost(bytes, optional, tag = "1")]
        data_message: Option<Vec<u8>>,
    }

    let dm = MinimalDataMessage {
        body: Some(body.to_string()),
        timestamp: Some(timestamp),
    };
    let content = MinimalContent {
        data_message: Some(dm.encode_to_vec()),
    };
    content.encode_to_vec()
}

/// Build the inner Content protobuf for a Note-to-Self send: wraps the
/// body as a DataMessage and tags it via SyncMessage::Sent so the
/// receiver-side filter (`destination == own_number`) fires.
fn build_sync_self_content(body: &str, own_destination: &str, timestamp: u64) -> Vec<u8> {
    use prost::Message as _;

    #[derive(prost::Message)]
    struct MinimalDataMessage {
        #[prost(string, optional, tag = "1")]
        body: Option<String>,
        #[prost(uint64, optional, tag = "3")]
        timestamp: Option<u64>,
    }
    #[derive(prost::Message)]
    struct MinimalSent {
        #[prost(string, optional, tag = "7")]
        destination_service_id: Option<String>,
        #[prost(uint64, optional, tag = "2")]
        timestamp: Option<u64>,
        #[prost(bytes, optional, tag = "1")]
        message: Option<Vec<u8>>,
    }
    #[derive(prost::Message)]
    struct MinimalSyncMessage {
        #[prost(bytes, optional, tag = "1")]
        sent: Option<Vec<u8>>,
    }
    #[derive(prost::Message)]
    struct MinimalContent {
        #[prost(bytes, optional, tag = "2")]
        sync_message: Option<Vec<u8>>,
    }

    let dm = MinimalDataMessage {
        body: Some(body.to_string()),
        timestamp: Some(timestamp),
    };
    let sent = MinimalSent {
        destination_service_id: Some(own_destination.to_string()),
        timestamp: Some(timestamp),
        message: Some(dm.encode_to_vec()),
    };
    let sm = MinimalSyncMessage {
        sent: Some(sent.encode_to_vec()),
    };
    let content = MinimalContent {
        sync_message: Some(sm.encode_to_vec()),
    };
    content.encode_to_vec()
}

/// Convert a `u32` device id loaded from storage into libsignal's
/// `DeviceId` (which is a NonZeroU8 underneath). Device ids issued by
/// Signal's chat-server fit in u8; anything larger is store corruption.
fn device_id_from_u32(id: u32) -> Result<DeviceId, ReceiveError> {
    let as_u8: u8 = id
        .try_into()
        .map_err(|_| ReceiveError::InvalidAci(format!("device_id {id} out of u8 range")))?;
    DeviceId::new(as_u8).map_err(|_| ReceiveError::InvalidAci(format!("device_id {id} zero")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
