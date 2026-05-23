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
use log::{debug, info, trace, warn};
use prost::Message as _;
use thiserror::Error;
use tokio::sync::broadcast;

use crate::crypto::provisioning::proto;
use crate::envelope::Envelope;
use crate::net::{self, Environment as NetEnv, NetError};
use crate::storage::{Identity, LinkStatus, SqliteStore, Store, StoreError};

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
            Err(e) => return Err(OpenError::Storage(e)),
        };
        if identity.link_status != LinkStatus::Linked {
            return Err(OpenError::PartiallyLinked);
        }

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
        // Send paths operate AS our ACI identity.
        let mut identity = tx_store.identity_store(crate::crypto::prekeys::IdentityKind::Aci);
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
        let result = target == self.inner.identity.account_number;
        trace!("is_note_to_self: target={} result={}", target, result);
        result
    }

    /// Encrypt a Note-to-Self transcript to each of the user's OTHER
    /// linked devices and dispatch via `send_sync_message`. The chat
    /// server fans the encrypted blobs to those devices; the user's
    /// other devices decode and surface them as `SyncMessage::Sent`.
    ///
    /// Routing: Signal's sync-message contract is "encrypt the same
    /// transcript once per other-device, addressed `own_aci.device_id`".
    /// We must NOT include our own device_id in the contents — the chat
    /// server rejects that.
    ///
    /// Device discovery: hot path uses persisted sessions under the
    /// own-ACI prefix (filtered for !=self). If no sessions exist (cold
    /// path on first Note-to-Self), we fetch ALL the user's device
    /// bundles via `UnauthenticatedChatApi::get_pre_keys(own_aci,
    /// AllDevices)`, authorized via the access-key derived from our
    /// own profile-key. This matches signal-cli's behavior and ensures
    /// we don't miss other secondary devices we haven't talked to yet.
    ///
    /// Atomicity: encrypt + session-state persist run inside one
    /// `sqlx::Transaction` via TxStore, matching the receive-side
    /// contract.
    async fn send_note_to_self(&self, body: &str) -> Result<(), SendError> {
        debug!("send_note_to_self: body_len={}", body.len());
        use libsignal_net_chat::api::keys::{DeviceSpecifier, UnauthenticatedChatApi};
        use libsignal_net_chat::api::messages::{AuthenticatedChatApi, SingleOutboundUnsealedMessage};
        use libsignal_net_chat::api::{Auth, Unauth, UserBasedAuthorization};
        use libsignal_protocol::ServiceId;

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

        // Hot path: any persisted other-device sessions for own_aci.
        let known_other_devices: Vec<u32> = self
            .inner
            .store
            .session_device_ids_for_service_id(&aci_string)
            .await?
            .into_iter()
            .filter(|id| *id != local_device_id_u32)
            .collect();

        // Cold path: fetch bundles for all of our own devices via the
        // authenticated-by-access-key endpoint and process them.
        let bundles_to_process: Option<Vec<libsignal_protocol::PreKeyBundle>> = if known_other_devices.is_empty() {
            let profile_key = self
                .inner
                .store
                .get_profile_key()
                .await?
                .ok_or(SendError::MissingCredential("profile_key"))?;
            let pk_bytes: [u8; zkgroup::PROFILE_KEY_LEN] = profile_key
                .as_slice()
                .try_into()
                .map_err(|_| SendError::Server(format!("profile_key length {}", profile_key.len())))?;
            let access_key = zkgroup::profiles::ProfileKey::create(pk_bytes).derive_access_key();

            let (unauth_chat, unauth_events) = net::connect_chat_unauthenticated(NetEnv::Production)
                .await
                .map_err(|e| SendError::Server(format!("open unauth chat: {e}")))?;
            drop(unauth_events);
            let unauth = Unauth(unauth_chat);
            let (_, bundles) = unauth
                .get_pre_keys(
                    UserBasedAuthorization::AccessKey(access_key),
                    ServiceId::from(own_aci),
                    DeviceSpecifier::AllDevices,
                )
                .await
                .map_err(|e| SendError::Server(format!("get_pre_keys(self,AllDevices): {e:?}")))?;
            unauth.0.disconnect().await;

            // Filter out our own device_id - the server includes us in
            // AllDevices, but we must NOT encrypt to self.
            let bundles: Vec<libsignal_protocol::PreKeyBundle> = bundles
                .into_iter()
                .filter(|b| match b.device_id() {
                    Ok(d) => u32::from(d) != local_device_id_u32,
                    Err(_) => false,
                })
                .collect();
            if bundles.is_empty() {
                info!("send_note_to_self: no other devices to sync to (we are the only device); no-op");
                return Ok(());
            }
            Some(bundles)
        } else {
            None
        };

        let content_bytes = build_sync_self_content(body, &aci_string, now_millis());

        // Encrypt one ciphertext per other-device inside a single
        // transaction so session-state writes commit or roll back as a
        // unit (atomicity contract from Phase 6).
        let pool = self.inner.store.pool().clone();
        let tx = pool.begin().await.map_err(StoreError::from)?;
        let tx_store = crate::storage::tx::TxStore::new(tx);
        let mut session = tx_store.session_store();
        // Send paths operate AS our ACI identity.
        let mut identity = tx_store.identity_store(crate::crypto::prekeys::IdentityKind::Aci);
        let mut outbound: Vec<SingleOutboundUnsealedMessage<CiphertextMessage>> = Vec::new();

        if let Some(bundles) = bundles_to_process {
            // Cold path: process each bundle into a session, then
            // encrypt for that device.
            for bundle in bundles.iter() {
                let device_id = bundle.device_id().map_err(SendError::Signal)?;
                let registration_id = bundle.registration_id().map_err(SendError::Signal)?;
                let remote_address = ProtocolAddress::new(aci_string.clone(), device_id);

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
            // Hot path: encrypt against existing sessions.
            for device_id_u32 in &known_other_devices {
                let device_id =
                    device_id_from_u32(*device_id_u32).map_err(|e| SendError::Server(format!("device_id: {e}")))?;
                let remote_address = ProtocolAddress::new(aci_string.clone(), device_id);

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
        debug!(
            "run_receive_loop: account={} device_id={}",
            self.inner.identity.account_number, self.inner.identity.device_id
        );
        let (chat, mut events) = self.open_authenticated_chat().await?;
        debug!("run_receive_loop: authenticated chat connected, entering event loop");

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
                    match self.process_envelope(&envelope).await {
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
        debug!("open_authenticated_chat: device_id={}", self.inner.identity.device_id);
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
    async fn process_envelope(&self, envelope_bytes: &[u8]) -> Result<Option<Envelope>, ReceiveError> {
        debug!("process_envelope: envelope_len={}", envelope_bytes.len());
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
            proto::envelope::Type::DoubleRatchet => CiphertextMessage::SignalMessage(SignalMessage::try_from(content)?),
            proto::envelope::Type::PrekeyMessage => {
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
        let source_device = wire.source_device_id.unwrap_or(1);
        let remote_address = ProtocolAddress::new(source_service_id.to_string(), device_id_from_u32(source_device)?);

        // Route by envelope.destination_service_id (wire tag 13). The
        // server sets this field on every delivery; PNI-addressed
        // envelopes go to PNI-scoped stores so libsignal asks for the
        // PNI keypair / reg id / prekey rows. Unknown or missing
        // destination defaults to ACI (legacy compatibility).
        let local_aci = self
            .inner
            .store
            .get_aci()
            .await?
            .ok_or(ReceiveError::MissingCredential("aci"))?;
        let local_pni = self.inner.store.get_pni().await?;
        let (identity_kind, local_service_id) =
            route_envelope_to_identity(wire.destination_service_id.as_deref(), &local_aci, local_pni.as_deref());
        let local_address = ProtocolAddress::new(local_service_id, device_id_from_u32(self.inner.identity.device_id)?);
        debug!(
            "process_envelope: routed identity_kind={:?} local_address={}",
            identity_kind, local_address
        );

        let pool = self.inner.store.pool().clone();
        let tx = pool.begin().await.map_err(StoreError::from)?;
        let tx_store = crate::storage::tx::TxStore::new(tx);
        let mut session = tx_store.session_store();
        let mut identity = tx_store.identity_store(identity_kind);
        let mut pre_key = tx_store.pre_key_store(identity_kind);
        let signed_pre_key = tx_store.signed_pre_key_store(identity_kind);
        let mut kyber = tx_store.kyber_pre_key_store(identity_kind);

        let plaintext = libsignal_protocol::message_decrypt(
            &ciphertext,
            &remote_address,
            &local_address,
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

/// Decide which local identity an inbound envelope is addressed to,
/// and what `local_service_id` to construct the libsignal-protocol
/// `local_address` from.
///
/// The wire envelope's `destination_service_id` (proto tag 13) is set
/// by Signal-Server on every delivery; this routes by string-comparing
/// it against the persisted ACI / PNI strings. Forward-compatible to
/// sealed sender (the same field is present on UNIDENTIFIED_SENDER
/// envelopes once we add handling for that type).
///
/// Behaviour:
/// - destination matches local PNI -> route to PNI scope; local
///   service id is the PNI string.
/// - destination matches local ACI -> route to ACI scope; local
///   service id is the ACI string.
/// - destination is absent -> route to ACI; quiet debug log (legacy
///   compatibility).
/// - destination is present but matches neither -> route to ACI with
///   a WARN. Should not happen in practice; the warn surfaces it.
pub(crate) fn route_envelope_to_identity(
    destination_service_id: Option<&str>,
    local_aci: &str,
    local_pni: Option<&str>,
) -> (crate::crypto::prekeys::IdentityKind, String) {
    use crate::crypto::prekeys::IdentityKind;
    debug!(
        "route_envelope_to_identity: dest={:?} local_aci={} local_pni={:?}",
        destination_service_id, local_aci, local_pni
    );
    match (destination_service_id, local_pni) {
        (Some(d), Some(pni)) if d == pni => (IdentityKind::Pni, d.to_string()),
        (Some(d), _) if d == local_aci => (IdentityKind::Aci, local_aci.to_string()),
        (Some(d), _) => {
            warn!(
                "route_envelope_to_identity: destination_service_id={} matches neither local ACI ({}) nor PNI ({:?}); routing to ACI",
                d, local_aci, local_pni
            );
            (IdentityKind::Aci, local_aci.to_string())
        }
        (None, _) => {
            debug!("route_envelope_to_identity: destination_service_id absent; routing to ACI");
            (IdentityKind::Aci, local_aci.to_string())
        }
    }
}

/// Translate decrypted Signal Content protobuf bytes into our public
/// [`Envelope`] enum. Decodes via prost-generated `signalservice::Content`
/// (replaces the earlier hand-rolled minimal decoders). v0.1 surfaces
/// DataMessage and SyncMessage::Sent; receipts/typing/edit are stubbed
/// and dropped here for Phase 1 (Phase 3 maps them onto the public enum).
fn decode_content(plaintext: &[u8], wire: &proto::Envelope) -> Option<Envelope> {
    use crate::envelope::{DataMessage as PubDataMessage, SyncMessage as PubSyncMessage};
    use prost::Message as _;

    debug!(
        "decode_content: plaintext_len={} envelope_type={:?}",
        plaintext.len(),
        wire.r#type()
    );

    let content = proto::Content::decode(plaintext)
        .map_err(|e| {
            warn!("decode_content: prost Content decode failed: {e}");
            e
        })
        .ok()?;

    match content.content? {
        proto::content::Content::DataMessage(dm) => {
            let timestamp = wire.client_timestamp.unwrap_or(0);
            let source = wire.source_service_id.clone().unwrap_or_default();
            let message = PubDataMessage {
                body: dm.body,
                timestamp,
            };
            Some(Envelope::DataMessage {
                source,
                timestamp,
                message,
            })
        }
        proto::content::Content::SyncMessage(sm) => {
            let proto::sync_message::Content::Sent(sent) = sm.content? else {
                return None;
            };
            let destination = sent.destination_service_id.unwrap_or_default();
            let timestamp = sent.timestamp.unwrap_or(0);
            let body = sent.message.and_then(|m| m.body);
            let message = PubDataMessage { body, timestamp };
            Some(Envelope::SyncMessage(PubSyncMessage::Sent {
                destination,
                timestamp,
                message,
            }))
        }
        other => {
            trace!("decode_content: dropping unhandled Content variant {other:?}");
            None
        }
    }
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
        debug!("maybe_replenish_prekeys:");
        use crate::crypto::prekeys::IdentityKind;

        // Per-identity replenishment. Each identity's "next id" comes
        // from a kind-filtered MAX(id) against the `prekeys` table;
        // the (identity_kind, id) primary key keeps ACI and PNI rows
        // in their own partitions. The server-authoritative count
        // (in maybe_replenish_one_identity) decides WHETHER to refill;
        // the local MAX(id) decides WHAT id to start the next batch at.
        let pool = self.inner.store.pool().clone();
        let aci_max: (Option<i64>,) = sqlx::query_as("SELECT MAX(id) FROM prekeys WHERE identity_kind = 'aci'")
            .fetch_one(&pool)
            .await
            .map_err(StoreError::from)?;
        let aci_next = aci_max.0.map(|v| v as u32).unwrap_or(0).saturating_add(1);
        let pni_max: (Option<i64>,) = sqlx::query_as("SELECT MAX(id) FROM prekeys WHERE identity_kind = 'pni'")
            .fetch_one(&pool)
            .await
            .map_err(StoreError::from)?;
        let pni_next = pni_max.0.map(|v| v as u32).unwrap_or(0).saturating_add(1);

        let mut rng = rand::rng();
        self.maybe_replenish_one_identity(IdentityKind::Aci, &mut rng, aci_next)
            .await?;
        if self.inner.store.get_pni_identity_keypair().await?.is_some() {
            self.maybe_replenish_one_identity(IdentityKind::Pni, &mut rng, pni_next)
                .await?;
        }

        info!(
            "maybe_replenish_prekeys: cycle complete aci_next={} pni_next={}",
            aci_next, pni_next
        );
        Ok(())
    }

    /// Query the server's prekey count for one identity and replenish
    /// if below the watermark. Refactored out so ACI and PNI can be
    /// replenished independently without bleeding errors across
    /// identities.
    async fn maybe_replenish_one_identity<R: rand::Rng + rand::CryptoRng>(
        &self,
        identity_kind: crate::crypto::prekeys::IdentityKind,
        rng: &mut R,
        next_id: u32,
    ) -> Result<(), ReceiveError> {
        debug!(
            "maybe_replenish_one_identity: identity_kind={:?} next_id={}",
            identity_kind, next_id
        );
        use crate::crypto::prekeys::{PREKEY_LOW_WATERMARK, generate_upload_persist};

        // Pre-fetch upload credentials (also needed for the count
        // request).  Cheap (one connection round-trip) and decoupled
        // from the actual replenishment work, so this method doesn't
        // hold pool connections across the network request.
        let creds = crate::api::load_upload_credentials(&self.inner.store, identity_kind)
            .await
            .map_err(|e| ReceiveError::Stopped(format!("load_upload_credentials({identity_kind:?}): {e}")))?;

        let counts = crate::api::get_available_prekey_count(&creds, identity_kind)
            .await
            .map_err(|e| ReceiveError::Stopped(format!("get_available_prekey_count({identity_kind:?}): {e}")))?;
        debug!(
            "maybe_replenish_one_identity: identity={:?} server_count(ec={}, pq={}) watermark={}",
            identity_kind, counts.ec, counts.pq, PREKEY_LOW_WATERMARK
        );
        if counts.ec >= PREKEY_LOW_WATERMARK {
            return Ok(());
        }

        generate_upload_persist(rng, &self.inner.store, identity_kind, next_id)
            .await
            .map_err(|e| ReceiveError::Stopped(format!("replenish({identity_kind:?}): {e}")))?;

        info!(
            "maybe_replenish_one_identity: refilled identity={:?} starting at id={}",
            identity_kind, next_id
        );
        Ok(())
    }
}

/// Build the inner Content protobuf for a 1:1 send: a DataMessage with
/// the body and timestamp, wrapped in the top-level Content.
fn build_one_to_one_content(body: &str, timestamp: u64) -> Vec<u8> {
    use prost::Message as _;

    debug!(
        "build_one_to_one_content: body_len={} timestamp={}",
        body.len(),
        timestamp
    );

    let dm = proto::DataMessage {
        body: Some(body.to_string()),
        timestamp: Some(timestamp),
        ..Default::default()
    };
    let content = proto::Content {
        content: Some(proto::content::Content::DataMessage(dm)),
        ..Default::default()
    };
    content.encode_to_vec()
}

/// Build the inner Content protobuf for a Note-to-Self send: wraps the
/// body as a DataMessage and tags it via SyncMessage::Sent so the
/// receiver-side filter (`destination == own_number`) fires.
fn build_sync_self_content(body: &str, own_destination: &str, timestamp: u64) -> Vec<u8> {
    use prost::Message as _;

    debug!(
        "build_sync_self_content: body_len={} own_destination={} timestamp={}",
        body.len(),
        own_destination,
        timestamp
    );

    let dm = proto::DataMessage {
        body: Some(body.to_string()),
        timestamp: Some(timestamp),
        ..Default::default()
    };
    let sent = proto::sync_message::Sent {
        destination_service_id: Some(own_destination.to_string()),
        timestamp: Some(timestamp),
        message: Some(dm),
        ..Default::default()
    };
    let sm = proto::SyncMessage {
        content: Some(proto::sync_message::Content::Sent(sent)),
        ..Default::default()
    };
    let content = proto::Content {
        content: Some(proto::content::Content::SyncMessage(sm)),
        ..Default::default()
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
