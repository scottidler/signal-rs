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
    Aci, CiphertextMessage, CiphertextMessageType, DeviceId, PreKeySignalMessage, ProtocolAddress, SignalMessage,
};
use log::{debug, info, trace, warn};
use prost::Message as _;
use thiserror::Error;
use tokio::sync::broadcast;

use crate::crypto::provisioning::proto;
use crate::envelope::Envelope;
use crate::net::{self, Environment as NetEnv, NetError};
use crate::storage::{Identity, LinkStatus, SqliteStore, Store, StoreError};

mod send;
#[cfg(test)]
pub(crate) use send::{
    attachment_pointer_to_proto, build_delete_content, build_one_to_one_content, build_sync_self_content,
    build_typing_content,
};

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

    #[error("api error: {0}")]
    Api(#[from] crate::api::ApiError),

    #[error("send failed: {0}")]
    Server(String),

    #[error("missing credential in store: {0}")]
    MissingCredential(&'static str),

    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error(
        "no profile key on file for peer ACI {0}; receive at least one \
         message from this peer first (or wait for SyncMessage::Contacts \
         backfill, which is post-v0.1)"
    )]
    NoProfileKey(String),

    #[error("PNI-addressed sends are unsupported in v0.1")]
    PniSendUnsupported,
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

    /// Fetch and decrypt a CDN-hosted attachment referenced by an
    /// [`AttachmentPointer`] (pulled off an inbound `Envelope::DataMessage`
    /// or `SyncMessage::Sent`). Verifies HMAC + SHA-256 digest before
    /// writing plaintext to `dest`. See [`crate::attachment::download_attachment`]
    /// for the cipher format details.
    pub async fn download_attachment(
        &self,
        pointer: &crate::envelope::AttachmentPointer,
        dest: &Path,
    ) -> Result<(), crate::attachment::AttachmentError> {
        crate::attachment::download_attachment(pointer, dest).await
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

        // Both unsealed and sealed sender paths route by the wire's
        // `destination_service_id` (tag 13) and need the local
        // ProtocolAddress + scoped stores. Compute up front; both
        // branches consume them.
        let local_aci = self
            .inner
            .store
            .get_aci()
            .await?
            .ok_or(ReceiveError::MissingCredential("aci"))?;
        let local_pni = self.inner.store.get_pni().await?;
        let (identity_kind, local_service_id) =
            route_envelope_to_identity(wire.destination_service_id.as_deref(), &local_aci, local_pni.as_deref());
        let local_device_id = device_id_from_u32(self.inner.identity.device_id)?;
        let local_address = ProtocolAddress::new(local_service_id.clone(), local_device_id);
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

        // Returns (source_service_id, ciphertext_for_decrypt, remote_address)
        // for both unsealed and sealed paths. The sealed path additionally
        // performs USMC unwrap + trust-root validation + self-send check
        // before reaching message_decrypt.
        let decrypt_inputs = match envelope_type {
            proto::envelope::Type::DoubleRatchet | proto::envelope::Type::PrekeyMessage => {
                let ciphertext = match envelope_type {
                    proto::envelope::Type::DoubleRatchet => {
                        CiphertextMessage::SignalMessage(SignalMessage::try_from(content)?)
                    }
                    proto::envelope::Type::PrekeyMessage => {
                        CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(content)?)
                    }
                    _ => unreachable!("outer arm restricts to these two variants"),
                };
                let source_service_id = wire
                    .source_service_id
                    .as_deref()
                    .ok_or(ReceiveError::MissingCredential("source_service_id"))?
                    .to_string();
                let source_device = wire.source_device_id.unwrap_or(1);
                let remote_address =
                    ProtocolAddress::new(source_service_id.clone(), device_id_from_u32(source_device)?);
                Some((source_service_id, ciphertext, remote_address))
            }
            proto::envelope::Type::UnidentifiedSender => {
                debug!("process_envelope: UNIDENTIFIED_SENDER envelope; unwrapping USMC");
                let usmc = libsignal_protocol::sealed_sender_decrypt_to_usmc(content, &identity).await?;

                let validation_time = libsignal_protocol::Timestamp::from_epoch_millis(now_millis());
                crate::crypto::sealed::validate_against_trust_roots(
                    usmc.sender()?,
                    crate::crypto::sealed::production_trust_roots(),
                    validation_time,
                )?;

                let sender_cert = usmc.sender()?;
                let sender_uuid = sender_cert.sender_uuid()?.to_string();
                let sender_device_id = sender_cert.sender_device_id()?;

                // Self-send guard: libsignal's high-level sealed_sender_decrypt
                // returns SealedSenderSelfSend in this case. Mirror that by
                // dropping the envelope rather than reprocessing our own message.
                if sender_uuid == local_service_id && sender_device_id == local_device_id {
                    debug!(
                        "process_envelope: sealed-sender self-send (sender_uuid={} device_id={}); dropping",
                        sender_uuid, sender_device_id
                    );
                    return Ok(None);
                }

                let inner_ciphertext = match usmc.msg_type()? {
                    CiphertextMessageType::Whisper => {
                        CiphertextMessage::SignalMessage(SignalMessage::try_from(usmc.contents()?)?)
                    }
                    CiphertextMessageType::PreKey => {
                        CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(usmc.contents()?)?)
                    }
                    other => {
                        warn!("process_envelope: sealed-sender inner msg_type {other:?} not supported in v1; dropping");
                        return Ok(None);
                    }
                };
                let remote_address = ProtocolAddress::new(sender_uuid.clone(), sender_device_id);
                Some((sender_uuid, inner_ciphertext, remote_address))
            }
            other => {
                debug!("process_envelope: ignoring envelope type {other:?} for v0.1");
                None
            }
        };

        let Some((source_service_id, ciphertext, remote_address)) = decrypt_inputs else {
            return Ok(None);
        };

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

        let timestamp = wire.client_timestamp.unwrap_or(0);
        let source_device: u32 = remote_address.device_id().into();
        let (mut decoded, peer_profile_key) = decode_content(&plaintext, &source_service_id, source_device, timestamp);

        // Persist any peer profile_key carried inline on the inbound
        // DataMessage. The outbound sealed-sender path consults this
        // table to derive the recipient's Unidentified-Access-Key.
        // SyncMessage::Sent.message.profile_key is OUR key (we sent it
        // from another device), so decode_content only returns the key
        // for top-level peer DataMessages.
        if let Some(pk) = peer_profile_key
            && source_service_id != local_aci
            && let Err(e) = self.inner.store.set_peer_profile_key(&source_service_id, &pk).await
        {
            warn!("process_envelope: failed to persist peer profile_key for {source_service_id}: {e}");
        }

        // Remap SyncMessage::Sent destination to Recipient::SelfSync when
        // it equals our own ACI. The doc surfaces this variant so consumers
        // can filter Note-to-Self without string-comparing their own ACI.
        if let Some(Envelope::SyncMessage(crate::envelope::SyncMessage::Sent {
            destination: dest @ Some(_),
            ..
        })) = decoded.as_mut()
            && let Some(crate::envelope::Recipient::Aci(aci_string)) = dest.as_ref()
            && aci_string == &local_aci
        {
            *dest = Some(crate::envelope::Recipient::SelfSync);
        }

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
/// [`Envelope`] enum. Decodes via prost-generated `signalservice::Content`.
///
/// `source`, `source_device`, and `timestamp` are supplied by the caller
/// because sealed-sender envelopes carry sender identity inside the
/// encrypted USMC (no plaintext `source_service_id`/`source_device_id`
/// on the wire). The unsealed path reads them from the wire envelope;
/// the sealed path reads them from the validated `SenderCertificate`.
///
/// Returns `(envelope, peer_profile_key)`. The second element is `Some`
/// when the Content carries a top-level `DataMessage.profile_key` from a
/// peer; the caller persists it into `peer_profile_keys` so subsequent
/// outbound sends to that peer can use the sealed-sender path. The
/// nested `SyncMessage::Sent.message.profile_key` is our own key, not
/// a peer's, so it intentionally is not surfaced here.
///
/// Phase 3 surfaces DataMessage, SyncMessage::Sent, SyncMessage::Read,
/// Receipt, Typing, Edit, Call. Unhandled Content variants fall through
/// to `Envelope::Unknown` so consumers see them rather than silently
/// dropping a future message type.
fn decode_content(
    plaintext: &[u8],
    source: &str,
    source_device: u32,
    timestamp: u64,
) -> (Option<Envelope>, Option<Vec<u8>>) {
    use crate::envelope::{Envelope as PubEnvelope, ReceiptKind};
    use prost::Message as _;

    debug!(
        "decode_content: plaintext_len={} source={} source_device={} timestamp={}",
        plaintext.len(),
        source,
        source_device,
        timestamp
    );

    let content = match proto::Content::decode(plaintext) {
        Ok(c) => c,
        Err(e) => {
            warn!("decode_content: prost Content decode failed: {e}");
            return (None, None);
        }
    };

    let Some(inner) = content.content else {
        return (None, None);
    };
    let source_recipient = service_id_to_recipient(source);

    let mut peer_profile_key: Option<Vec<u8>> = None;
    let envelope = match inner {
        proto::content::Content::DataMessage(dm) => {
            peer_profile_key = dm.profile_key.clone();
            let u = unpack_data_message(dm);
            Some(PubEnvelope::DataMessage {
                source: source_recipient,
                source_device,
                timestamp,
                group_id: u.group_id,
                body: u.body,
                attachments: u.attachments,
                quote: u.quote,
                edit_of_timestamp: None,
                expire_in_seconds: u.expire_in_seconds,
            })
        }
        proto::content::Content::SyncMessage(sm) => decode_sync_message(sm, timestamp),
        proto::content::Content::ReceiptMessage(rm) => {
            let receipt_kind = match rm.r#type() {
                proto::receipt_message::Type::Delivery => ReceiptKind::Delivery,
                proto::receipt_message::Type::Read => ReceiptKind::Read,
                proto::receipt_message::Type::Viewed => ReceiptKind::Viewed,
            };
            Some(PubEnvelope::Receipt {
                receipt_kind,
                source: source_recipient,
                timestamps: rm.timestamp,
            })
        }
        proto::content::Content::TypingMessage(tm) => {
            let started = matches!(tm.action(), proto::typing_message::Action::Started);
            Some(PubEnvelope::Typing {
                source: source_recipient,
                group_id: tm.group_id,
                started,
                timestamp: tm.timestamp.unwrap_or(timestamp),
            })
        }
        proto::content::Content::EditMessage(em) => {
            let target_sent_timestamp = em.target_sent_timestamp.unwrap_or(0);
            let body = em.data_message.and_then(|dm| dm.body);
            Some(PubEnvelope::Edit {
                source: source_recipient,
                timestamp,
                target_sent_timestamp,
                body,
            })
        }
        proto::content::Content::CallMessage(cm) => Some(PubEnvelope::Call {
            source: source_recipient,
            raw: cm.encode_to_vec(),
        }),
        other => {
            let type_tag = match &other {
                proto::content::Content::NullMessage(_) => "null_message",
                proto::content::Content::DecryptionErrorMessage(_) => "decryption_error_message",
                proto::content::Content::StoryMessage(_) => "story_message",
                _ => "unknown",
            };
            let raw = match other {
                proto::content::Content::NullMessage(v) => v.encode_to_vec(),
                proto::content::Content::DecryptionErrorMessage(v) => v,
                proto::content::Content::StoryMessage(v) => v.encode_to_vec(),
                _ => Vec::new(),
            };
            Some(PubEnvelope::Unknown {
                type_tag: type_tag.to_string(),
                raw,
            })
        }
    };
    (envelope, peer_profile_key)
}

/// Classify a wire `source_service_id` / `destination_service_id` string
/// into a typed [`crate::envelope::Recipient`]. Signal uses a `PNI:`
/// prefix on PNI service-ids; bare UUIDs are ACIs.
fn service_id_to_recipient(s: &str) -> crate::envelope::Recipient {
    use crate::envelope::Recipient;
    if let Some(pni) = s.strip_prefix("PNI:") {
        Recipient::Pni(pni.to_string())
    } else {
        Recipient::Aci(s.to_string())
    }
}

/// The Phase 3 surface fields pulled out of a prost-generated DataMessage.
/// `edit_of_timestamp` is sourced separately by the EditMessage decode arm.
struct UnpackedDataMessage {
    group_id: Option<Vec<u8>>,
    body: Option<String>,
    attachments: Vec<crate::envelope::AttachmentPointer>,
    quote: Option<crate::envelope::Quote>,
    expire_in_seconds: Option<u32>,
}

fn unpack_data_message(dm: proto::DataMessage) -> UnpackedDataMessage {
    UnpackedDataMessage {
        group_id: dm.group_v2.and_then(|g| g.master_key),
        body: dm.body,
        attachments: dm.attachments.into_iter().map(map_attachment).collect(),
        quote: dm.quote.map(map_quote),
        expire_in_seconds: dm.expire_timer,
    }
}

fn map_attachment(p: proto::AttachmentPointer) -> crate::envelope::AttachmentPointer {
    use crate::envelope::AttachmentPointer as Pub;
    let flags = p.flags.unwrap_or(0);
    let voice_note = flags & (proto::attachment_pointer::Flags::VoiceMessage as u32) != 0;
    let borderless = flags & (proto::attachment_pointer::Flags::Borderless as u32) != 0;
    let gif = flags & (proto::attachment_pointer::Flags::Gif as u32) != 0;
    let (cdn_id, cdn_key) = match p.attachment_identifier {
        Some(proto::attachment_pointer::AttachmentIdentifier::CdnId(id)) => (id, None),
        Some(proto::attachment_pointer::AttachmentIdentifier::CdnKey(k)) => (0, Some(k)),
        None => (0, None),
    };
    Pub {
        cdn_id,
        cdn_key,
        cdn_number: p.cdn_number.unwrap_or(0),
        content_type: p.content_type,
        size: p.size,
        digest: p.digest.unwrap_or_default(),
        key: p.key.unwrap_or_default(),
        file_name: p.file_name,
        caption: p.caption,
        width: p.width,
        height: p.height,
        voice_note,
        borderless,
        gif,
        upload_timestamp: p.upload_timestamp,
        blurhash: p.blur_hash,
    }
}

fn map_quote(q: proto::data_message::Quote) -> crate::envelope::Quote {
    crate::envelope::Quote {
        id: q.id.unwrap_or(0),
        author: q
            .author_aci
            .as_deref()
            .map(service_id_to_recipient)
            .unwrap_or(crate::envelope::Recipient::Aci(String::new())),
        text: q.text,
    }
}

fn decode_sync_message(sm: proto::SyncMessage, fallback_timestamp: u64) -> Option<Envelope> {
    use crate::envelope::{Envelope as PubEnvelope, ReadReceipt, Recipient, SyncMessage as PubSyncMessage};

    // SyncMessage.read is a `repeated` field outside the oneof; check it
    // first so a SyncMessage carrying only read-receipts still surfaces.
    if !sm.read.is_empty() {
        let reads = sm
            .read
            .into_iter()
            .map(|r| ReadReceipt {
                sender: r
                    .sender_aci
                    .as_deref()
                    .map(service_id_to_recipient)
                    .unwrap_or(Recipient::Aci(String::new())),
                timestamp: r.timestamp.unwrap_or(0),
            })
            .collect();
        return Some(PubEnvelope::SyncMessage(PubSyncMessage::Read { reads }));
    }

    let inner = sm.content?;
    match inner {
        proto::sync_message::Content::Sent(sent) => {
            let destination = sent.destination_service_id.as_deref().map(service_id_to_recipient);
            let sync_timestamp = sent.timestamp.unwrap_or(fallback_timestamp);
            // SyncMessage::Sent surfaces destination/body/attachments
            // but not the inner quote (the originating DataMessage's
            // quote was already mirrored when it arrived as the peer's
            // DataMessage; we don't want to duplicate it here).
            let u = sent.message.map(unpack_data_message).unwrap_or(UnpackedDataMessage {
                group_id: None,
                body: None,
                attachments: Vec::new(),
                quote: None,
                expire_in_seconds: None,
            });
            Some(PubEnvelope::SyncMessage(PubSyncMessage::Sent {
                destination,
                group_id: u.group_id,
                timestamp: sync_timestamp,
                body: u.body,
                attachments: u.attachments,
                edit_of_timestamp: None,
                expire_in_seconds: u.expire_in_seconds,
            }))
        }
        _ => {
            trace!("decode_sync_message: dropping non-Sent/non-Read sync sub-variant");
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
