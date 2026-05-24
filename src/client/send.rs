//! Outbound message paths: the public `Client::send` orchestrator, the
//! sealed-sender peer flow, the unsealed fallback path, and Note-to-Self
//! sync-message dispatch.
//!
//! Decomposed out of `client.rs` so each file stays under the 1500-line
//! limit (see `~/repos/.claude/refs/dealing-with-large-files.md`). The
//! receive pipeline, storage routing helpers, and prekey replenishment
//! stay in `client.rs`.
//!
//! Visibility note: `impl Client { ... }` adds methods to the public
//! [`crate::client::Client`] type. Submodules of `client` may access
//! `Client`'s private fields (e.g. `inner.store`) per Rust's
//! parent-scope visibility rules, so we don't need to widen
//! `ClientInner`'s field visibility.

use std::borrow::Cow;
use std::path::PathBuf;

use libsignal_net_chat::api::Auth;
use libsignal_protocol::{Aci, CiphertextMessage, DeviceId, ProtocolAddress, SessionStore};
use log::{debug, info, warn};

use crate::crypto::provisioning::proto;
use crate::envelope::{AttachmentPointer, Recipient};
use crate::net::{self, Environment as NetEnv};
use crate::storage::StoreError;

use super::{Client, SendError, device_id_from_u32, now_millis};

/// Internal dispatch outcome for the sealed-sender send. Kept private
/// to this module so libsignal-net-chat's `MismatchedDeviceError` does
/// not leak into the public [`SendError`] surface, while still letting
/// the retry path consume the typed `missing/extra/stale` device lists
/// for surgical session deletion. Returning this from
/// `encrypt_and_dispatch_sealed` and matching on it in
/// `send_sealed_to_aci` replaces the earlier string-encoded handshake
/// (`SendError::Server("MISMATCHED: ...")`), which was fragile to any
/// other error message that happened to start with the same prefix.
enum SendAttempt {
    Ok,
    Mismatched(libsignal_net_chat::api::messages::MismatchedDeviceError),
}

impl Client {
    /// Send a 1:1 text message. Returns the millisecond timestamp the
    /// outbound message was tagged with so callers can correlate with
    /// later delivery / read receipts.
    ///
    /// Routing by [`Recipient`]:
    /// - `Recipient::SelfSync` -> Note-to-Self via `send_sync_message`.
    /// - `Recipient::Aci(uuid)` -> 1:1 to peer. Sealed sender if we
    ///   have a stored profile key for the peer; otherwise warn and
    ///   fall back to unsealed using the existing session (or error
    ///   if no session exists yet).
    /// - `Recipient::Pni(_)` -> `SendError::PniSendUnsupported`.
    pub async fn send(&self, to: Recipient, body: &str) -> Result<u64, SendError> {
        debug!("Client::send: to={:?} body_len={}", to, body.len());
        self.send_with_attachments(to, body, &[]).await
    }

    /// Send a 1:1 message with zero or more attachments. Uploads the
    /// attachment bytes to Signal's CDN (bucket-padded + AES-CBC/HMAC
    /// encrypted) and embeds the resulting [`AttachmentPointer`]s in
    /// the outbound DataMessage. Returns the message timestamp.
    ///
    /// `attachment_paths` are local filesystem paths; each is read into
    /// memory, encrypted, and uploaded over the authenticated chat
    /// upload-form endpoint before the message itself dispatches.
    pub async fn send_with_attachments(
        &self,
        to: Recipient,
        body: &str,
        attachment_paths: &[PathBuf],
    ) -> Result<u64, SendError> {
        debug!(
            "Client::send_with_attachments: to={:?} body_len={} attachments={}",
            to,
            body.len(),
            attachment_paths.len()
        );

        let attachments = self.upload_attachments_for_send(attachment_paths).await?;

        match to {
            Recipient::SelfSync => self.send_note_to_self(body, &attachments).await,
            Recipient::Aci(uuid) => {
                let aci = Aci::parse_from_service_id_string(&uuid)
                    .ok_or_else(|| SendError::InvalidRecipient(format!("aci uuid: {uuid}")))?;
                let timestamp_ms = now_millis();
                let content_bytes = build_one_to_one_content(body, timestamp_ms, &attachments);
                self.dispatch_to_peer_aci(aci, &content_bytes, timestamp_ms).await?;
                Ok(timestamp_ms)
            }
            Recipient::Pni(_) => Err(SendError::PniSendUnsupported),
        }
    }

    /// Send a typing indicator (`started=true` for typing-started,
    /// `started=false` for typing-stopped) to a peer ACI. The
    /// `TypingMessage` proto rides the same sealed-sender peer dispatch
    /// path used by [`Client::send`] - it shares the encryption flow
    /// with regular DataMessages and only differs in the Content oneof
    /// variant carried inside.
    ///
    /// Only [`Recipient::Aci`] is supported; SelfSync and Pni return
    /// errors (typing-to-self is meaningless and PNI sends are out of
    /// scope per the design doc).
    pub async fn typing(&self, to: Recipient, started: bool) -> Result<(), SendError> {
        debug!("Client::typing: to={:?} started={}", to, started);
        let aci = match to {
            Recipient::Aci(uuid) => Aci::parse_from_service_id_string(&uuid)
                .ok_or_else(|| SendError::InvalidRecipient(format!("aci uuid: {uuid}")))?,
            Recipient::SelfSync => return Err(SendError::InvalidRecipient("typing to self".into())),
            Recipient::Pni(_) => return Err(SendError::PniSendUnsupported),
        };
        let timestamp_ms = now_millis();
        let content_bytes = build_typing_content(started, timestamp_ms);
        self.dispatch_to_peer_aci(aci, &content_bytes, timestamp_ms).await?;
        Ok(())
    }

    /// Send a remote-delete request for a previously-sent message
    /// (`target_timestamp` is the millisecond send-timestamp of the
    /// message being deleted, returned by an earlier [`Client::send`]
    /// or pulled off an inbound envelope). Builds a `DataMessage` with
    /// the `delete: Delete { target_sent_timestamp }` field populated
    /// and no body / no attachments, then dispatches via the same
    /// peer path used by [`Client::send`].
    ///
    /// Only [`Recipient::Aci`] is supported; SelfSync and Pni return
    /// errors.
    pub async fn delete_for_everyone(&self, to: Recipient, target_timestamp: u64) -> Result<(), SendError> {
        debug!(
            "Client::delete_for_everyone: to={:?} target_timestamp={}",
            to, target_timestamp
        );
        let aci = match to {
            Recipient::Aci(uuid) => Aci::parse_from_service_id_string(&uuid)
                .ok_or_else(|| SendError::InvalidRecipient(format!("aci uuid: {uuid}")))?,
            Recipient::SelfSync => return Err(SendError::InvalidRecipient("delete to self".into())),
            Recipient::Pni(_) => return Err(SendError::PniSendUnsupported),
        };
        let timestamp_ms = now_millis();

        // 1. Fan the delete out to the peer's devices. If this fails the
        //    delete never lands on the contact's phone and surfacing the
        //    error to the caller is correct.
        let peer_content = build_delete_content(target_timestamp, timestamp_ms);
        self.dispatch_to_peer_aci(aci, &peer_content, timestamp_ms).await?;

        // 2. Sync the tombstone to our own OTHER linked devices so they
        //    also remove the message from the thread. Best-effort:
        //    the peer-side delete has already landed at this point, so
        //    returning Err here would mislead the caller. signal-cli
        //    follows the same pattern (peer dispatch first, then a
        //    SyncMessage::Sent carrying the delete; the sync failure is
        //    a UX regression on own devices, not a delete failure).
        let peer_destination = aci.service_id_string();
        let sync_content = build_sync_delete_content(&peer_destination, target_timestamp, timestamp_ms);
        if let Err(e) = self.dispatch_sync_to_own_devices(&sync_content, timestamp_ms).await {
            warn!(
                "delete_for_everyone: peer delete to {} landed but sync to own devices failed: {}; \
                 the message will remain visible on this user's other linked devices until they are \
                 re-synced",
                peer_destination, e
            );
        }
        Ok(())
    }

    /// Upload each path through the authenticated chat upload-form
    /// endpoint and convert the resulting public-API [`AttachmentPointer`]
    /// into the wire proto used by [`build_one_to_one_content`] /
    /// [`build_sync_self_content`]. Returns an empty Vec when paths is
    /// empty so the no-attachment send path stays a no-op.
    async fn upload_attachments_for_send(&self, paths: &[PathBuf]) -> Result<Vec<proto::AttachmentPointer>, SendError> {
        debug!("upload_attachments_for_send: count={}", paths.len());
        if paths.is_empty() {
            return Ok(Vec::new());
        }

        let (auth_chat, events) = self
            .open_authenticated_chat()
            .await
            .map_err(|e| SendError::Server(format!("open auth chat for upload: {e}")))?;
        drop(events);
        let auth = Auth(auth_chat);

        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            let content_type = mime_guess_for_path(path);
            let pointer = crate::attachment::upload::upload_attachment_from_path(&auth, path, content_type)
                .await
                .map_err(|e| SendError::Server(format!("upload {}: {e}", path.display())))?;
            info!(
                "upload_attachments_for_send: uploaded path={} cdn={} cdn_key_len={}",
                path.display(),
                pointer.cdn_number,
                pointer.cdn_key.as_deref().map(|s| s.len()).unwrap_or(0)
            );
            out.push(attachment_pointer_to_proto(pointer));
        }
        auth.0.disconnect().await;
        Ok(out)
    }

    /// Internal dispatch for a peer ACI target. Looks up the stored
    /// profile key and routes to sealed-sender if present, or an
    /// unsealed fallback (with a `warn!` so the operator sees the
    /// privacy downgrade) if not.
    ///
    /// `content_bytes` is the encoded Signal `Content` protobuf the
    /// caller wants to deliver (a one-to-one DataMessage, a
    /// TypingMessage, a remote-delete DataMessage, etc.); the dispatch
    /// path is payload-agnostic. `timestamp_ms` must be the same
    /// timestamp embedded in `content_bytes` so the wire-level
    /// send-timestamp and the in-Content timestamp agree.
    async fn dispatch_to_peer_aci(
        &self,
        target: Aci,
        content_bytes: &[u8],
        timestamp_ms: u64,
    ) -> Result<(), SendError> {
        let target_string = target.service_id_string();
        let peer_pk = self.inner.store.get_peer_profile_key(&target_string).await?;

        if let Some(pk_bytes) = peer_pk {
            let pk_arr: [u8; zkgroup::PROFILE_KEY_LEN] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| SendError::Server(format!("peer profile_key bad length: {}", pk_bytes.len())))?;
            let access_key = zkgroup::profiles::ProfileKey::create(pk_arr).derive_access_key();
            return self
                .send_sealed_to_aci(target, content_bytes, timestamp_ms, access_key)
                .await;
        }

        // No profile key on file. The unauthenticated prekey-bundle
        // fetch needs an access key, so cold-start unsealed sends are
        // impossible. Only the hot path (existing session for at least
        // one of the peer's devices) is viable as a fallback.
        let known = self
            .inner
            .store
            .session_device_ids_for_service_id(&target_string)
            .await?;
        if known.is_empty() {
            return Err(SendError::NoProfileKey(target_string));
        }
        warn!(
            "dispatch_to_peer_aci: no profile key for {} - falling back to unsealed send over \
             existing sessions ({} device(s)); this leaks sender identity to the server",
            target_string,
            known.len()
        );
        self.send_unsealed_hotpath(target, content_bytes, timestamp_ms, &known)
            .await
    }

    /// Encrypt + dispatch via the sealed-sender path. Returns the
    /// outbound message timestamp.
    ///
    /// Flow:
    /// 1. Load (or refresh) our SenderCertificate.
    /// 2. Cold path: open unauth chat, `get_pre_keys(AllDevices)` with
    ///    AccessKey auth, `process_prekey_bundle` for each device.
    ///    Hot path: use existing sessions.
    /// 3. Inside one `sqlx::Transaction`, call `sealed_sender_encrypt`
    ///    for every device; collect (device_id, registration_id, bytes).
    /// 4. Open unauth chat and dispatch `Unauth::send_message` with
    ///    `UserBasedSendAuthorization::User(AccessKey)`.
    /// 5. On `SealedSendFailure::MismatchedDevices`, clear the affected
    ///    sessions, refetch `get_pre_keys(AllDevices)`, re-encrypt, and
    ///    retry once.
    async fn send_sealed_to_aci(
        &self,
        target: Aci,
        content_bytes: &[u8],
        timestamp_ms: u64,
        access_key: [u8; zkgroup::ACCESS_KEY_LEN],
    ) -> Result<(), SendError> {
        let target_string = target.service_id_string();
        debug!(
            "send_sealed_to_aci: target={} content_len={} timestamp_ms={}",
            target_string,
            content_bytes.len(),
            timestamp_ms
        );

        // 1. Sender certificate.
        let cert = crate::api::load_or_refresh_sender_certificate(&self.inner.store, timestamp_ms).await?;
        debug!("send_sealed_to_aci: sender certificate ready");

        // 2. Materialise the set of (device_id, registration_id) pairs
        //    we'll encrypt for. Existing sessions hot path; otherwise
        //    fetch all bundles via the unauth chat and process them.
        let known = self
            .inner
            .store
            .session_device_ids_for_service_id(&target_string)
            .await?;
        let targets = if known.is_empty() {
            debug!("send_sealed_to_aci: cold path - fetching bundles for all devices");
            self.fetch_and_process_peer_bundles(&target, &target_string, access_key)
                .await?
        } else {
            debug!(
                "send_sealed_to_aci: hot path - using {} existing session(s)",
                known.len()
            );
            self.collect_registration_ids_for_known_devices(&target_string, &known)
                .await?
        };

        if targets.is_empty() {
            return Err(SendError::Server(format!(
                "no devices resolved for target {target_string}"
            )));
        }

        // 3. Encrypt for each device + dispatch. On MismatchedDevices,
        //    surgically refresh the affected sessions and retry once.
        match self
            .encrypt_and_dispatch_sealed(
                &target,
                &target_string,
                content_bytes,
                timestamp_ms,
                &cert,
                access_key,
                targets,
            )
            .await?
        {
            SendAttempt::Ok => {
                info!(
                    "send_sealed_to_aci: dispatched to {} timestamp_ms={}",
                    target_string, timestamp_ms
                );
                Ok(())
            }
            SendAttempt::Mismatched(err) => {
                warn!(
                    "send_sealed_to_aci: mismatched devices for {} missing={:?} extra={:?} stale={:?} \
                     - retrying once after refreshing the affected sessions",
                    target_string, err.missing_devices, err.extra_devices, err.stale_devices
                );
                let targets = self
                    .refresh_targets_after_mismatch(&target, &target_string, access_key, &err)
                    .await?;
                match self
                    .encrypt_and_dispatch_sealed(
                        &target,
                        &target_string,
                        content_bytes,
                        timestamp_ms,
                        &cert,
                        access_key,
                        targets,
                    )
                    .await?
                {
                    SendAttempt::Ok => {
                        info!(
                            "send_sealed_to_aci: dispatched (after retry) to {} timestamp_ms={}",
                            target_string, timestamp_ms
                        );
                        Ok(())
                    }
                    SendAttempt::Mismatched(err2) => Err(SendError::Server(format!(
                        "mismatched devices on retry for {target_string}: \
                         missing={:?} extra={:?} stale={:?}",
                        err2.missing_devices, err2.extra_devices, err2.stale_devices
                    ))),
                }
            }
        }
    }

    /// Fetch all device bundles for `target` via unauthenticated chat
    /// `get_pre_keys(AllDevices)` and process each into a fresh session
    /// inside one transaction. Returns the (device_id, registration_id)
    /// pairs caller will encrypt for.
    async fn fetch_and_process_peer_bundles(
        &self,
        target: &Aci,
        target_string: &str,
        access_key: [u8; zkgroup::ACCESS_KEY_LEN],
    ) -> Result<Vec<(DeviceId, u32)>, SendError> {
        use libsignal_net_chat::api::keys::{DeviceSpecifier, UnauthenticatedChatApi};
        use libsignal_net_chat::api::{Unauth, UserBasedAuthorization};
        use libsignal_protocol::ServiceId;

        debug!("fetch_and_process_peer_bundles: target={}", target_string);

        let aci_string = self
            .inner
            .store
            .get_aci()
            .await?
            .ok_or(SendError::MissingCredential("aci"))?;
        let local_device_id = device_id_from_u32(self.inner.identity.device_id)
            .map_err(|e| SendError::Server(format!("device_id: {e}")))?;
        let local_address = ProtocolAddress::new(aci_string, local_device_id);

        let (unauth_chat, unauth_events) = net::connect_chat_unauthenticated(NetEnv::Production)
            .await
            .map_err(|e| SendError::Server(format!("open unauth chat for prekeys: {e}")))?;
        drop(unauth_events);
        let unauth = Unauth(unauth_chat);
        let (_, bundles) = unauth
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(access_key),
                ServiceId::from(*target),
                DeviceSpecifier::AllDevices,
            )
            .await
            .map_err(|e| SendError::Server(format!("get_pre_keys: {e:?}")))?;
        unauth.0.disconnect().await;
        if bundles.is_empty() {
            return Err(SendError::Server("get_pre_keys returned no device bundles".to_string()));
        }

        // Read the set of device ids we already have a session for
        // BEFORE opening the transaction, so we can decide per-bundle
        // whether to call `process_prekey_bundle` (which initializes
        // a fresh session and would clobber any existing one) or to
        // preserve the existing session's ratchet state.
        //
        // Why this matters: the retry path after a `MismatchedDevices`
        // response deletes only the affected (`extra ∪ stale`) sessions.
        // Other devices' sessions are still live and may have advanced
        // their ratchet via a concurrent inbound message; we MUST NOT
        // overwrite them, or that inbound message becomes undecryptable.
        let known_set: std::collections::HashSet<u32> = self
            .inner
            .store
            .session_device_ids_for_service_id(target_string)
            .await?
            .into_iter()
            .collect();

        let pool = self.inner.store.pool().clone();
        let tx = pool.begin().await.map_err(StoreError::from)?;
        let tx_store = crate::storage::tx::TxStore::new(tx);
        let mut session = tx_store.session_store();
        let mut identity = tx_store.identity_store(crate::crypto::prekeys::IdentityKind::Aci);

        let mut targets = Vec::with_capacity(bundles.len());
        for bundle in bundles.iter() {
            let device_id = bundle.device_id().map_err(SendError::Signal)?;
            let device_id_u32 = u32::from(device_id);
            let remote_address = ProtocolAddress::new(target_string.to_string(), device_id);

            if known_set.contains(&device_id_u32) {
                // Existing session: preserve it. Pull the
                // registration_id from the local record so the caller's
                // outbound metadata matches the live session, not the
                // server's bundle (which the peer just rotated past on
                // a stale-device retry but the session still mirrors).
                let record = SessionStore::load_session(&session, &remote_address)
                    .await?
                    .ok_or_else(|| {
                        SendError::Server(format!("session row for device {device_id} disappeared during refresh"))
                    })?;
                let registration_id = record.remote_registration_id().map_err(SendError::Signal)?;
                targets.push((device_id, registration_id));
            } else {
                // No session: cold path or just-deleted (missing or
                // stale) device. Initialize from the bundle.
                let registration_id = bundle.registration_id().map_err(SendError::Signal)?;
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
                targets.push((device_id, registration_id));
            }
        }
        drop(session);
        drop(identity);
        tx_store.commit().await.map_err(StoreError::from)?;
        Ok(targets)
    }

    /// Pull (device_id, registration_id) from each existing session
    /// for `target_string` so the hot-path can skip the bundle fetch.
    async fn collect_registration_ids_for_known_devices(
        &self,
        target_string: &str,
        known: &[u32],
    ) -> Result<Vec<(DeviceId, u32)>, SendError> {
        debug!(
            "collect_registration_ids_for_known_devices: target={} known={:?}",
            target_string, known
        );
        let pool = self.inner.store.pool().clone();
        let tx = pool.begin().await.map_err(StoreError::from)?;
        let tx_store = crate::storage::tx::TxStore::new(tx);
        let session = tx_store.session_store();

        let mut out = Vec::with_capacity(known.len());
        for &device_id_u32 in known {
            let device_id =
                device_id_from_u32(device_id_u32).map_err(|e| SendError::Server(format!("device_id: {e}")))?;
            let remote_address = ProtocolAddress::new(target_string.to_string(), device_id);
            let record = SessionStore::load_session(&session, &remote_address)
                .await?
                .ok_or_else(|| SendError::Server(format!("session row for device {device_id} disappeared")))?;
            let registration_id = record.remote_registration_id().map_err(SendError::Signal)?;
            out.push((device_id, registration_id));
        }
        drop(session);
        // No mutations in this tx; commit is cheap.
        tx_store.commit().await.map_err(StoreError::from)?;
        Ok(out)
    }

    /// Encrypt the message for every (device_id, registration_id) in
    /// `targets` (inside one transaction) and dispatch via
    /// `Unauth::send_message`. Returns `Ok(SendAttempt::Mismatched(err))`
    /// when the server reports `MismatchedDevices` so the caller can
    /// drive the surgical retry; other request errors are returned as
    /// `Err(SendError)`.
    async fn encrypt_and_dispatch_sealed(
        &self,
        target: &Aci,
        target_string: &str,
        content_bytes: &[u8],
        timestamp_ms: u64,
        cert: &libsignal_protocol::SenderCertificate,
        access_key: [u8; zkgroup::ACCESS_KEY_LEN],
        targets: Vec<(DeviceId, u32)>,
    ) -> Result<SendAttempt, SendError> {
        use libsignal_net_chat::api::RequestError;
        use libsignal_net_chat::api::messages::{
            SealedSendFailure, SingleOutboundMessage, UnauthenticatedChatApi, UserBasedSendAuthorization,
        };
        use libsignal_net_chat::api::{Unauth, UserBasedAuthorization};
        use libsignal_protocol::ServiceId;

        debug!(
            "encrypt_and_dispatch_sealed: target={} devices={} content_len={} timestamp_ms={}",
            target_string,
            targets.len(),
            content_bytes.len(),
            timestamp_ms
        );

        // Encrypt inside one transaction so the ratchet advances for
        // every device atomically.
        let pool = self.inner.store.pool().clone();
        let tx = pool.begin().await.map_err(StoreError::from)?;
        let tx_store = crate::storage::tx::TxStore::new(tx);
        let mut session = tx_store.session_store();
        let mut identity = tx_store.identity_store(crate::crypto::prekeys::IdentityKind::Aci);

        let mut encrypted: Vec<(DeviceId, u32, Vec<u8>)> = Vec::with_capacity(targets.len());
        for (device_id, registration_id) in &targets {
            let remote_address = ProtocolAddress::new(target_string.to_string(), *device_id);
            let bytes = libsignal_protocol::sealed_sender_encrypt(
                &remote_address,
                cert,
                content_bytes,
                &mut session,
                &mut identity,
                std::time::SystemTime::now(),
                &mut rand::rng(),
            )
            .await?;
            encrypted.push((*device_id, *registration_id, bytes));
        }
        drop(session);
        drop(identity);
        tx_store.commit().await.map_err(StoreError::from)?;

        let outbound: Vec<libsignal_net_chat::api::messages::SingleOutboundSealedSenderMessage<'_>> = encrypted
            .iter()
            .map(|(d, r, b)| SingleOutboundMessage {
                device_id: *d,
                registration_id: *r,
                contents: Cow::Borrowed(b.as_slice()),
            })
            .collect();

        let (unauth_chat, unauth_events) = net::connect_chat_unauthenticated(NetEnv::Production)
            .await
            .map_err(|e| SendError::Server(format!("open unauth chat for send: {e}")))?;
        drop(unauth_events);
        let unauth = Unauth(unauth_chat);
        let auth = UserBasedSendAuthorization::User(UserBasedAuthorization::AccessKey(access_key));
        let result = unauth
            .send_message(
                ServiceId::from(*target),
                libsignal_protocol::Timestamp::from_epoch_millis(timestamp_ms),
                outbound,
                auth,
                false, // online_only
                true,  // urgent
            )
            .await;
        unauth.0.disconnect().await;

        match result {
            Ok(()) => Ok(SendAttempt::Ok),
            Err(RequestError::Other(SealedSendFailure::MismatchedDevices(e))) => Ok(SendAttempt::Mismatched(e)),
            Err(e) => Err(SendError::Server(format!("send_message: {e:?}"))),
        }
    }

    /// Recover from a `MismatchedDevices` response by surgically
    /// rebuilding sessions for only the affected device IDs. Valid
    /// sessions for devices not in the mismatch lists are left alone
    /// so a concurrent inbound message that advanced their ratchet is
    /// not lost.
    ///
    /// What we delete and why:
    /// - `extra_devices`: server says these don't exist; the local
    ///   session is bogus (peer removed the device since we last saw
    ///   them), drop it.
    /// - `stale_devices`: the device's registration id changed (peer
    ///   reinstalled, or the same slot got reused). Old session is
    ///   unusable; drop and re-process the fresh bundle.
    /// - `missing_devices`: peer added a device we haven't seen.
    ///   Nothing to delete (no session exists yet); we just need a
    ///   bundle.
    ///
    /// After surgically deleting `extra ∪ stale`, we refetch all
    /// bundles via `get_pre_keys(AllDevices)`. `fetch_and_process_peer_bundles`
    /// preserves any session that still exists locally (i.e. the
    /// valid devices not in any mismatch list) and processes a fresh
    /// bundle only for devices that no longer have a session
    /// (the just-deleted stale ones plus the missing ones).
    async fn refresh_targets_after_mismatch(
        &self,
        target: &Aci,
        target_string: &str,
        access_key: [u8; zkgroup::ACCESS_KEY_LEN],
        mismatch: &libsignal_net_chat::api::messages::MismatchedDeviceError,
    ) -> Result<Vec<(DeviceId, u32)>, SendError> {
        debug!(
            "refresh_targets_after_mismatch: target={} extra={:?} stale={:?} missing={:?}",
            target_string, mismatch.extra_devices, mismatch.stale_devices, mismatch.missing_devices
        );
        let pool = self.inner.store.pool().clone();
        for dev in mismatch.extra_devices.iter().chain(mismatch.stale_devices.iter()) {
            let address = format!("{target_string}.{}", u32::from(*dev));
            sqlx::query("DELETE FROM sessions WHERE address = ?")
                .bind(&address)
                .execute(&pool)
                .await
                .map_err(StoreError::from)?;
        }
        self.fetch_and_process_peer_bundles(target, target_string, access_key)
            .await
    }

    /// Unsealed fallback for the no-profile-key case: encrypt against
    /// existing sessions only (no bundle fetch, since the bundle fetch
    /// itself would require an access key we don't have) and dispatch
    /// via the authenticated chat. Returns the message timestamp.
    async fn send_unsealed_hotpath(
        &self,
        target: Aci,
        content_bytes: &[u8],
        timestamp_ms: u64,
        known: &[u32],
    ) -> Result<(), SendError> {
        use libsignal_net_chat::api::Auth;
        use libsignal_net_chat::api::messages::{AuthenticatedChatApi, SingleOutboundUnsealedMessage};
        use libsignal_protocol::ServiceId;

        let target_string = target.service_id_string();
        debug!(
            "send_unsealed_hotpath: target={} devices={} content_len={} timestamp_ms={}",
            target_string,
            known.len(),
            content_bytes.len(),
            timestamp_ms
        );

        let aci_string = self
            .inner
            .store
            .get_aci()
            .await?
            .ok_or(SendError::MissingCredential("aci"))?;
        let local_device_id = device_id_from_u32(self.inner.identity.device_id)
            .map_err(|e| SendError::Server(format!("device_id: {e}")))?;
        let local_address = ProtocolAddress::new(aci_string, local_device_id);

        let pool = self.inner.store.pool().clone();
        let tx = pool.begin().await.map_err(StoreError::from)?;
        let tx_store = crate::storage::tx::TxStore::new(tx);
        let mut session = tx_store.session_store();
        let mut identity = tx_store.identity_store(crate::crypto::prekeys::IdentityKind::Aci);

        let mut outbound: Vec<SingleOutboundUnsealedMessage<CiphertextMessage>> = Vec::with_capacity(known.len());
        for &device_id_u32 in known {
            let device_id =
                device_id_from_u32(device_id_u32).map_err(|e| SendError::Server(format!("device_id: {e}")))?;
            let remote_address = ProtocolAddress::new(target_string.clone(), device_id);
            let record = SessionStore::load_session(&session, &remote_address)
                .await?
                .ok_or_else(|| SendError::Server(format!("session row for device {device_id} disappeared")))?;
            let registration_id = record.remote_registration_id().map_err(SendError::Signal)?;
            let ciphertext = libsignal_protocol::message_encrypt(
                content_bytes,
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
        drop(session);
        drop(identity);
        tx_store.commit().await.map_err(StoreError::from)?;

        let (auth_chat, events) = self
            .open_authenticated_chat()
            .await
            .map_err(|e| SendError::Server(format!("open auth chat: {e}")))?;
        drop(events);
        let auth = Auth(auth_chat);
        auth.send_message(
            ServiceId::from(target),
            libsignal_protocol::Timestamp::from_epoch_millis(timestamp_ms),
            &outbound,
            false,
            true,
        )
        .await
        .map_err(|e| SendError::Server(format!("send_message: {e:?}")))?;

        Ok(())
    }

    /// Encrypt a Note-to-Self transcript to each of the user's OTHER
    /// linked devices and dispatch via `send_sync_message`. The chat
    /// server fans the encrypted blobs to those devices; the user's
    /// other devices decode and surface them as `SyncMessage::Sent`.
    ///
    /// Routing: Signal's sync-message contract is "encrypt the same
    /// transcript once per other-device, addressed `own_aci.device_id`".
    /// We must NOT include our own device_id in the contents - the chat
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
    async fn send_note_to_self(&self, body: &str, attachments: &[proto::AttachmentPointer]) -> Result<u64, SendError> {
        let timestamp_ms = now_millis();
        debug!(
            "send_note_to_self: body_len={} timestamp_ms={}",
            body.len(),
            timestamp_ms
        );

        let aci_string = self
            .inner
            .store
            .get_aci()
            .await?
            .ok_or(SendError::MissingCredential("aci"))?;
        let content_bytes = build_sync_self_content(body, &aci_string, timestamp_ms, attachments);
        self.dispatch_sync_to_own_devices(&content_bytes, timestamp_ms).await?;
        Ok(timestamp_ms)
    }

    /// Encrypt a pre-built SyncMessage `Content` payload for every OTHER
    /// linked device on our account and dispatch via the authenticated
    /// chat's `send_sync_message`. Returns once the chat-server has
    /// accepted the fan-out (or short-circuits with `Ok(())` if we have
    /// no other devices yet).
    ///
    /// Two callers today:
    /// - Note-to-Self (`send_note_to_self`): syncs the user's own
    ///   `SyncMessage::Sent` transcript so other devices see the message.
    /// - Remote delete (`Client::delete_for_everyone`): syncs the
    ///   delete tombstone so the user's other devices also remove the
    ///   message from their thread (the peer delete is a separate
    ///   call; this one only handles own-device fan-out).
    ///
    /// `content_bytes` must already encode a top-level
    /// `Content::SyncMessage(...)` payload; the caller decides the
    /// inner shape (Sent for transcripts, Sent-with-delete for
    /// tombstones, etc.). `timestamp_ms` is the wire-level send
    /// timestamp and must match the one embedded in the SyncMessage
    /// (per the receive-side correlation contract).
    ///
    /// Atomicity: encrypt + session-state persist run inside one
    /// `sqlx::Transaction` via TxStore, matching the receive-side
    /// contract from Phase 6.
    async fn dispatch_sync_to_own_devices(&self, content_bytes: &[u8], timestamp_ms: u64) -> Result<(), SendError> {
        use libsignal_net_chat::api::keys::{DeviceSpecifier, UnauthenticatedChatApi};
        use libsignal_net_chat::api::messages::{AuthenticatedChatApi, SingleOutboundUnsealedMessage};
        use libsignal_net_chat::api::{Auth, Unauth, UserBasedAuthorization};
        use libsignal_protocol::ServiceId;

        debug!(
            "dispatch_sync_to_own_devices: content_len={} timestamp_ms={}",
            content_bytes.len(),
            timestamp_ms
        );

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
                info!(
                    "dispatch_sync_to_own_devices: no other devices to sync to (we are the only device); \
                     no-op timestamp_ms={}",
                    timestamp_ms
                );
                return Ok(());
            }
            Some(bundles)
        } else {
            None
        };

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
                    content_bytes,
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
                    content_bytes,
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
            libsignal_protocol::Timestamp::from_epoch_millis(timestamp_ms),
            &outbound,
            true, // urgent
        )
        .await
        .map_err(|e| SendError::Server(format!("send_sync_message: {e:?}")))?;

        info!(
            "dispatch_sync_to_own_devices: dispatched content_len={} to {} other device(s) timestamp_ms={}",
            content_bytes.len(),
            outbound.len(),
            timestamp_ms
        );
        Ok(())
    }
}

/// Build the inner Content protobuf for a 1:1 send: a DataMessage with
/// the body, timestamp, and any attachment pointers, wrapped in the
/// top-level Content.
pub(crate) fn build_one_to_one_content(
    body: &str,
    timestamp: u64,
    attachments: &[proto::AttachmentPointer],
) -> Vec<u8> {
    use prost::Message as _;

    debug!(
        "build_one_to_one_content: body_len={} timestamp={} attachments={}",
        body.len(),
        timestamp,
        attachments.len()
    );

    let dm = proto::DataMessage {
        body: Some(body.to_string()),
        timestamp: Some(timestamp),
        attachments: attachments.to_vec(),
        ..Default::default()
    };
    let content = proto::Content {
        content: Some(proto::content::Content::DataMessage(dm)),
        ..Default::default()
    };
    content.encode_to_vec()
}

/// Build the inner Content protobuf for a typing indicator: wraps a
/// `TypingMessage` (with `STARTED` or `STOPPED` action and the supplied
/// timestamp) in the top-level Content. The `groupId` field is left
/// unset; only 1:1 typing is supported by [`Client::typing`] in v1.
pub(crate) fn build_typing_content(started: bool, timestamp: u64) -> Vec<u8> {
    use prost::Message as _;

    debug!("build_typing_content: started={} timestamp={}", started, timestamp);

    let action = if started {
        proto::typing_message::Action::Started
    } else {
        proto::typing_message::Action::Stopped
    };
    let tm = proto::TypingMessage {
        timestamp: Some(timestamp),
        action: Some(action as i32),
        group_id: None,
    };
    let content = proto::Content {
        content: Some(proto::content::Content::TypingMessage(tm)),
        ..Default::default()
    };
    content.encode_to_vec()
}

/// Build the inner Content protobuf for a remote-delete request:
/// wraps a `DataMessage` whose only meaningful field is
/// `delete: Delete { target_sent_timestamp }`, plus the outer
/// `timestamp` so the peer's client can correlate the delete
/// envelope. No body, no attachments - the receiver replaces the
/// targeted message in its UI with a tombstone.
pub(crate) fn build_delete_content(target_sent_timestamp: u64, timestamp: u64) -> Vec<u8> {
    use prost::Message as _;

    debug!(
        "build_delete_content: target_sent_timestamp={} timestamp={}",
        target_sent_timestamp, timestamp
    );

    let dm = proto::DataMessage {
        timestamp: Some(timestamp),
        delete: Some(proto::data_message::Delete {
            target_sent_timestamp: Some(target_sent_timestamp),
        }),
        ..Default::default()
    };
    let content = proto::Content {
        content: Some(proto::content::Content::DataMessage(dm)),
        ..Default::default()
    };
    content.encode_to_vec()
}

/// Build the inner Content protobuf for the *sync* half of a remote
/// delete: wraps a `DataMessage` whose only meaningful field is
/// `delete.target_sent_timestamp` inside a `SyncMessage::Sent` whose
/// `destination_service_id` names the *peer* whose message was deleted.
/// Sent to the user's own OTHER linked devices so they also remove the
/// targeted message from the thread.
///
/// Symmetric to [`build_delete_content`] but for the own-device fan-out;
/// the peer fan-out uses the bare `DataMessage` shape because the peer
/// has no concept of "the user deleted a message in our thread - here
/// is the transcript you should mirror," only "delete this id."
pub(crate) fn build_sync_delete_content(peer_destination: &str, target_sent_timestamp: u64, timestamp: u64) -> Vec<u8> {
    use prost::Message as _;

    debug!(
        "build_sync_delete_content: peer_destination={} target_sent_timestamp={} timestamp={}",
        peer_destination, target_sent_timestamp, timestamp
    );

    let dm = proto::DataMessage {
        timestamp: Some(timestamp),
        delete: Some(proto::data_message::Delete {
            target_sent_timestamp: Some(target_sent_timestamp),
        }),
        ..Default::default()
    };
    let sent = proto::sync_message::Sent {
        destination_service_id: Some(peer_destination.to_string()),
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

/// Build the inner Content protobuf for a Note-to-Self send: wraps the
/// body and attachment pointers as a DataMessage and tags it via
/// SyncMessage::Sent so the receiver-side filter (`destination ==
/// own_number`) fires.
pub(crate) fn build_sync_self_content(
    body: &str,
    own_destination: &str,
    timestamp: u64,
    attachments: &[proto::AttachmentPointer],
) -> Vec<u8> {
    use prost::Message as _;

    debug!(
        "build_sync_self_content: body_len={} own_destination={} timestamp={} attachments={}",
        body.len(),
        own_destination,
        timestamp,
        attachments.len()
    );

    let dm = proto::DataMessage {
        body: Some(body.to_string()),
        timestamp: Some(timestamp),
        attachments: attachments.to_vec(),
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

/// Map our public [`AttachmentPointer`] (returned by `upload_attachment_*`)
/// into the prost-generated proto. The proto uses a oneof for cdn id vs
/// cdn key plus bitflags for `voice_note`/`borderless`/`gif`; the public
/// type keeps those flat for easier consumer use.
pub(crate) fn attachment_pointer_to_proto(p: AttachmentPointer) -> proto::AttachmentPointer {
    let identifier = match p.cdn_key {
        Some(k) => Some(proto::attachment_pointer::AttachmentIdentifier::CdnKey(k)),
        None => Some(proto::attachment_pointer::AttachmentIdentifier::CdnId(p.cdn_id)),
    };
    let mut flags: u32 = 0;
    if p.voice_note {
        flags |= proto::attachment_pointer::Flags::VoiceMessage as u32;
    }
    if p.borderless {
        flags |= proto::attachment_pointer::Flags::Borderless as u32;
    }
    if p.gif {
        flags |= proto::attachment_pointer::Flags::Gif as u32;
    }
    proto::AttachmentPointer {
        client_uuid: None,
        content_type: p.content_type,
        key: Some(p.key),
        size: p.size,
        thumbnail: None,
        digest: Some(p.digest),
        incremental_mac: None,
        chunk_size: None,
        file_name: p.file_name,
        flags: if flags == 0 { None } else { Some(flags) },
        width: p.width,
        height: p.height,
        caption: p.caption,
        blur_hash: p.blurhash,
        upload_timestamp: p.upload_timestamp,
        cdn_number: Some(p.cdn_number),
        attachment_identifier: identifier,
    }
}

/// Best-effort Content-Type guess from a path's extension. Recognized
/// extensions return the canonical MIME type; unrecognized extensions
/// fall through to `application/octet-stream` (so the pointer always
/// carries some `content_type` when the path has an extension). Paths
/// without any extension at all return `None`. We deliberately keep the
/// table small: only the formats borg / signal-rs are expected to send
/// in practice (text, images, common audio/video, generic binary).
fn mime_guess_for_path(path: &std::path::Path) -> Option<String> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    let mime = match ext.as_str() {
        "txt" | "log" | "md" => "text/plain",
        "json" => "application/json",
        "yaml" | "yml" => "application/yaml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "mp3" => "audio/mpeg",
        "ogg" | "oga" => "audio/ogg",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    };
    Some(mime.to_string())
}
