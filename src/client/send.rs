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

use libsignal_protocol::{Aci, CiphertextMessage, DeviceId, ProtocolAddress, SessionStore};
use log::{debug, info, warn};

use crate::crypto::provisioning::proto;
use crate::envelope::Recipient;
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
        match to {
            Recipient::SelfSync => self.send_note_to_self(body).await,
            Recipient::Aci(uuid) => {
                let aci = Aci::parse_from_service_id_string(&uuid)
                    .ok_or_else(|| SendError::InvalidRecipient(format!("aci uuid: {uuid}")))?;
                self.send_to_peer_aci(aci, body).await
            }
            Recipient::Pni(_) => Err(SendError::PniSendUnsupported),
        }
    }

    /// Internal dispatch for a peer ACI target. Looks up the stored
    /// profile key and routes to sealed-sender if present, or an
    /// unsealed fallback (with a `warn!` so the operator sees the
    /// privacy downgrade) if not.
    async fn send_to_peer_aci(&self, target: Aci, body: &str) -> Result<u64, SendError> {
        let target_string = target.service_id_string();
        let peer_pk = self.inner.store.get_peer_profile_key(&target_string).await?;

        if let Some(pk_bytes) = peer_pk {
            let pk_arr: [u8; zkgroup::PROFILE_KEY_LEN] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| SendError::Server(format!("peer profile_key bad length: {}", pk_bytes.len())))?;
            let access_key = zkgroup::profiles::ProfileKey::create(pk_arr).derive_access_key();
            return self.send_sealed_to_aci(target, body, access_key).await;
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
            "send_to_peer_aci: no profile key for {} - falling back to unsealed send over \
             existing sessions ({} device(s)); this leaks sender identity to the server",
            target_string,
            known.len()
        );
        self.send_unsealed_hotpath(target, body, &known).await
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
        body: &str,
        access_key: [u8; zkgroup::ACCESS_KEY_LEN],
    ) -> Result<u64, SendError> {
        let target_string = target.service_id_string();
        let timestamp_ms = now_millis();
        debug!(
            "send_sealed_to_aci: target={} body_len={} timestamp_ms={}",
            target_string,
            body.len(),
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
            .encrypt_and_dispatch_sealed(&target, &target_string, body, timestamp_ms, &cert, access_key, targets)
            .await?
        {
            SendAttempt::Ok => {
                info!(
                    "send_sealed_to_aci: dispatched to {} timestamp_ms={}",
                    target_string, timestamp_ms
                );
                Ok(timestamp_ms)
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
                        body,
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
                        Ok(timestamp_ms)
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
        body: &str,
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
            "encrypt_and_dispatch_sealed: target={} devices={} timestamp_ms={}",
            target_string,
            targets.len(),
            timestamp_ms
        );

        let content_bytes = build_one_to_one_content(body, timestamp_ms);

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
                &content_bytes,
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
    async fn send_unsealed_hotpath(&self, target: Aci, body: &str, known: &[u32]) -> Result<u64, SendError> {
        use libsignal_net_chat::api::Auth;
        use libsignal_net_chat::api::messages::{AuthenticatedChatApi, SingleOutboundUnsealedMessage};
        use libsignal_protocol::ServiceId;

        let target_string = target.service_id_string();
        let timestamp_ms = now_millis();
        debug!(
            "send_unsealed_hotpath: target={} devices={} body_len={} timestamp_ms={}",
            target_string,
            known.len(),
            body.len(),
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

        let content_bytes = build_one_to_one_content(body, timestamp_ms);
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

        Ok(timestamp_ms)
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
    async fn send_note_to_self(&self, body: &str) -> Result<u64, SendError> {
        use libsignal_net_chat::api::keys::{DeviceSpecifier, UnauthenticatedChatApi};
        use libsignal_net_chat::api::messages::{AuthenticatedChatApi, SingleOutboundUnsealedMessage};
        use libsignal_net_chat::api::{Auth, Unauth, UserBasedAuthorization};
        use libsignal_protocol::ServiceId;

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
                    "send_note_to_self: no other devices to sync to (we are the only device); \
                     no-op timestamp_ms={}",
                    timestamp_ms
                );
                return Ok(timestamp_ms);
            }
            Some(bundles)
        } else {
            None
        };

        let content_bytes = build_sync_self_content(body, &aci_string, timestamp_ms);

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
            libsignal_protocol::Timestamp::from_epoch_millis(timestamp_ms),
            &outbound,
            true, // urgent
        )
        .await
        .map_err(|e| SendError::Server(format!("send_sync_message: {e:?}")))?;

        info!(
            "send_note_to_self: dispatched body_len={} to {} other device(s) timestamp_ms={}",
            body.len(),
            outbound.len(),
            timestamp_ms
        );
        Ok(timestamp_ms)
    }
}

/// Build the inner Content protobuf for a 1:1 send: a DataMessage with
/// the body and timestamp, wrapped in the top-level Content.
pub(crate) fn build_one_to_one_content(body: &str, timestamp: u64) -> Vec<u8> {
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
pub(crate) fn build_sync_self_content(body: &str, own_destination: &str, timestamp: u64) -> Vec<u8> {
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
