//! Linking flow: drive libsignal-net's provisioning WebSocket, decrypt the
//! envelope via the Phase 4 cipher, persist identity, upload initial prekeys.
//!
//! The orchestration here splits into two halves:
//!
//! - **The "live" half** - opens a provisioning WebSocket to Signal, waits
//!   for `ReceivedAddress` → renders the QR via the caller's callback →
//!   waits for `ReceivedEnvelope` → uploads initial prekeys to Signal's
//!   keyserver. This half cannot run without real Signal infrastructure; it
//!   is reachable only via [`link`] and is exercised by Phase 10's manual
//!   smoke test.
//!
//! - **The "post-decrypt" half** - [`persist_provision_message`] takes a
//!   decrypted [`ProvisionMessage`] (from Phase 4's `decrypt_envelope`) and
//!   a [`SqliteStore`], maps the protobuf fields onto our identity bundle,
//!   and persists them at `link_status = IdentityPersisted`. This is the
//!   half that handles the half-linked recovery story and is integration-
//!   tested with synthesized envelopes.

use std::path::Path;
use std::time::Duration;

use libsignal_net::chat::server_requests::ProvisioningEvent;
use libsignal_net::chat::ws::ListenerEvent;
use libsignal_protocol::IdentityKeyPair;
use log::{debug, info};
use thiserror::Error;
use tokio::time::timeout;

use crate::crypto::prekeys::{IdentityKind, PrekeyError, generate_upload_persist};
use crate::crypto::provisioning::{ProvisioningKeyPair, decrypt_envelope, proto::ProvisionMessage};
use crate::net::{Environment as NetEnv, NetError, connect_provisioning};
use crate::storage::{LinkStatus, SqliteStore, Store, StoreError};

const PROVISIONING_URI_SCHEME: &str = "sgnl";

/// How long to wait for the Signal server to push the
/// `ProvisioningEvent::ReceivedAddress` after we open the WebSocket. Signal's
/// provisioning service responds within seconds; if we are still waiting at
/// this point the connection is dead.
const PROVISIONING_ADDRESS_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for the user to scan the QR with their primary device and
/// for the primary to forward the encrypted identity envelope. Reasonable
/// upper bound for a manual scan.
const PROVISIONING_ENVELOPE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Error, Debug)]
pub enum LinkError {
    #[error("storage error: {0}")]
    Storage(#[from] StoreError),

    #[error("provisioning cipher error: {0}")]
    Cipher(#[from] crate::crypto::provisioning::ProvisioningCipherError),

    #[error("ProvisionMessage missing required field: {0}")]
    MissingField(&'static str),

    #[error(
        "ProvisionMessage carries an invalid identity keypair: {0}; \
         linking aborted before persisting"
    )]
    InvalidIdentityKey(String),

    #[error("libsignal-protocol error: {0}")]
    Signal(#[from] libsignal_protocol::SignalProtocolError),

    #[error("libsignal-net connect error: {0}")]
    Net(#[from] NetError),

    #[error("prekey error: {0}")]
    Prekey(#[from] PrekeyError),

    #[error("provisioning event stream closed before expected event arrived")]
    ProvisioningStreamClosed,

    #[error("provisioning event {0} could not be decoded: {1}")]
    ProvisioningEventDecode(&'static str, String),

    #[error("provisioning server pushed unexpected event {0} before expected event {1}")]
    UnexpectedProvisioningEvent(&'static str, &'static str),

    #[error("timed out waiting for provisioning event {0} after {1:?}")]
    ProvisioningTimeout(&'static str, Duration),

    #[error("provisioning server disconnected before linking completed: {0}")]
    ProvisioningDisconnected(String),

    #[error("device-completion failed (PUT /v1/devices): {0}")]
    DeviceCompletion(String),
}

/// Outcome returned to the caller of [`link`] once linking succeeds and
/// `link_status` reaches `Linked`.
#[derive(Debug, Clone)]
pub struct LinkOutcome {
    pub account_number: String,
    pub device_id: u32,
}

/// Build a `sgnl://` provisioning URI from our ephemeral pubkey + the
/// opaque server-issued address. The primary device scans this as a QR
/// code; format matches signal-service-android's `ProvisioningManager`.
///
/// The address is the value pulled from `ProvisioningEvent::ReceivedAddress`
/// and is treated as opaque by both sides.
pub fn build_provisioning_uri(public_key: &[u8], address: &str) -> String {
    use base64::Engine as _;
    let pub_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(public_key);
    // sgnl://linkdevice?uuid=<address>&pub_key=<base64-no-pad>
    format!(
        "{}://linkdevice?uuid={}&pub_key={}",
        PROVISIONING_URI_SCHEME,
        url_encode(address),
        url_encode(&pub_b64),
    )
}

/// Minimal percent-encoder for sgnl:// URI components. Encodes anything
/// outside the unreserved set per RFC 3986.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.' | b'~') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Persist identity from a decrypted ProvisionMessage. Sets
/// `link_status = IdentityPersisted`; the caller transitions to `Linked`
/// once the initial prekey upload succeeds.
///
/// This is the testable half of linking - the part that doesn't need a
/// live Signal connection.
pub async fn persist_provision_message(store: &SqliteStore, msg: &ProvisionMessage) -> Result<LinkOutcome, LinkError> {
    debug!(
        "persist_provision_message: number={} provisioningVersion={:?}",
        msg.number.as_deref().unwrap_or("<missing>"),
        msg.provisioning_version,
    );

    let aci_pub = msg
        .aci_identity_key_public
        .as_deref()
        .ok_or(LinkError::MissingField("aciIdentityKeyPublic"))?;
    let aci_priv = msg
        .aci_identity_key_private
        .as_deref()
        .ok_or(LinkError::MissingField("aciIdentityKeyPrivate"))?;
    let number = msg.number.clone().ok_or(LinkError::MissingField("number"))?;

    // libsignal's IdentityKeyPair::new takes (IdentityKey, PrivateKey). We
    // assemble both from the protobuf-supplied bytes. Validation errors at
    // this point indicate the primary device sent us garbage - bail before
    // persisting anything.
    let identity_pub = libsignal_protocol::IdentityKey::decode(aci_pub)
        .map_err(|e| LinkError::InvalidIdentityKey(format!("aci pub: {e}")))?;
    let identity_priv = libsignal_protocol::PrivateKey::deserialize(aci_priv)
        .map_err(|e| LinkError::InvalidIdentityKey(format!("aci priv: {e}")))?;
    let identity_keypair = IdentityKeyPair::new(identity_pub, identity_priv);

    // Signal mints registration IDs on the device side; primary supplies a
    // provisioningCode, not a registration_id. Generate a fresh one here.
    // libsignal's KeyHelper-equivalent: use a CSPRNG-derived u32 in the
    // 1..=16380 range per Signal's protocol convention.
    let registration_id = generate_registration_id();
    // device_id is a placeholder until the PUT /v1/devices/{code} call
    // returns the real one; we persist 0 here and overwrite in
    // `complete_device_registration`.
    let placeholder_device_id = 0;

    store
        .save_identity_bundle(
            &identity_keypair,
            registration_id,
            &number,
            placeholder_device_id,
            LinkStatus::IdentityPersisted,
        )
        .await?;

    // ACI, PNI, profile key are needed by the device-completion + keys
    // upload calls. Persist them now even though the link is only
    // half-complete; the half-linked-resume path can pick them up.
    if let Some(aci) = &msg.aci {
        store.set_aci(aci).await?;
    }
    if let Some(pni) = &msg.pni {
        store.set_pni(pni).await?;
    }
    // PNI identity keypair - independent of ACI. Used to sign PNI-side
    // prekey bundles. signal-cli generates separate prekey batches per
    // identity; without the PNI keypair persisted, peers routing to us
    // by phone-number identifier can't establish sessions.
    if let (Some(pni_pub), Some(pni_priv)) = (&msg.pni_identity_key_public, &msg.pni_identity_key_private) {
        let pni_identity_pub = libsignal_protocol::IdentityKey::decode(pni_pub)
            .map_err(|e| LinkError::InvalidIdentityKey(format!("pni pub: {e}")))?;
        let pni_identity_priv = libsignal_protocol::PrivateKey::deserialize(pni_priv)
            .map_err(|e| LinkError::InvalidIdentityKey(format!("pni priv: {e}")))?;
        let pni_keypair = IdentityKeyPair::new(pni_identity_pub, pni_identity_priv);
        store.set_pni_identity_keypair(&pni_keypair).await?;
    }
    if let Some(profile_key) = &msg.profile_key {
        store.set_profile_key(profile_key).await?;
    }
    if let Some(code) = &msg.provisioning_code {
        store.set_provisioning_code(code).await?;
    }

    info!(
        "persist_provision_message: persisted identity for {} link_status=IdentityPersisted (device_id pending PUT /v1/devices)",
        number
    );

    Ok(LinkOutcome {
        account_number: number,
        device_id: placeholder_device_id,
    })
}

/// Generate a Signal-style registration ID. Signal's protocol uses a u32
/// in the range `1..=16380` so it fits in a 14-bit varint and stays away
/// from reserved values. Uses the OS-provided CSPRNG.
fn generate_registration_id() -> u32 {
    use rand::Rng;
    let mut rng = rand::rng();
    rng.random_range(1..=16380)
}

/// Top-level linking entry. Drives Signal's provisioning WebSocket through
/// to a fully linked state directory:
///
/// 1. Open the provisioning WebSocket via `libsignal-net`.
/// 2. Wait for `ProvisioningEvent::ReceivedAddress`, build the `sgnl://`
///    URI, invoke `display_qr` so the operator can scan it on the primary
///    device.
/// 3. Wait for `ProvisioningEvent::ReceivedEnvelope`, decrypt via the
///    Phase 4 cipher, persist identity at `link_status = IdentityPersisted`.
/// 4. Generate the initial prekey batch, persist locally, upload to
///    Signal's keyserver, then transition `link_status = Linked`.
///
/// **Half-linked resume:** if the state directory is already at
/// `IdentityPersisted` (because a prior call crashed between identity
/// persistence and prekey upload), the QR/protocol-exchange phase is
/// skipped and we resume directly at step 4.
pub async fn link(
    state_dir: &Path,
    device_name: &str,
    display_qr: impl FnOnce(&str),
) -> Result<LinkOutcome, LinkError> {
    debug!("link: state_dir={} device_name={}", state_dir.display(), device_name);

    let store = SqliteStore::open(state_dir).await?;

    // Half-linked recovery: skip the protocol exchange entirely and pick
    // up at whichever sub-step did not finish last time. `load_identity`
    // returns `NotLinked` for a virgin state dir; only `IdentityPersisted`
    // triggers the resume.
    match store.load_identity().await {
        Ok(identity) if identity.link_status == LinkStatus::IdentityPersisted => {
            info!(
                "link: resuming half-linked state (account={}, link_status=IdentityPersisted)",
                identity.account_number
            );
            return finalize_after_persist(&store, &identity.account_number, device_name).await;
        }
        Ok(linked) => {
            // Already Linked: nothing to do, just report current state.
            return Ok(LinkOutcome {
                account_number: linked.account_number,
                device_id: linked.device_id,
            });
        }
        Err(StoreError::NotLinked) => {
            // Fresh state dir - drop through to the live handshake.
        }
        Err(e) => return Err(e.into()),
    }

    let outcome = drive_provisioning_handshake(&store, display_qr).await?;
    finalize_after_persist(&store, &outcome.account_number, device_name).await
}

/// Run the post-persist steps of linking: device-completion (if not
/// already done) and prekey upload. Shared between the fresh-link path
/// and the half-linked-resume path. Returns the final LinkOutcome with
/// the server-assigned device_id.
async fn finalize_after_persist(
    store: &SqliteStore,
    account_number: &str,
    device_name: &str,
) -> Result<LinkOutcome, LinkError> {
    let identity = store.load_identity().await?;
    let registration_id = identity.registration_id;

    // Device-completion only runs once per provisioning_code; check
    // whether we already have a password (proxy for "device-completion
    // succeeded previously") before calling.
    let device_id = match store.get_password().await? {
        Some(_) => {
            debug!("finalize_after_persist: password already set, skipping device-completion");
            identity.device_id
        }
        None => {
            let code = store
                .get_provisioning_code()
                .await?
                .ok_or(LinkError::MissingField("provisioningCode (after persist)"))?;
            let assigned =
                crate::api::complete_device_registration(store, &code, device_name, account_number, registration_id)
                    .await
                    .map_err(|e| LinkError::DeviceCompletion(e.to_string()))?;
            store.clear_provisioning_code().await?;
            assigned
        }
    };

    finish_prekey_upload(store, account_number).await?;

    Ok(LinkOutcome {
        account_number: account_number.to_string(),
        device_id,
    })
}

/// Open the provisioning WebSocket, drive the handshake to
/// `link_status = IdentityPersisted`, return the resulting outcome.
async fn drive_provisioning_handshake(
    store: &SqliteStore,
    display_qr: impl FnOnce(&str),
) -> Result<LinkOutcome, LinkError> {
    let mut rng = rand::rng();
    let keypair = ProvisioningKeyPair::generate(&mut rng);
    let pubkey = keypair.public_key_bytes();

    let (chat, mut events) = connect_provisioning(NetEnv::Production).await?;
    debug!("drive_provisioning_handshake: provisioning WebSocket opened");

    let address = match wait_for_event(&mut events, "ReceivedAddress", PROVISIONING_ADDRESS_TIMEOUT).await? {
        ProvisioningEvent::ReceivedAddress { address, send_ack } => {
            // Ack the address so the server proceeds; ignore the result -
            // libsignal returns Err only if the WebSocket is already dead,
            // which the next recv() will surface anyway.
            let _ = send_ack(http::StatusCode::OK);
            address
        }
        other => return Err(unexpected("ReceivedAddress", &other)),
    };

    let uri = build_provisioning_uri(&pubkey, &address);
    debug!("drive_provisioning_handshake: built sgnl:// URI, invoking display_qr");
    display_qr(&uri);

    let envelope_bytes = match wait_for_event(&mut events, "ReceivedEnvelope", PROVISIONING_ENVELOPE_TIMEOUT).await? {
        ProvisioningEvent::ReceivedEnvelope { envelope, send_ack } => {
            let _ = send_ack(http::StatusCode::OK);
            envelope
        }
        other => return Err(unexpected("ReceivedEnvelope", &other)),
    };

    // We have what we need; close the provisioning WebSocket cleanly. The
    // primary device's job is done at this point.
    chat.disconnect().await;

    let msg = decrypt_envelope(&keypair, &envelope_bytes)?;
    persist_provision_message(store, &msg).await
}

/// Step 4 of [`link`]: generate prekeys, upload them, transition to
/// `Linked`. Pulled into its own function so the half-linked-resume path
/// can call it directly without going through the WebSocket handshake.
async fn finish_prekey_upload(store: &SqliteStore, account_number: &str) -> Result<(), LinkError> {
    debug!("finish_prekey_upload: account={}", account_number);
    let mut rng = rand::rng();
    // Initial upload: ACI keys first, then PNI keys (signal-cli does
    // both during link). Each is its own batch with its own signing
    // identity. Phase 8 replenishment will continue from the highest
    // id already in the store, per identity. Both batches start at id
    // 1 because they live in disjoint server-side pools.
    generate_upload_persist(&mut rng, store, IdentityKind::Aci, 1).await?;
    // PNI batch only if a PNI keypair was supplied by the primary.
    if store.get_pni_identity_keypair().await?.is_some() {
        generate_upload_persist(&mut rng, store, IdentityKind::Pni, 1).await?;
    } else {
        debug!("finish_prekey_upload: no PNI identity persisted, skipping PNI prekey upload");
    }
    mark_linked(store).await?;
    info!("finish_prekey_upload: link_status -> Linked");
    Ok(())
}

/// Pull the next typed `ProvisioningEvent` off the listener channel,
/// converting from `ws::ListenerEvent` and applying a timeout. Maps the
/// non-event states (`Stopped`, channel close) to typed `LinkError`s.
async fn wait_for_event(
    events: &mut tokio::sync::mpsc::UnboundedReceiver<ListenerEvent>,
    label: &'static str,
    deadline: Duration,
) -> Result<ProvisioningEvent, LinkError> {
    let raw = timeout(deadline, events.recv())
        .await
        .map_err(|_| LinkError::ProvisioningTimeout(label, deadline))?
        .ok_or(LinkError::ProvisioningStreamClosed)?;
    let typed =
        ProvisioningEvent::try_from(raw).map_err(|e| LinkError::ProvisioningEventDecode(label, e.to_string()))?;
    if let ProvisioningEvent::Stopped(cause) = &typed {
        return Err(LinkError::ProvisioningDisconnected(format!("{cause:?}")));
    }
    Ok(typed)
}

/// Format an unexpected `ProvisioningEvent` for the error path.
fn unexpected(expected: &'static str, got: &ProvisioningEvent) -> LinkError {
    let got_label: &'static str = match got {
        ProvisioningEvent::ReceivedAddress { .. } => "ReceivedAddress",
        ProvisioningEvent::ReceivedEnvelope { .. } => "ReceivedEnvelope",
        ProvisioningEvent::Stopped(_) => "Stopped",
    };
    LinkError::UnexpectedProvisioningEvent(got_label, expected)
}

/// Convenience: generate an ephemeral keypair + provisioning URI for a
/// caller that wants to drive `ProvisioningConnection` directly. Returned
/// `ProvisioningKeyPair` must be held alive until the encrypted envelope
/// arrives - its private half decrypts the response.
pub fn prepare_link_session<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    address: &str,
) -> (ProvisioningKeyPair, String) {
    let kp = ProvisioningKeyPair::generate(rng);
    let uri = build_provisioning_uri(&kp.public_key_bytes(), address);
    (kp, uri)
}

/// Decrypt an envelope and persist in one step. The integration-test
/// surface that exercises the full post-decrypt path Phase 5 owns. Used
/// by both `link` (once wired) and direct consumers that already drove
/// the ProvisioningConnection themselves.
pub async fn finalize_link(
    store: &SqliteStore,
    keypair: &ProvisioningKeyPair,
    encrypted_envelope: &[u8],
) -> Result<LinkOutcome, LinkError> {
    let msg = decrypt_envelope(keypair, encrypted_envelope)?;
    persist_provision_message(store, &msg).await
}

/// Resume a half-linked state directory by transitioning `link_status`
/// to `Linked`. Called after the initial prekey upload succeeds. Without
/// this, [`SqliteStore::load_identity`] keeps returning `PartiallyLinked`
/// and the device is silently unreachable by new peers.
pub async fn mark_linked(store: &SqliteStore) -> Result<(), LinkError> {
    debug!("mark_linked: transitioning IdentityPersisted -> Linked");
    store.set_link_status(LinkStatus::Linked).await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
