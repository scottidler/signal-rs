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

use libsignal_protocol::IdentityKeyPair;
use log::{debug, info, warn};
use thiserror::Error;

use crate::crypto::provisioning::{ProvisioningKeyPair, decrypt_envelope, proto::ProvisionMessage};
use crate::storage::{LinkStatus, SqliteStore, Store, StoreError};

const PROVISIONING_URI_SCHEME: &str = "sgnl";

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

    #[error(
        "live-server linking is not yet wired up; \
         Phase 10 manual smoke test will exercise libsignal-net::ProvisioningConnection"
    )]
    LiveServerNotImplemented,
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
    let device_id = msg.provisioning_version.unwrap_or(1);

    store
        .save_identity_bundle(
            &identity_keypair,
            registration_id,
            &number,
            device_id,
            LinkStatus::IdentityPersisted,
        )
        .await?;

    info!(
        "persist_provision_message: persisted identity for {} device_id={} link_status=IdentityPersisted",
        number, device_id
    );

    Ok(LinkOutcome {
        account_number: number,
        device_id,
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

/// Top-level linking entry. **Not yet wired to live Signal servers** -
/// returns `LinkError::LiveServerNotImplemented` until Phase 10. Library
/// consumers (borg) interact with [`persist_provision_message`] directly
/// via a fixture path until then.
///
/// Once wired, the flow is documented in the design doc § "Data flow for
/// link". The `display_qr` callback exists so consumers (CLI vs.
/// programmatic) can render the URI however they like.
pub async fn link(
    _state_dir: &Path,
    _device_name: &str,
    _display_qr: impl FnOnce(&str),
) -> Result<LinkOutcome, LinkError> {
    warn!("link: live-server flow is Phase 10 manual smoke test");
    Err(LinkError::LiveServerNotImplemented)
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
