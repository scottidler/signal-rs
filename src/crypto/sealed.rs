//! Sealed sender (UNIDENTIFIED_SENDER) trust-root configuration and the
//! multi-root validation helper.
//!
//! Signal production runs TWO trust roots concurrently. signal-cli's
//! `lib/.../config/LiveConfig.java` exposes them as
//! `UNIDENTIFIED_SENDER_TRUST_ROOT` and `UNIDENTIFIED_SENDER_TRUST_ROOT2`
//! and returns both in a `List<ECPublicKey>` (lines 28-30, 83-84). A
//! client that pins to a single root silently drops every sealed-sender
//! message whose certificate chain terminates at the OTHER root,
//! defeating the entire phase.
//!
//! libsignal's `sealed_sender_decrypt` wrapper accepts ONE trust root,
//! which is why `client::process_envelope`'s sealed branch reaches for
//! `sealed_sender_decrypt_to_usmc` + this module's
//! [`validate_against_trust_roots`] helper directly. The helper wraps
//! libsignal's `SenderCertificate::validate_with_trust_roots` which
//! performs constant-time multi-root validation via `subtle::Choice`
//! (hides which root matched). This is strictly safer than the manual
//! iterate-and-short-circuit the design doc originally outlined.
//!
//! Reference:
//! - signal-cli `LiveConfig.java`: trust-root byte sources.
//! - libsignal `rust/protocol/src/sealed_sender.rs:331`:
//!   `validate_with_trust_roots`.

use std::sync::LazyLock;

use base64::Engine;
use libsignal_protocol::{PublicKey, SenderCertificate, SignalProtocolError, Timestamp};
use log::{debug, warn};

/// Production trust root #1 (UNIDENTIFIED_SENDER_TRUST_ROOT in signal-cli's
/// LiveConfig.java, lines 28-29).
const TRUST_ROOT_1_BASE64: &str = "BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF";
/// Production trust root #2 (UNIDENTIFIED_SENDER_TRUST_ROOT2 in signal-cli's
/// LiveConfig.java, lines 30-31).
const TRUST_ROOT_2_BASE64: &str = "BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6";

static PRODUCTION_TRUST_ROOTS: LazyLock<[PublicKey; 2]> = LazyLock::new(|| {
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes_1 = engine
        .decode(TRUST_ROOT_1_BASE64)
        .expect("TRUST_ROOT_1_BASE64 is a compile-time constant; base64 must decode");
    let bytes_2 = engine
        .decode(TRUST_ROOT_2_BASE64)
        .expect("TRUST_ROOT_2_BASE64 is a compile-time constant; base64 must decode");
    [
        PublicKey::deserialize(&bytes_1).expect("trust root 1 must deserialize as Curve25519"),
        PublicKey::deserialize(&bytes_2).expect("trust root 2 must deserialize as Curve25519"),
    ]
});

/// Borrow the two Signal production sealed-sender trust roots. Both must be
/// accepted; a single-root pin would silently drop messages whose chain
/// terminates at the other root.
pub fn production_trust_roots() -> &'static [PublicKey] {
    PRODUCTION_TRUST_ROOTS.as_slice()
}

/// Validate a [`SenderCertificate`] against any of the supplied trust roots
/// at the given `validation_time`. Returns `Ok(())` if validation succeeds
/// against at least one root; returns `Err(SignalProtocolError)` otherwise.
///
/// Delegates to libsignal's
/// `SenderCertificate::validate_with_trust_roots`, which iterates roots in
/// constant time via `subtle::Choice` to hide which root matched. Logs at
/// `debug` on success and `warn` on rejection so phone-smoke runs leave a
/// trace either way.
pub fn validate_against_trust_roots(
    cert: &SenderCertificate,
    trust_roots: &[PublicKey],
    validation_time: Timestamp,
) -> Result<(), SignalProtocolError> {
    debug!(
        "validate_against_trust_roots: trust_root_count={} validation_time_ms={}",
        trust_roots.len(),
        validation_time.epoch_millis()
    );

    let trust_root_refs: Vec<&PublicKey> = trust_roots.iter().collect();
    if cert.validate_with_trust_roots(&trust_root_refs, validation_time)? {
        Ok(())
    } else {
        warn!(
            "validate_against_trust_roots: certificate rejected by all {} trust roots",
            trust_roots.len()
        );
        Err(SignalProtocolError::InvalidSealedSenderMessage(
            "sender certificate not signed by any configured trust root, or expired".to_string(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
