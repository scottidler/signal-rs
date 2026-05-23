//! Multi-root validation tests. The concern this phase exists to address
//! is that signal-cli configures TWO production trust roots concurrently
//! (`UNIDENTIFIED_SENDER_TRUST_ROOT` and `UNIDENTIFIED_SENDER_TRUST_ROOT2`
//! in LiveConfig.java) and a single-root pin would silently drop every
//! sealed-sender message whose certificate chain terminates at the OTHER
//! root. These tests pin the multi-root acceptance directly at the
//! `validate_against_trust_roots` boundary; the process_envelope-level
//! wiring is covered out-of-band by Phase 10's manual smoke (real peer
//! 1:1 message, sealed-sender envelope, must appear on stdout).
//!
//! The test pattern mirrors libsignal-protocol's own
//! `rust/protocol/tests/sealed_sender.rs:191-208` for fixture
//! construction.

use super::*;

use libsignal_protocol::{DeviceId, KeyPair, SenderCertificate, ServerCertificate, Timestamp};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const SENDER_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";

fn build_sender_cert(rng: &mut ChaCha20Rng, trust_root: &KeyPair, expiration_ms: u64) -> SenderCertificate {
    let server_key = KeyPair::generate(rng);
    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, rng).expect("server cert constructs");
    let sender_key = KeyPair::generate(rng);
    let device_id = DeviceId::new(1).unwrap();
    SenderCertificate::new(
        SENDER_UUID.to_string(),
        None,
        sender_key.public_key,
        device_id,
        Timestamp::from_epoch_millis(expiration_ms),
        server_cert,
        &server_key.private_key,
        rng,
    )
    .expect("sender cert constructs")
}

#[test]
fn validates_cert_signed_by_root_one_against_both_roots_in_order() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xA1A1);
    let root_a = KeyPair::generate(&mut rng);
    let root_b = KeyPair::generate(&mut rng);

    let cert_a = build_sender_cert(&mut rng, &root_a, 2_000_000_000_000);
    let trust_roots = [root_a.public_key, root_b.public_key];

    let now = Timestamp::from_epoch_millis(1_700_000_000_000);
    validate_against_trust_roots(&cert_a, &trust_roots, now).expect("cert_a must validate against [a, b]");
}

#[test]
fn validates_cert_signed_by_root_two_against_both_roots_in_order() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xB2B2);
    let root_a = KeyPair::generate(&mut rng);
    let root_b = KeyPair::generate(&mut rng);

    let cert_b = build_sender_cert(&mut rng, &root_b, 2_000_000_000_000);
    let trust_roots = [root_a.public_key, root_b.public_key];

    let now = Timestamp::from_epoch_millis(1_700_000_000_000);
    validate_against_trust_roots(&cert_b, &trust_roots, now).expect("cert_b must validate against [a, b]");
}

#[test]
fn validates_cert_signed_by_root_one_when_root_two_is_listed_first() {
    // The concern the design doc raises: a single trust root silently
    // drops messages signed by the OTHER root. The reversed-order check
    // here confirms validation is order-independent (libsignal's
    // validate_with_trust_roots iterates in constant time via
    // subtle::Choice; this test pins that contract).
    let mut rng = ChaCha20Rng::seed_from_u64(0xC3C3);
    let root_a = KeyPair::generate(&mut rng);
    let root_b = KeyPair::generate(&mut rng);

    let cert_a = build_sender_cert(&mut rng, &root_a, 2_000_000_000_000);
    let trust_roots_reversed = [root_b.public_key, root_a.public_key];

    let now = Timestamp::from_epoch_millis(1_700_000_000_000);
    validate_against_trust_roots(&cert_a, &trust_roots_reversed, now)
        .expect("cert_a must validate when root_a is listed second");
}

#[test]
fn validates_cert_signed_by_root_two_when_root_one_is_listed_first() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xD4D4);
    let root_a = KeyPair::generate(&mut rng);
    let root_b = KeyPair::generate(&mut rng);

    let cert_b = build_sender_cert(&mut rng, &root_b, 2_000_000_000_000);
    let trust_roots = [root_a.public_key, root_b.public_key];

    let now = Timestamp::from_epoch_millis(1_700_000_000_000);
    validate_against_trust_roots(&cert_b, &trust_roots, now)
        .expect("cert_b must validate when root_b is listed second");
}

#[test]
fn rejects_cert_signed_by_unrelated_root() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xE5E5);
    let root_a = KeyPair::generate(&mut rng);
    let root_b = KeyPair::generate(&mut rng);
    let unrelated_root = KeyPair::generate(&mut rng);

    let cert_unrelated = build_sender_cert(&mut rng, &unrelated_root, 2_000_000_000_000);
    let trust_roots = [root_a.public_key, root_b.public_key];

    let now = Timestamp::from_epoch_millis(1_700_000_000_000);
    let err = validate_against_trust_roots(&cert_unrelated, &trust_roots, now)
        .expect_err("unrelated-root cert must be rejected");
    assert!(
        matches!(
            err,
            libsignal_protocol::SignalProtocolError::InvalidSealedSenderMessage(_)
        ),
        "expected InvalidSealedSenderMessage, got {err:?}"
    );
}

#[test]
fn rejects_expired_cert_even_when_signed_by_configured_root() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xF6F6);
    let root_a = KeyPair::generate(&mut rng);
    let root_b = KeyPair::generate(&mut rng);

    // Cert expires at t=1_000; we validate at t=2_000.
    let cert_a = build_sender_cert(&mut rng, &root_a, 1_000);
    let trust_roots = [root_a.public_key, root_b.public_key];

    let validation_time = Timestamp::from_epoch_millis(2_000);
    let err = validate_against_trust_roots(&cert_a, &trust_roots, validation_time)
        .expect_err("expired cert must be rejected");
    assert!(
        matches!(
            err,
            libsignal_protocol::SignalProtocolError::InvalidSealedSenderMessage(_)
        ),
        "expected InvalidSealedSenderMessage, got {err:?}"
    );
}

#[test]
fn production_trust_roots_parses_two_distinct_keys() {
    let roots = production_trust_roots();
    assert_eq!(roots.len(), 2, "must expose exactly two production roots");
    assert_ne!(
        roots[0].serialize(),
        roots[1].serialize(),
        "production roots must be distinct"
    );
}
