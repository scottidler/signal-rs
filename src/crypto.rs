//! Pure-Rust crypto: the ProvisioningCipher port.
//!
//! libsignal-protocol owns the Double Ratchet, sealed sender, prekey bundle
//! crypto, etc. This module fills the one gap libsignal does not cover - the
//! ProvisioningCipher used to decrypt the encrypted ProvisionMessage bytes
//! that arrive over the provisioning WebSocket. Reference:
//! signal-service-android's ProvisioningCipher.java.

pub mod provisioning;

pub use provisioning::{ProvisioningCipherError, ProvisioningKeyPair, decrypt_envelope, proto};
