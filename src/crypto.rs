//! Pure-Rust crypto: the ProvisioningCipher port.
//!
//! libsignal-protocol owns the Double Ratchet, sealed sender, prekey bundle
//! crypto, etc. This module fills the one gap libsignal does not cover - the
//! ProvisioningCipher used to decrypt the encrypted ProvisionMessage bytes
//! that arrive over the provisioning WebSocket. Reference:
//! signal-service-android's ProvisioningCipher.java.

pub mod prekeys;
pub mod provisioning;

pub use prekeys::{
    GeneratedBatch, IdentityKind, PrekeyError, generate_batch, generate_upload_persist, persist_batch, upload_batch,
};
pub use provisioning::{ProvisioningCipherError, ProvisioningKeyPair, decrypt_envelope, proto};
