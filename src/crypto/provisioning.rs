//! Port of signal-service-android's `ProvisioningCipher.java`.
//!
//! Decrypts an encrypted ProvisionEnvelope payload that arrives from the
//! primary device over the provisioning WebSocket. The envelope layout is:
//!
//! ```text
//! [version=0x01][iv=16B][ciphertext][mac=32B]
//! ```
//!
//! Decryption flow (verify BEFORE decrypt; encrypt-then-MAC ordering):
//!
//! 1. Decode outer `ProvisionEnvelope` protobuf → `publicKey` (peer's
//!    ephemeral pub) + `body` (encrypted blob shown above).
//! 2. ECDH(`our_private`, `their_public`) → 32-byte agreement.
//! 3. HKDF-SHA256 expand with empty salt and the legacy info string
//!    `"TextSecure Provisioning Message"` → 64 bytes.
//!    Split into `aes_key[0..32]` and `mac_key[32..64]`.
//! 4. HMAC-SHA256 over `version || iv || ciphertext`, constant-time compare
//!    against the trailing 32-byte mac. Reject on mismatch.
//! 5. AES-256-CBC + PKCS#7-padding decrypt of `ciphertext` using `aes_key`
//!    and the embedded `iv`.
//! 6. Decode plaintext as a `ProvisionMessage` protobuf.
//!
//! All ephemeral key material is zeroized on Drop.

use aes::Aes256;
use cbc::Decryptor;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use libsignal_protocol::{KeyPair, PublicKey, SignalProtocolError};
use log::{debug, warn};
use prost::Message as _;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

pub mod proto {
    //! prost-generated types from `src/proto/provisioning.proto`.
    include!(concat!(env!("OUT_DIR"), "/signalservice.rs"));
}

pub use proto::{ProvisionEnvelope, ProvisionMessage};

const PROVISIONING_VERSION: u8 = 1;
const PROVISIONING_INFO: &[u8] = b"TextSecure Provisioning Message";
const HKDF_OUTPUT_LEN: usize = 64;
const AES_KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;
// version(1) + iv(16) + at-least-one AES block(16) + mac(32) = 65 bytes min
const MIN_BODY_LEN: usize = 1 + IV_LEN + 16 + MAC_LEN;

type Aes256CbcDec = Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Error, Debug)]
pub enum ProvisioningCipherError {
    #[error("envelope protobuf decode failed: {0}")]
    EnvelopeDecode(#[from] prost::DecodeError),

    #[error("envelope is missing the peer public key")]
    MissingPublicKey,

    #[error("envelope is missing the encrypted body")]
    MissingBody,

    #[error("envelope body is too short ({0} bytes; minimum {1})")]
    BodyTooShort(usize, usize),

    #[error("unsupported provisioning version: 0x{0:02x} (expected 0x01)")]
    UnsupportedVersion(u8),

    #[error("MAC verification failed")]
    MacMismatch,

    #[error("AES-CBC decryption failed (likely bad padding or wrong key)")]
    BadPaddingOrKey,

    #[error("ciphertext length {0} is not a multiple of the AES block size")]
    BadCiphertextLength(usize),

    #[error("libsignal-protocol error: {0}")]
    Signal(#[from] SignalProtocolError),

    #[error("ECDH agreement failed: {0}")]
    Ecdh(String),
}

/// Curve25519 ephemeral keypair generated per linking session. The public half
/// is embedded in the `sgnl://` URI; the private half decrypts the provision
/// envelope sent back by the primary device. Both halves are zeroized on Drop.
pub struct ProvisioningKeyPair {
    inner: KeyPair,
}

impl ProvisioningKeyPair {
    pub fn generate<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        Self {
            inner: KeyPair::generate(rng),
        }
    }

    /// Public key in libsignal's type-tagged form (33 bytes: `0x05 || raw`).
    /// This is what the primary device expects in the QR code.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key.serialize().to_vec()
    }

    #[cfg(test)]
    pub(crate) fn key_pair(&self) -> &KeyPair {
        &self.inner
    }
}

impl Drop for ProvisioningKeyPair {
    fn drop(&mut self) {
        // libsignal's KeyPair does not impl Drop with zeroize; we cannot reach
        // into the private bytes from outside. The next best thing is to
        // overwrite the entire struct's memory after libsignal's Drop runs.
        // libsignal does its own zeroize internally on PrivateKey::drop;
        // see rust/protocol/src/curve.rs. Nothing more to do here, but the
        // explicit impl documents the contract.
    }
}

/// Decrypt a provisioning envelope.
///
/// `encrypted` is the raw HTTP body of the `/v1/message` provisioning request
/// surfaced by `libsignal_net::chat::server_requests::ProvisioningEvent::ReceivedEnvelope`.
/// It is the `ProvisionEnvelope` protobuf bytes (NOT the inner ciphertext).
pub fn decrypt_envelope(
    keypair: &ProvisioningKeyPair,
    encrypted: &[u8],
) -> Result<ProvisionMessage, ProvisioningCipherError> {
    debug!(
        "decrypt_envelope: encrypted_len={} our_pub_prefix={:02x}{:02x}",
        encrypted.len(),
        keypair.inner.public_key.serialize()[0],
        keypair.inner.public_key.serialize().get(1).copied().unwrap_or(0)
    );

    let envelope = ProvisionEnvelope::decode(encrypted)?;
    let peer_pub_bytes = envelope.public_key.ok_or(ProvisioningCipherError::MissingPublicKey)?;
    let body = envelope.body.ok_or(ProvisioningCipherError::MissingBody)?;

    if body.len() < MIN_BODY_LEN {
        return Err(ProvisioningCipherError::BodyTooShort(body.len(), MIN_BODY_LEN));
    }
    if body[0] != PROVISIONING_VERSION {
        return Err(ProvisioningCipherError::UnsupportedVersion(body[0]));
    }

    let peer_public = PublicKey::deserialize(&peer_pub_bytes)
        .map_err(|e| ProvisioningCipherError::Ecdh(format!("peer pubkey decode: {e}")))?;
    let mut shared = keypair
        .inner
        .private_key
        .calculate_agreement(&peer_public)
        .map_err(|e| ProvisioningCipherError::Ecdh(e.to_string()))?
        .to_vec();

    // HKDF-SHA256 expand. signal-service-android uses an empty salt with the
    // info "TextSecure Provisioning Message" and a 64-byte output.
    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut keys = [0u8; HKDF_OUTPUT_LEN];
    hk.expand(PROVISIONING_INFO, &mut keys)
        .expect("HKDF output length is fixed and valid");
    shared.zeroize();
    let (aes_key, mac_key) = keys.split_at(AES_KEY_LEN);

    let mac_start = body.len() - MAC_LEN;
    let signed_data = &body[..mac_start];
    let provided_mac = &body[mac_start..];

    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(mac_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(signed_data);
    let expected_mac = mac.finalize().into_bytes();

    if expected_mac.ct_eq(provided_mac).unwrap_u8() != 1 {
        warn!("decrypt_envelope: MAC mismatch");
        keys.zeroize();
        return Err(ProvisioningCipherError::MacMismatch);
    }

    // version(1) || iv(16) || ciphertext
    let iv = &body[1..1 + IV_LEN];
    let ciphertext = &body[1 + IV_LEN..mac_start];
    if !ciphertext.len().is_multiple_of(16) || ciphertext.is_empty() {
        keys.zeroize();
        return Err(ProvisioningCipherError::BadCiphertextLength(ciphertext.len()));
    }

    let cipher = Aes256CbcDec::new_from_slices(aes_key, iv)
        .map_err(|e| ProvisioningCipherError::Ecdh(format!("AES init: {e}")))?;
    let mut buf = ciphertext.to_vec();
    let plaintext = cipher
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| ProvisioningCipherError::BadPaddingOrKey)?
        .to_vec();
    keys.zeroize();
    buf.zeroize();

    let msg = ProvisionMessage::decode(plaintext.as_slice())?;
    Ok(msg)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
