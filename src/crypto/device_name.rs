//! Encrypted linked-device name. Byte-for-byte port of Signal-Android's
//! `DeviceNameCipher` (`app/src/main/java/org/thoughtcrime/securesms/
//! registration/secondary/DeviceNameCipher.kt`).
//!
//! Wire format (the bytes returned by [`encrypt_device_name`]) is a
//! protobuf-encoded `DeviceName { ephemeralPublic, syntheticIv, ciphertext }`,
//! base64-encoded once more before going into `accountAttributes.name`
//! on Signal-Server's `/v1/devices/link` JSON body. Server discards
//! any unparseable base64 (`DeviceNameByteArrayAdapter.Deserializer`),
//! so a wrong wire shape silently leaves the phone showing "Unnamed device".
//!
//! Algorithm (encrypt):
//!
//! 1. Generate an ephemeral curve25519 keypair.
//! 2. `master_secret = ECDH(ephemeral.private, aci_identity.public)`
//! 3. `synthetic_iv_key = HMAC-SHA256(master_secret, "auth")`
//!    `synthetic_iv     = HMAC-SHA256(synthetic_iv_key, plaintext)[0..16]`
//! 4. `cipher_key_key   = HMAC-SHA256(master_secret, "cipher")`
//!    `cipher_key       = HMAC-SHA256(cipher_key_key, synthetic_iv)` (32 bytes)
//! 5. `ciphertext = AES-256-CTR(cipher_key, iv = zeros[16])(plaintext)`
//!    Java's `AES/CTR/NoPadding` uses a 128-bit big-endian counter; the
//!    Rust port MUST match (`Ctr128BE<Aes256>`), other counter widths
//!    silently produce wrong bytes.
//! 6. Encode `DeviceName { ephemeralPublic = ephemeral.public.serialize(),
//!    syntheticIv, ciphertext }`. `serialize()` is the 33-byte
//!    type-tagged form (`0x05 || raw32`); the primary's `ECPublicKey`
//!    constructor on the decrypt side expects exactly that.
//!
//! Decrypt verifies `synthetic_iv` matches by recomputing it from the
//! decrypted plaintext, rejecting on mismatch. Without that step a
//! malicious primary could swap the ciphertext for an attacker-chosen
//! one; the synthetic IV is the integrity check.

use aes::Aes256;
use base64::Engine as _;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, KeyInit, Mac};
use libsignal_protocol::{IdentityKeyPair, KeyPair, PublicKey, SignalProtocolError};
use log::{debug, warn};
use prost::Message as _;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

#[allow(clippy::large_enum_variant)]
pub mod proto {
    //! prost-generated `DeviceName { ephemeralPublic, syntheticIv,
    //! ciphertext }` from `src/proto/device_name.proto`.
    include!(concat!(env!("OUT_DIR"), "/signalrs.device_name.rs"));
}

type Aes256Ctr = Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const SYNTHETIC_IV_LEN: usize = 16;
const CIPHER_IV_LEN: usize = 16;

#[derive(Error, Debug)]
pub enum DeviceNameError {
    #[error("libsignal error: {0}")]
    Signal(#[from] SignalProtocolError),

    #[error("AES-CTR init failed: bad key/iv length")]
    AesInit,

    #[error("HMAC init failed: bad key length")]
    HmacInit,

    #[error("DeviceName protobuf decode failed: {0}")]
    ProtoDecode(#[from] prost::DecodeError),

    #[error("encrypted-name base64 decode failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("DeviceName is missing required field: {0}")]
    MissingField(&'static str),

    #[error("synthetic IV mismatch: computed IV does not match the one in the ciphertext")]
    SyntheticIvMismatch,
}

/// Encrypt a linked-device name with the ACI identity keypair. Output is
/// the base64-encoded `DeviceName` protobuf, ready to drop into
/// `accountAttributes.name`. Plaintext is UTF-8; Java treats it the same.
pub fn encrypt_device_name(plaintext: &str, identity: &IdentityKeyPair) -> Result<String, DeviceNameError> {
    debug!("encrypt_device_name: plaintext_len={}", plaintext.len());
    let mut rng = rand::rng();
    let ephemeral = KeyPair::generate(&mut rng);
    encrypt_device_name_with(plaintext.as_bytes(), identity, &ephemeral)
}

/// Inner form that takes a caller-provided ephemeral keypair. Exists so
/// the known-answer test can drive the algorithm with a deterministic
/// keypair and assert exact bytes.
pub(crate) fn encrypt_device_name_with(
    plaintext: &[u8],
    identity: &IdentityKeyPair,
    ephemeral: &KeyPair,
) -> Result<String, DeviceNameError> {
    let master_secret = ephemeral
        .private_key
        .calculate_agreement(identity.public_key())
        .map_err(SignalProtocolError::from)?;

    let synthetic_iv = compute_synthetic_iv(&master_secret, plaintext)?;
    let cipher_key = compute_cipher_key(&master_secret, &synthetic_iv)?;

    let mut ciphertext = plaintext.to_vec();
    let iv = [0u8; CIPHER_IV_LEN];
    let mut cipher = Aes256Ctr::new_from_slices(&cipher_key, &iv).map_err(|_| DeviceNameError::AesInit)?;
    cipher.apply_keystream(&mut ciphertext);

    let msg = proto::DeviceName {
        ephemeral_public: Some(ephemeral.public_key.serialize().to_vec()),
        synthetic_iv: Some(synthetic_iv.to_vec()),
        ciphertext: Some(ciphertext),
    };
    let encoded = msg.encode_to_vec();
    Ok(base64::engine::general_purpose::STANDARD.encode(encoded))
}

/// Decrypt a `DeviceName` produced by [`encrypt_device_name`] (or by
/// signal-cli / Signal-Android). Returns the decoded UTF-8 plaintext.
/// Used by `signal-rs status` to render linked-device names instead of
/// the raw base64 the server hands back.
pub fn decrypt_device_name(encrypted_b64: &str, identity: &IdentityKeyPair) -> Result<String, DeviceNameError> {
    debug!("decrypt_device_name: encrypted_b64_len={}", encrypted_b64.len());
    let encoded = base64::engine::general_purpose::STANDARD.decode(encrypted_b64)?;
    let msg = proto::DeviceName::decode(&*encoded)?;

    let ephemeral_pub_bytes = msg
        .ephemeral_public
        .as_deref()
        .ok_or(DeviceNameError::MissingField("ephemeralPublic"))?;
    let synthetic_iv = msg
        .synthetic_iv
        .as_deref()
        .ok_or(DeviceNameError::MissingField("syntheticIv"))?;
    let ciphertext = msg
        .ciphertext
        .as_deref()
        .ok_or(DeviceNameError::MissingField("ciphertext"))?;

    let ephemeral_pub = PublicKey::deserialize(ephemeral_pub_bytes).map_err(SignalProtocolError::from)?;
    let master_secret = identity
        .private_key()
        .calculate_agreement(&ephemeral_pub)
        .map_err(SignalProtocolError::from)?;

    let cipher_key = compute_cipher_key(&master_secret, synthetic_iv)?;

    let mut plaintext = ciphertext.to_vec();
    let iv = [0u8; CIPHER_IV_LEN];
    let mut cipher = Aes256Ctr::new_from_slices(&cipher_key, &iv).map_err(|_| DeviceNameError::AesInit)?;
    cipher.apply_keystream(&mut plaintext);

    // Integrity check: synthetic IV must equal HMAC(HMAC(secret, "auth"),
    // plaintext)[0..16]. Mismatch means a primary swapped ciphertext for
    // something it picked; refuse to surface attacker-chosen bytes as a
    // legitimate device name.
    let computed = compute_synthetic_iv(&master_secret, &plaintext)?;
    if computed.ct_eq(synthetic_iv).unwrap_u8() != 1 {
        warn!("decrypt_device_name: synthetic IV mismatch; rejecting");
        return Err(DeviceNameError::SyntheticIvMismatch);
    }

    Ok(String::from_utf8_lossy(&plaintext).into_owned())
}

fn compute_synthetic_iv(master_secret: &[u8], plaintext: &[u8]) -> Result<[u8; SYNTHETIC_IV_LEN], DeviceNameError> {
    let synthetic_iv_key = hmac(master_secret, b"auth")?;
    let full = hmac(&synthetic_iv_key, plaintext)?;
    let mut out = [0u8; SYNTHETIC_IV_LEN];
    out.copy_from_slice(&full[..SYNTHETIC_IV_LEN]);
    Ok(out)
}

fn compute_cipher_key(master_secret: &[u8], synthetic_iv: &[u8]) -> Result<[u8; 32], DeviceNameError> {
    let cipher_key_key = hmac(master_secret, b"cipher")?;
    hmac(&cipher_key_key, synthetic_iv)
}

fn hmac(key: &[u8], data: &[u8]) -> Result<[u8; 32], DeviceNameError> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).map_err(|_| DeviceNameError::HmacInit)?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
