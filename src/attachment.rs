//! Attachment download: fetch the encrypted blob from Signal's CDN,
//! HMAC-verify, AES-256-CBC decrypt, digest-verify, and write the
//! plaintext to disk.
//!
//! Cipher format (mirrors signal-cli's `AttachmentCipherInputStream`):
//!
//! ```text
//! blob = IV(16) || ciphertext || HMAC-SHA256(32)
//! key  = AES_KEY(32) || HMAC_KEY(32)
//! HMAC-SHA256(HMAC_KEY, IV || ciphertext) == trailing 32 bytes
//! AES-256-CBC(AES_KEY, IV).decrypt(ciphertext) (PKCS#7 padding) -> plaintext
//! SHA-256(blob) == pointer.digest
//! ```
//!
//! CDN URL dispatch (mirrors
//! `SignalServiceMessageReceiver.retrieveAttachment`):
//! - cdn_number == 0 -> `https://cdn.signal.org/attachments/{cdn_id}`
//! - cdn_number == 2 -> `https://cdn2.signal.org/attachments/{cdn_key}`
//! - cdn_number == 3 -> `https://cdn3.signal.org/attachments/{cdn_key}`
//!
//! Anything else returns [`AttachmentError::UnsupportedCdn`].

use std::io::Write;
use std::path::Path;

use aes::Aes256;
use cbc::Decryptor;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, Mac};
use log::{debug, info, warn};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::envelope::AttachmentPointer;

pub mod upload;
pub use upload::{UploadError, upload_attachment_bytes, upload_attachment_from_path};

type Aes256CbcDec = Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const IV_LEN: usize = 16;
const AES_BLOCK_LEN: usize = 16;
const MAC_LEN: usize = 32;
const AES_KEY_LEN: usize = 32;
const HMAC_KEY_LEN: usize = 32;
const ATTACHMENT_KEY_LEN: usize = AES_KEY_LEN + HMAC_KEY_LEN;
/// Smallest legitimate encrypted blob: IV + one AES block + MAC tag.
const MIN_BLOB_LEN: usize = IV_LEN + AES_BLOCK_LEN + MAC_LEN;

#[derive(Error, Debug)]
pub enum AttachmentError {
    #[error("unsupported cdn_number: {0} (expected 0, 2, or 3)")]
    UnsupportedCdn(u32),

    #[error("attachment key has wrong length: expected {expected} bytes, got {actual}")]
    BadKeyLen { expected: usize, actual: usize },

    #[error("encrypted blob is too small ({0} bytes); needs at least IV(16) + 1 block + HMAC(32) = 49")]
    BlobTooSmall(usize),

    #[error("HMAC verification failed; blob ciphertext was tampered with or key is wrong")]
    HmacMismatch,

    #[error("digest verification failed; on-disk blob does not match the pointer's SHA-256 digest")]
    DigestMismatch,

    #[error("AES-CBC decrypt failed: {0}")]
    Decrypt(String),

    #[error("HTTP fetch failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("filesystem write failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Fetch and decrypt the attachment referenced by `pointer`, writing the
/// plaintext bytes to `dest`. Verifies HMAC + digest before any byte
/// reaches `dest` so a partial write of corrupted plaintext is not
/// possible.
pub async fn download_attachment(pointer: &AttachmentPointer, dest: &Path) -> Result<(), AttachmentError> {
    debug!(
        "download_attachment: cdn_number={} cdn_id={} cdn_key={:?} dest={}",
        pointer.cdn_number,
        pointer.cdn_id,
        pointer.cdn_key.as_deref(),
        dest.display()
    );

    if pointer.key.len() != ATTACHMENT_KEY_LEN {
        return Err(AttachmentError::BadKeyLen {
            expected: ATTACHMENT_KEY_LEN,
            actual: pointer.key.len(),
        });
    }

    let url = build_cdn_url(pointer)?;
    let client = crate::net::pinned_http_client()?;
    let blob = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?
        .to_vec();
    info!("download_attachment: fetched {} bytes from {}", blob.len(), url);

    let mut plaintext = verify_and_decrypt(&blob, &pointer.key, &pointer.digest)?;
    debug!(
        "download_attachment: decrypted plaintext_len={} pointer_size={:?}",
        plaintext.len(),
        pointer.size
    );

    // Strip bucket padding: signal-cli (and now our own send path) pad
    // the plaintext up to a privacy-preserving bucket size before
    // encrypting. The pointer carries the unpadded byte count in `size`;
    // trust it when present so dest receives only the real bytes the
    // sender authored, not the trailing zero pad.
    if let Some(size) = pointer.size {
        let size = size as usize;
        if size <= plaintext.len() {
            plaintext.truncate(size);
        }
    }

    let mut f = std::fs::File::create(dest)?;
    f.write_all(&plaintext)?;
    Ok(())
}

fn build_cdn_url(pointer: &AttachmentPointer) -> Result<String, AttachmentError> {
    match pointer.cdn_number {
        0 => Ok(format!("https://cdn.signal.org/attachments/{}", pointer.cdn_id)),
        2 => Ok(format!(
            "https://cdn2.signal.org/attachments/{}",
            pointer.cdn_key.as_deref().unwrap_or("")
        )),
        3 => Ok(format!(
            "https://cdn3.signal.org/attachments/{}",
            pointer.cdn_key.as_deref().unwrap_or("")
        )),
        other => Err(AttachmentError::UnsupportedCdn(other)),
    }
}

/// Pure helper that verifies HMAC + digest and returns the plaintext.
/// Separated from the network and filesystem path so the cipher logic is
/// unit-testable end-to-end against fixtures.
pub(crate) fn verify_and_decrypt(
    blob: &[u8],
    attachment_key: &[u8],
    expected_digest: &[u8],
) -> Result<Vec<u8>, AttachmentError> {
    debug!(
        "verify_and_decrypt: blob_len={} key_len={} expected_digest_len={}",
        blob.len(),
        attachment_key.len(),
        expected_digest.len()
    );

    if attachment_key.len() != ATTACHMENT_KEY_LEN {
        return Err(AttachmentError::BadKeyLen {
            expected: ATTACHMENT_KEY_LEN,
            actual: attachment_key.len(),
        });
    }
    if blob.len() < MIN_BLOB_LEN {
        return Err(AttachmentError::BlobTooSmall(blob.len()));
    }

    let aes_key = &attachment_key[..AES_KEY_LEN];
    let hmac_key = &attachment_key[AES_KEY_LEN..];

    let (signed_part, trailing_mac) = blob.split_at(blob.len() - MAC_LEN);

    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(hmac_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(signed_part);
    let computed = mac.finalize().into_bytes();
    if computed.as_slice().ct_eq(trailing_mac).unwrap_u8() == 0 {
        warn!("verify_and_decrypt: HMAC mismatch on attachment blob");
        return Err(AttachmentError::HmacMismatch);
    }

    if !expected_digest.is_empty() {
        let blob_sha256 = Sha256::digest(blob);
        if blob_sha256.as_slice().ct_eq(expected_digest).unwrap_u8() == 0 {
            warn!("verify_and_decrypt: SHA-256 digest mismatch on attachment blob");
            return Err(AttachmentError::DigestMismatch);
        }
    }

    let iv = &signed_part[..IV_LEN];
    let ciphertext = &signed_part[IV_LEN..];

    let cipher = Aes256CbcDec::new_from_slices(aes_key, iv).map_err(|e| AttachmentError::Decrypt(e.to_string()))?;
    let mut buf = ciphertext.to_vec();
    let plaintext = cipher
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|e| AttachmentError::Decrypt(e.to_string()))?
        .to_vec();
    Ok(plaintext)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
