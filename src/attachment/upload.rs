//! Attachment upload: bucket-pad plaintext, AES-256-CBC + HMAC-SHA256
//! encrypt, fetch a signed upload form from chat-server, PUT/PATCH the
//! ciphertext blob to the CDN, return a populated [`AttachmentPointer`]
//! ready to embed in an outbound DataMessage.
//!
//! Cipher format is the mirror image of [`crate::attachment::verify_and_decrypt`]:
//!
//! ```text
//! padded_plaintext = plaintext || 0x00 * (bucket_size - plaintext.len())
//! ciphertext       = AES-256-CBC(AES_KEY, IV).encrypt(padded_plaintext)  // PKCS#7
//! blob             = IV(16) || ciphertext || HMAC-SHA256(HMAC_KEY, IV || ciphertext)
//! key (out)        = AES_KEY(32) || HMAC_KEY(32)
//! digest (out)     = SHA-256(blob)
//! size (out)       = plaintext.len()  // unpadded
//! ```
//!
//! Bucket padding mirrors signal-cli's `PaddingInputStream.getPaddedSize`:
//! the smallest size is 541 bytes, and sizes above grow on the
//! `ceil(1.05^ceil(log_1.05(n)))` curve. This is the privacy-preserving
//! pad so a passive observer of CDN traffic cannot learn the exact
//! plaintext byte-count from the ciphertext length.
//!
//! CDN dispatch mirrors `AttachmentControllerV4`:
//! - cdn=2 → GCS resumable upload: POST `signed_upload_url` with the
//!   form headers + `Content-Length: 0`, read the `Location` response
//!   header (the actual resumable session URI), then PUT the bytes.
//! - cdn=3 → TUS upload: POST `signed_upload_url` with form headers +
//!   `Tus-Resumable: 1.0.0`, `Upload-Length: N`, `Content-Length: 0`;
//!   read the `Location` header; PATCH the bytes with
//!   `Upload-Offset: 0`, `Content-Type: application/offset+octet-stream`,
//!   `Tus-Resumable: 1.0.0`.

use std::path::Path;

use aes::Aes256;
use cbc::Encryptor;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, Mac};
use log::{debug, info};
use rand::TryRngCore;
use rand::rngs::OsRng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::envelope::AttachmentPointer;

type Aes256CbcEnc = Encryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const AES_KEY_LEN: usize = 32;
const HMAC_KEY_LEN: usize = 32;
const ATTACHMENT_KEY_LEN: usize = AES_KEY_LEN + HMAC_KEY_LEN;
const IV_LEN: usize = 16;
const MIN_BUCKET_LEN: usize = 541;
const BUCKET_GROWTH: f64 = 1.05;
/// 16 MiB cap on the input plaintext we'll attempt to upload. This is
/// well under Signal-Server's `global.attachments.maxBytes` default and
/// keeps the in-memory ciphertext buffer bounded. Larger files would
/// need a streaming upload path that we don't have today.
const MAX_PLAINTEXT_LEN: usize = 16 * 1024 * 1024;

#[derive(Error, Debug)]
pub enum UploadError {
    #[error("attachment too large: {0} bytes exceeds the {MAX_PLAINTEXT_LEN}-byte cap")]
    TooLarge(usize),

    #[error("attachment file is empty")]
    Empty,

    #[error("filesystem read failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("upload form fetch failed: {0}")]
    Form(String),

    #[error("unsupported cdn_number from form: {0} (expected 2 or 3)")]
    UnsupportedCdn(u32),

    #[error("CDN session-init returned no Location header (cdn={cdn})")]
    MissingLocation { cdn: u32 },

    #[error("CDN session-init failed: HTTP {status} {body}")]
    SessionInit { status: u16, body: String },

    #[error("CDN bytes-upload failed: HTTP {status} {body}")]
    BytesUpload { status: u16, body: String },

    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid header value from form: {0}")]
    BadHeader(String),
}

/// Pad `plaintext_len` up to Signal's bucket-padded ceiling. Always
/// returns at least [`MIN_BUCKET_LEN`].
///
/// Mirrors signal-android's `PaddingInputStream.getPaddedSize`:
///
/// ```java
/// return Math.max(541, (long) Math.floor(Math.pow(1.05, Math.ceil(Math.log(size) / Math.log(1.05)))));
/// ```
///
/// The outer step is `floor`, not `ceil` — same growth curve, but a
/// `ceil` here puts every signal-rs ciphertext systematically one byte
/// above the canonical bucket and lets a passive observer distinguish
/// our traffic from signal-android/signal-cli's on the CDN. That's the
/// fingerprint we're explicitly trying to avoid by bucket-padding in
/// the first place.
pub(crate) fn bucket_padded_size(plaintext_len: usize) -> usize {
    if plaintext_len <= MIN_BUCKET_LEN {
        return MIN_BUCKET_LEN;
    }
    let log = (plaintext_len as f64).log(BUCKET_GROWTH);
    let bucket = BUCKET_GROWTH.powf(log.ceil()).floor() as usize;
    bucket.max(plaintext_len)
}

/// Build the IV(16) || ciphertext || HMAC(32) wire blob. `padded_plaintext`
/// is the bucket-padded plaintext; `aes_key` + `hmac_key` together form
/// the 64-byte attachment key.
pub(crate) fn encrypt_attachment_blob(
    padded_plaintext: &[u8],
    aes_key: &[u8; AES_KEY_LEN],
    hmac_key: &[u8; HMAC_KEY_LEN],
    iv: &[u8; IV_LEN],
) -> Vec<u8> {
    debug!(
        "encrypt_attachment_blob: padded_plaintext_len={} iv_len={} aes_key_len={} hmac_key_len={}",
        padded_plaintext.len(),
        iv.len(),
        aes_key.len(),
        hmac_key.len()
    );

    let cipher = Aes256CbcEnc::new_from_slices(aes_key, iv)
        .expect("AES-256 + 16-byte IV always accepted by cbc::Encryptor::new_from_slices");

    // PKCS#7 needs room for one full extra block past the plaintext.
    let mut buf = vec![0u8; padded_plaintext.len() + 16];
    buf[..padded_plaintext.len()].copy_from_slice(padded_plaintext);
    let ciphertext = cipher
        .encrypt_padded::<Pkcs7>(&mut buf, padded_plaintext.len())
        .expect("PKCS7 + sufficient buffer never errors on encrypt")
        .to_vec();

    let mut blob = Vec::with_capacity(IV_LEN + ciphertext.len() + 32);
    blob.extend_from_slice(iv);
    blob.extend_from_slice(&ciphertext);

    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(hmac_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&blob);
    let mac_bytes = mac.finalize().into_bytes();
    blob.extend_from_slice(&mac_bytes);

    blob
}

/// Read `path`, encrypt with a freshly generated random key+IV, and
/// upload the ciphertext to Signal's CDN through the upload-form path.
/// Returns the populated [`AttachmentPointer`] that the caller embeds in
/// the outbound DataMessage's `attachments` field.
///
/// `auth_chat` is an authenticated chat surface (constructed via
/// [`libsignal_net_chat::api::Auth`]) used only for the
/// `get_upload_form` request. The actual byte upload is a plain HTTPS
/// PUT/PATCH to the CDN.
pub async fn upload_attachment_from_path<A, T>(
    auth_chat: &A,
    path: &Path,
    content_type: Option<String>,
) -> Result<AttachmentPointer, UploadError>
where
    A: libsignal_net_chat::api::messages::AuthenticatedChatApi<T>,
    T: 'static,
{
    debug!(
        "upload_attachment_from_path: path={} content_type={:?}",
        path.display(),
        content_type
    );
    let bytes = std::fs::read(path)?;
    let file_name = path.file_name().and_then(|s| s.to_str()).map(|s| s.to_string());
    upload_attachment_bytes(auth_chat, &bytes, content_type, file_name).await
}

/// Lower-level variant that takes the raw plaintext bytes already in
/// memory. The high-level [`upload_attachment_from_path`] reads the file
/// then delegates here.
pub async fn upload_attachment_bytes<A, T>(
    auth_chat: &A,
    plaintext: &[u8],
    content_type: Option<String>,
    file_name: Option<String>,
) -> Result<AttachmentPointer, UploadError>
where
    A: libsignal_net_chat::api::messages::AuthenticatedChatApi<T>,
    T: 'static,
{
    debug!(
        "upload_attachment_bytes: plaintext_len={} content_type={:?} file_name={:?}",
        plaintext.len(),
        content_type,
        file_name
    );
    if plaintext.is_empty() {
        return Err(UploadError::Empty);
    }
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(UploadError::TooLarge(plaintext.len()));
    }

    // 1. Generate the 64-byte attachment key and the 16-byte IV.
    let mut key_bytes = [0u8; ATTACHMENT_KEY_LEN];
    OsRng
        .try_fill_bytes(&mut key_bytes)
        .map_err(|e| UploadError::Form(format!("OsRng key: {e}")))?;
    let mut iv = [0u8; IV_LEN];
    OsRng
        .try_fill_bytes(&mut iv)
        .map_err(|e| UploadError::Form(format!("OsRng iv: {e}")))?;

    let mut aes_key = [0u8; AES_KEY_LEN];
    aes_key.copy_from_slice(&key_bytes[..AES_KEY_LEN]);
    let mut hmac_key = [0u8; HMAC_KEY_LEN];
    hmac_key.copy_from_slice(&key_bytes[AES_KEY_LEN..]);

    // 2. Bucket-pad and encrypt.
    let padded_len = bucket_padded_size(plaintext.len());
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(plaintext);
    padded.resize(padded_len, 0u8);
    let blob = encrypt_attachment_blob(&padded, &aes_key, &hmac_key, &iv);
    let digest = Sha256::digest(&blob).to_vec();
    debug!(
        "upload_attachment_bytes: padded_len={} blob_len={} digest_len={}",
        padded_len,
        blob.len(),
        digest.len()
    );

    // 3. Fetch an upload form. Server picks CDN and key.
    let form = auth_chat
        .get_upload_form(blob.len() as u64)
        .await
        .map_err(|e| UploadError::Form(format!("get_upload_form: {e:?}")))?;
    info!(
        "upload_attachment_bytes: form ready cdn={} key_len={} url_len={}",
        form.cdn,
        form.key.len(),
        form.signed_upload_url.len()
    );

    // 4. Push the bytes to the CDN over the protocol the server chose.
    //
    // Asymmetric with `attachment::download_attachment`, which uses
    // `crate::net::pinned_http_client()` (Signal-only trust). Upload
    // cannot pin because cdn=2 posts to a GCS signed URL on
    // `storage.googleapis.com`, which requires public-CA trust. If
    // Signal ever returns an upload URL on a Signal-only host the right
    // move is to switch to `add_root_certificate(signal_cert)` on top
    // of system roots so both targets work.
    let http = reqwest::Client::builder()
        .build()
        .map_err(|e| UploadError::Form(format!("reqwest::Client::builder: {e}")))?;
    let form_headers = form_headers_to_reqwest(&form.headers)?;
    match form.cdn {
        2 => push_to_cdn2_gcs(&http, &form.signed_upload_url, form_headers, &blob).await?,
        3 => push_to_cdn3_tus(&http, &form.signed_upload_url, form_headers, &blob).await?,
        other => return Err(UploadError::UnsupportedCdn(other)),
    }

    // 5. Build the pointer for the outbound DataMessage.
    Ok(AttachmentPointer {
        cdn_id: 0,
        cdn_key: Some(form.key),
        cdn_number: form.cdn,
        content_type,
        size: Some(plaintext.len() as u32),
        digest,
        key: key_bytes.to_vec(),
        file_name,
        caption: None,
        width: None,
        height: None,
        voice_note: false,
        borderless: false,
        gif: false,
        upload_timestamp: Some(now_millis()),
        blurhash: None,
    })
}

fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Convert the form's `Vec<(String, String)>` into a `reqwest::HeaderMap`.
/// Bad header values are surfaced as [`UploadError::BadHeader`] rather
/// than silently dropped, so a server change that adds an exotic value
/// fails loudly during local testing.
fn form_headers_to_reqwest(headers: &[(String, String)]) -> Result<HeaderMap, UploadError> {
    let mut out = HeaderMap::with_capacity(headers.len());
    for (k, v) in headers {
        let name = HeaderName::try_from(k.as_str()).map_err(|e| UploadError::BadHeader(format!("name {k}: {e}")))?;
        let value = HeaderValue::from_str(v).map_err(|e| UploadError::BadHeader(format!("value for {k}: {e}")))?;
        out.insert(name, value);
    }
    Ok(out)
}

/// GCS resumable two-shot: POST to init the session, PUT bytes to the
/// returned session URI.
async fn push_to_cdn2_gcs(
    http: &reqwest::Client,
    signed_upload_url: &str,
    mut headers: HeaderMap,
    blob: &[u8],
) -> Result<(), UploadError> {
    debug!(
        "push_to_cdn2_gcs: signed_upload_url_len={} blob_len={}",
        signed_upload_url.len(),
        blob.len()
    );
    // Session init: POST with the server-provided headers (which include
    // `x-goog-resumable: start`) and Content-Length: 0. GCS responds 201
    // with a `Location` header pointing at the actual session URI.
    headers.insert(reqwest::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    let init = http
        .post(signed_upload_url)
        .headers(headers)
        .body(Vec::new())
        .send()
        .await?;
    let init_status = init.status();
    if !init_status.is_success() {
        let body = init.text().await.unwrap_or_default();
        return Err(UploadError::SessionInit {
            status: init_status.as_u16(),
            body,
        });
    }
    let session_uri = init
        .headers()
        .get(LOCATION)
        .ok_or(UploadError::MissingLocation { cdn: 2 })?
        .to_str()
        .map_err(|e| UploadError::BadHeader(format!("Location: {e}")))?
        .to_string();
    debug!("push_to_cdn2_gcs: session_uri_len={}", session_uri.len());

    // Bytes upload: single PUT to the session URI. Smaller-than-cutover
    // attachments fit in one chunk; we don't bother with multi-chunk
    // resumption because we own the buffer in memory. signal-android
    // sets `Content-Type: application/octet-stream` on the PUT body and
    // GCS resumable validates against the session-init Content-Type, so
    // include it explicitly rather than relying on a server default.
    let put = http
        .put(&session_uri)
        .header(reqwest::header::CONTENT_LENGTH, blob.len())
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(blob.to_vec())
        .send()
        .await?;
    let put_status = put.status();
    if !put_status.is_success() {
        let body = put.text().await.unwrap_or_default();
        return Err(UploadError::BytesUpload {
            status: put_status.as_u16(),
            body,
        });
    }
    info!("push_to_cdn2_gcs: uploaded {} bytes", blob.len());
    Ok(())
}

/// TUS two-shot: POST to create the upload resource, PATCH bytes at
/// offset 0.
async fn push_to_cdn3_tus(
    http: &reqwest::Client,
    signed_upload_url: &str,
    mut headers: HeaderMap,
    blob: &[u8],
) -> Result<(), UploadError> {
    debug!(
        "push_to_cdn3_tus: signed_upload_url_len={} blob_len={}",
        signed_upload_url.len(),
        blob.len()
    );
    headers.insert(
        HeaderName::from_static("tus-resumable"),
        HeaderValue::from_static("1.0.0"),
    );
    headers.insert(
        HeaderName::from_static("upload-length"),
        HeaderValue::from_str(&blob.len().to_string())
            .map_err(|e| UploadError::BadHeader(format!("upload-length: {e}")))?,
    );
    headers.insert(reqwest::header::CONTENT_LENGTH, HeaderValue::from_static("0"));

    let init = http
        .post(signed_upload_url)
        .headers(headers)
        .body(Vec::new())
        .send()
        .await?;
    let init_status = init.status();
    if !init_status.is_success() {
        let body = init.text().await.unwrap_or_default();
        return Err(UploadError::SessionInit {
            status: init_status.as_u16(),
            body,
        });
    }
    let session_uri = init
        .headers()
        .get(LOCATION)
        .ok_or(UploadError::MissingLocation { cdn: 3 })?
        .to_str()
        .map_err(|e| UploadError::BadHeader(format!("Location: {e}")))?
        .to_string();
    debug!("push_to_cdn3_tus: session_uri_len={}", session_uri.len());

    let patch = http
        .patch(&session_uri)
        .header(reqwest::header::CONTENT_LENGTH, blob.len())
        .header("upload-offset", "0")
        .header("content-type", "application/offset+octet-stream")
        .header("tus-resumable", "1.0.0")
        .body(blob.to_vec())
        .send()
        .await?;
    let patch_status = patch.status();
    if !patch_status.is_success() {
        let body = patch.text().await.unwrap_or_default();
        return Err(UploadError::BytesUpload {
            status: patch_status.as_u16(),
            body,
        });
    }
    info!("push_to_cdn3_tus: uploaded {} bytes", blob.len());
    Ok(())
}
