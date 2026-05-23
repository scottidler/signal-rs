//! Raw-HTTPS API helpers against `chat.signal.org`.
//!
//! The design doc anticipated routing these calls through
//! `libsignal-net-chat`, but at libsignal v0.94.1 the chat API surface only
//! exposes `get_pre_keys` (the consume-bundle side). The upload side
//! (device-completion + keys upload during the secondary-device link flow)
//! is not part of `libsignal-net-chat`'s public surface; signal-cli issues
//! these as raw HTTPS PUTs and we follow that path for v0.1.
//!
//! Wire formats here are inferred from libsignal-net-chat's deserialize
//! side and from signal-cli's request bodies; runtime correctness against
//! the live Signal server is validated by Phase 10's manual smoke test.

use base64::Engine as _;
use http::HeaderValue;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use libsignal_protocol::GenericSignedPreKey;
use log::{debug, info};
use rand::TryRngCore;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::prekeys::{GeneratedBatch, IdentityKind};
use crate::storage::{SqliteStore, Store, StoreError};

/// Production Signal chat server. Staging is `chat.staging.signal.org` and
/// will be parameterized in a follow-up.
const CHAT_BASE_URL: &str = "https://chat.signal.org";

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("storage error: {0}")]
    Storage(#[from] StoreError),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("signal server returned {status}: {body}")]
    Server { status: u16, body: String },

    #[error("missing credential in store: {0}")]
    MissingCredential(&'static str),

    #[error("signal-protocol error: {0}")]
    Signal(#[from] libsignal_protocol::SignalProtocolError),

    #[error("rng error: {0}")]
    Rng(String),

    #[error("tls config error: {0}")]
    TlsConfig(String),
}

/// JSON body for `PUT /v1/devices/link`. Combines the provisioning
/// verification code, the account/device attributes, and BOTH identities'
/// signed + last-resort kyber prekeys into a single atomic PUT. Field
/// names match the canonical Signal-Server `LinkDeviceRequest` record
/// (see `entities/LinkDeviceRequest.java`).
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LinkDeviceRequestBody<'a> {
    verification_code: &'a str,
    account_attributes: LinkAccountAttributes,
    aci_signed_pre_key: SignedPreKeyJson,
    pni_signed_pre_key: SignedPreKeyJson,
    aci_pq_last_resort_pre_key: KyberPreKeyJson,
    pni_pq_last_resort_pre_key: KyberPreKeyJson,
}

/// Nested `accountAttributes` field inside [`LinkDeviceRequestBody`].
/// Matches Signal-Server's `entities/DeviceAttributes` JSON shape:
/// `fetchesMessages` toggles the chat-WebSocket fetch path (true for our
/// desktop-style secondary), `registrationId`/`pniRegistrationId` are the
/// libsignal registration IDs we generated and persisted in Phase 5,
/// `capabilities` MUST be non-null (the controller rejects null with 422)
/// and MUST deserialize as a `Map<String, Boolean>` per
/// `DeviceCapabilityAdapter.Deserializer`; we send an empty object `{}`.
/// `name` is intentionally omitted: the field is `byte[]` server-side
/// (encrypted device name); we leave it empty for v0.1 since the
/// linked-devices UI label is cosmetic and Signal's validator accepts a
/// missing/null name field.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LinkAccountAttributes {
    fetches_messages: bool,
    registration_id: u32,
    pni_registration_id: u32,
    capabilities: std::collections::HashMap<String, bool>,
}

/// JSON response shape from `PUT /v1/devices/link`. Matches
/// Signal-Server's `entities/LinkDeviceResponse`.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LinkDeviceResponse {
    uuid: String,
    pni: String,
    device_id: u32,
}

/// JSON body for `PUT /v2/keys/?identity=aci|pni`. Wire-format mirrors what
/// `libsignal-net-chat::ws::keys`'s deserialize side parses on the GET path,
/// cross-checked against `libsignal-net-chat::ws::registration::request`'s
/// camelCase field names (`identityKey`, `signedPreKey`,
/// `pqLastResortPreKey`).
///
/// Fields that may legitimately be absent for a given upload (e.g. no
/// new one-time pq prekeys) are `Option`/`skip_if_empty` rather than
/// empty-array-emitting; Signal's server rejects empty arrays for slots
/// it expects to be omitted.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PreKeyUploadBody {
    identity_key: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pre_keys: Vec<PreKeyJson>,
    signed_pre_key: SignedPreKeyJson,
    /// One-time post-quantum prekeys. v0.1 generates only the
    /// last-resort PQ key, so this is normally empty and omitted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pq_pre_keys: Vec<KyberPreKeyJson>,
    pq_last_resort_pre_key: KyberPreKeyJson,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PreKeyJson {
    key_id: u32,
    public_key: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SignedPreKeyJson {
    key_id: u32,
    public_key: String,
    signature: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct KyberPreKeyJson {
    key_id: u32,
    public_key: String,
    signature: String,
}

/// Pre-generated prekey material for one identity (ACI or PNI). Carries
/// the signed prekey + last-resort kyber prekey records produced by
/// [`crate::crypto::prekeys::generate_batch`]; the caller passes both
/// identities' bundles into [`link_device`] for the combined PUT body.
pub struct LinkPreKeys<'a> {
    pub signed_record: &'a libsignal_protocol::SignedPreKeyRecord,
    pub kyber_record: &'a libsignal_protocol::KyberPreKeyRecord,
    pub signed_id: u32,
    pub kyber_id: u32,
}

/// Complete the secondary-device link via Signal's combined link PUT.
/// Mints a fresh password, builds a `LinkDeviceRequest` body that carries
/// device attributes plus the ACI and PNI signed+kyber-last-resort
/// prekeys, PUTs to `/v1/devices/link` with HTTP Basic auth (password
/// becomes the device password), stores the server-assigned `device_id`
/// and the minted password.
///
/// The prekeys MUST already be generated and signed by the caller (see
/// [`crate::crypto::prekeys::generate_batch`]); this function does NOT
/// touch the prekey lifecycle directly. Caller is responsible for
/// persisting the full batches locally after this succeeds.
///
/// Returns the server-assigned `device_id`.
pub async fn link_device(
    store: &SqliteStore,
    provisioning_code: &str,
    device_name: &str,
    number: &str,
    aci_registration_id: u32,
    pni_registration_id: u32,
    aci_prekeys: LinkPreKeys<'_>,
    pni_prekeys: LinkPreKeys<'_>,
) -> Result<u32, ApiError> {
    debug!(
        "link_device: number={} aci_reg_id={} pni_reg_id={} device_name={} aci_signed_id={} aci_kyber_id={} pni_signed_id={} pni_kyber_id={}",
        number,
        aci_registration_id,
        pni_registration_id,
        device_name,
        aci_prekeys.signed_id,
        aci_prekeys.kyber_id,
        pni_prekeys.signed_id,
        pni_prekeys.kyber_id,
    );

    let password = mint_password()?;
    let body = LinkDeviceRequestBody {
        verification_code: provisioning_code,
        account_attributes: LinkAccountAttributes {
            fetches_messages: true,
            registration_id: aci_registration_id,
            pni_registration_id,
            // `spqr` (SPARSE_POST_QUANTUM_RATCHET) has
            // `requireForNewDevices=true` AND `preventDowngrade=true` on
            // Signal-Server's DeviceCapability enum — new linked devices
            // are rejected with 409 if missing. We advertise it to clear
            // the check; libsignal-protocol's session machinery handles
            // SPQR transparently when peers initiate sessions that use it.
            capabilities: [("spqr".to_string(), true)].into_iter().collect(),
        },
        aci_signed_pre_key: signed_prekey_json(&aci_prekeys)?,
        pni_signed_pre_key: signed_prekey_json(&pni_prekeys)?,
        aci_pq_last_resort_pre_key: kyber_prekey_json(&aci_prekeys)?,
        pni_pq_last_resort_pre_key: kyber_prekey_json(&pni_prekeys)?,
    };

    let url = format!("{CHAT_BASE_URL}/v1/devices/link");
    let auth_header = basic_auth_header(number, &password);

    let client = http_client()?;
    let resp = client
        .put(&url)
        .header(AUTHORIZATION, auth_header)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::Server {
            status: status.as_u16(),
            body,
        });
    }

    let parsed: LinkDeviceResponse = resp.json().await?;
    let device_id = parsed.device_id;
    debug!(
        "link_device: server returned uuid={} pni={} device_id={}",
        parsed.uuid, parsed.pni, device_id
    );

    store.set_password(&password).await?;
    store.set_device_id(device_id).await?;

    info!("link_device: device_id={} assigned", device_id);
    Ok(device_id)
}

/// Extract the JSON form of a signed prekey from its `SignedPreKeyRecord`.
/// libsignal's `EC` public key serializes to 33 bytes (type byte 0x05 +
/// 32 bytes raw); the signature is 64 bytes Ed25519. Both are
/// base64-encoded for the JSON wire.
fn signed_prekey_json(p: &LinkPreKeys<'_>) -> Result<SignedPreKeyJson, ApiError> {
    let kp = p.signed_record.key_pair()?;
    Ok(SignedPreKeyJson {
        key_id: p.signed_id,
        public_key: b64(kp.public_key.serialize().as_ref()),
        signature: b64(p.signed_record.signature()?.as_ref()),
    })
}

/// Extract the JSON form of a kyber last-resort prekey from its
/// `KyberPreKeyRecord`. The Kyber1024 public key serializes to ~1568
/// bytes; the signature is 64 bytes Ed25519. Both base64-encoded.
fn kyber_prekey_json(p: &LinkPreKeys<'_>) -> Result<KyberPreKeyJson, ApiError> {
    let kp = p.kyber_record.key_pair()?;
    Ok(KyberPreKeyJson {
        key_id: p.kyber_id,
        public_key: b64(&kp.public_key.serialize()),
        signature: b64(p.kyber_record.signature()?.as_ref()),
    })
}

/// Pre-fetched credentials needed for the keys-upload PUT. Bundled by
/// [`load_upload_credentials`] BEFORE the caller opens any transaction
/// so the HTTP upload path never reaches back into the connection pool
/// (which the transaction holds for its lifetime).
pub struct UploadCredentials {
    pub identity_keypair: libsignal_protocol::IdentityKeyPair,
    pub service_id: String,
    pub device_id: u32,
    pub password: String,
}

/// Read everything `upload_keys_for_identity` needs from the store
/// once, before any transaction is opened. Decouples the upload path
/// from the connection pool so the transactional persist+upload flow
/// cannot deadlock against itself.
pub async fn load_upload_credentials(
    store: &SqliteStore,
    identity_kind: IdentityKind,
) -> Result<UploadCredentials, ApiError> {
    debug!("load_upload_credentials: identity_kind={:?}", identity_kind);
    let identity = store.load_identity().await?;
    let password = store
        .get_password()
        .await?
        .ok_or(ApiError::MissingCredential("password"))?;

    // Signing identity depends on the kind (ACI prekeys signed by ACI
    // identity, PNI prekeys signed by PNI identity), but HTTP Basic auth
    // always uses the ACI-derived service id. The PNI is the URL
    // discriminator (?identity=pni), not an independent auth principal —
    // Signal's chat server rejects PNI-as-username with 401 because the
    // device credentials are bound to the ACI account.
    let identity_keypair = match identity_kind {
        IdentityKind::Aci => identity.identity_keypair,
        IdentityKind::Pni => store
            .get_pni_identity_keypair()
            .await?
            .ok_or(ApiError::MissingCredential("pni_identity_keypair"))?,
    };
    let service_id = store.get_aci().await?.ok_or(ApiError::MissingCredential("aci"))?;

    Ok(UploadCredentials {
        identity_keypair,
        service_id,
        device_id: identity.device_id,
        password,
    })
}

/// Server-authoritative prekey count for one identity. Returned by
/// [`get_available_prekey_count`]; mirrors signal-cli's
/// `OneTimePreKeyCounts(ec, kyber)` shape.
#[derive(Debug, Clone, Copy)]
pub struct OneTimePreKeyCounts {
    pub ec: u32,
    pub pq: u32,
}

/// JSON response shape for `GET /v2/keys/?identity={kind}`. Signal-Server
/// returns `{"count": N, "pqCount": M}`. Field names verified against
/// signal-cli's `OneTimePreKeyCounts` deserialize path.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PreKeyCountResponse {
    count: u32,
    #[serde(default)]
    pq_count: u32,
}

/// Read the server's authoritative one-time-prekey count for the given
/// identity. The replenishment watermark in Phase 8 should compare
/// against this value, not the local SQLite row count - peers consume
/// prekeys on the server side, and the local store has no way to
/// observe that consumption until the resulting message arrives.
pub async fn get_available_prekey_count(
    creds: &UploadCredentials,
    identity_kind: IdentityKind,
) -> Result<OneTimePreKeyCounts, ApiError> {
    let url = format!("{CHAT_BASE_URL}/v2/keys/?identity={}", identity_kind.as_query_param());
    let user = format!("{}.{}", creds.service_id, creds.device_id);
    let auth_header = basic_auth_header(&user, &creds.password);

    debug!("get_available_prekey_count: identity={:?} url={}", identity_kind, url);

    let client = http_client()?;
    let resp = client.get(&url).header(AUTHORIZATION, auth_header).send().await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::Server {
            status: status.as_u16(),
            body,
        });
    }

    let parsed: PreKeyCountResponse = resp.json().await?;
    Ok(OneTimePreKeyCounts {
        ec: parsed.count,
        pq: parsed.pq_count,
    })
}

/// Upload a generated prekey batch under the given identity (ACI or
/// PNI). Issues `PUT /v2/keys/?identity={kind}` with HTTP Basic auth.
/// **No store access** — takes pre-fetched [`UploadCredentials`] so
/// callers may safely hold a `sqlx::Transaction` while this runs.
pub async fn upload_keys_for_identity(
    creds: &UploadCredentials,
    batch: &GeneratedBatch,
    identity_kind: IdentityKind,
) -> Result<(), ApiError> {
    let body = build_prekey_upload_body(&creds.identity_keypair, batch)?;

    let url = format!("{CHAT_BASE_URL}/v2/keys/?identity={}", identity_kind.as_query_param());
    let user = format!("{}.{}", creds.service_id, creds.device_id);
    let auth_header = basic_auth_header(&user, &creds.password);

    debug!(
        "upload_keys_for_identity: identity={:?} url={} user={}",
        identity_kind, url, user
    );

    let client = http_client()?;
    let resp = client
        .put(&url)
        .header(AUTHORIZATION, auth_header)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(ApiError::Server {
            status: status.as_u16(),
            body: body_text,
        });
    }

    info!("upload_keys_for_identity: status={}", status);
    Ok(())
}

/// Build the JSON body for a keys upload directly from the in-memory
/// `GeneratedBatch`. Reads ZERO from the store - load-bearing for the
/// transactional persist+upload flow, where the prekey rows are still
/// inside an in-flight `sqlx::Transaction` and not visible to a
/// separate pool checkout.
fn build_prekey_upload_body(
    identity_keypair: &libsignal_protocol::IdentityKeyPair,
    batch: &GeneratedBatch,
) -> Result<PreKeyUploadBody, ApiError> {
    debug!(
        "build_prekey_upload_body: one_time_prekeys={} signed_prekey_id={} kyber_prekey_id={}",
        batch.one_time_records.len(),
        batch.signed_prekey_id,
        batch.kyber_prekey_id
    );
    let identity_key_b64 = b64(identity_keypair.public_key().serialize().as_ref());

    // One-time prekeys: pull the public half straight from each
    // PreKeyRecord in the batch.
    let mut pre_keys = Vec::with_capacity(batch.one_time_records.len());
    for (idx, record) in batch.one_time_records.iter().enumerate() {
        pre_keys.push(PreKeyJson {
            key_id: batch.one_time_prekey_ids[idx],
            public_key: b64(record.key_pair()?.public_key.serialize().as_ref()),
        });
    }

    // Signed prekey
    let signed_kp = batch.signed_record.key_pair()?;
    let signed_pre_key = SignedPreKeyJson {
        key_id: batch.signed_prekey_id,
        public_key: b64(signed_kp.public_key.serialize().as_ref()),
        signature: b64(batch.signed_record.signature()?.as_ref()),
    };

    // Kyber last-resort prekey
    let kyber_kp = batch.kyber_record.key_pair()?;
    let pq_last_resort = KyberPreKeyJson {
        key_id: batch.kyber_prekey_id,
        public_key: b64(&kyber_kp.public_key.serialize()),
        signature: b64(batch.kyber_record.signature()?.as_ref()),
    };

    Ok(PreKeyUploadBody {
        identity_key: identity_key_b64,
        pre_keys,
        signed_pre_key,
        pq_pre_keys: Vec::new(),
        pq_last_resort_pre_key: pq_last_resort,
    })
}

/// Mint a random 24-byte password, base64-encoded. Matches signal-cli's
/// link-time password length.
fn mint_password() -> Result<String, ApiError> {
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| ApiError::Rng(format!("OsRng: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes))
}

/// Build an HTTP Basic auth header value: `Basic base64(user:pass)`.
fn basic_auth_header(user: &str, pass: &str) -> HeaderValue {
    let raw = format!("{user}:{pass}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    HeaderValue::from_str(&format!("Basic {encoded}")).expect("base64 is header-safe")
}

/// Base64-encode bytes for JSON body fields. Signal uses padded standard
/// base64 in request bodies.
fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Signal's self-signed root CA. chat.signal.org presents a cert chained
/// to this root, not to any public CA, so we must pin it explicitly.
/// Sourced from libsignal `rust/net/res/signal.cer` (DER-encoded).
const SIGNAL_ROOT_CERT_DER: &[u8] = include_bytes!("../res/signal.cer");

/// Construct a fresh reqwest client pinned to Signal's root CA. System
/// trust roots are excluded; only `SIGNAL_ROOT_CERT_DER` is accepted.
/// We keep this per-call rather than pooling for v0.1; the link flow
/// issues only two requests and the keys upload one more, so
/// connection-reuse pressure is low.
fn http_client() -> Result<HttpClient, ApiError> {
    debug!("http_client: building reqwest client with Signal-pinned root CA");
    let cert = reqwest::Certificate::from_der(SIGNAL_ROOT_CERT_DER)
        .map_err(|e| ApiError::TlsConfig(format!("parse signal root cert: {e}")))?;
    Ok(HttpClient::builder()
        .user_agent(concat!("signal-rs/", env!("CARGO_PKG_VERSION")))
        .use_rustls_tls()
        .tls_certs_only([cert])
        .build()?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn mint_password_returns_unique_base64() {
        let a = mint_password().unwrap();
        let b = mint_password().unwrap();
        assert_ne!(a, b, "two mints must differ");
        // 24 bytes -> 32 base64-no-pad chars; we expect either 32 or 32 chars
        // depending on the encoder; STANDARD_NO_PAD on 24 bytes is 32 chars.
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn basic_auth_header_encodes_user_and_password() {
        let h = basic_auth_header("user@example", "p@ss w0rd!");
        let s = h.to_str().unwrap();
        assert!(s.starts_with("Basic "));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(s.trim_start_matches("Basic "))
            .unwrap();
        assert_eq!(decoded, b"user@example:p@ss w0rd!");
    }

    #[test]
    fn b64_round_trip() {
        let raw = b"hello signal";
        let encoded = b64(raw);
        let decoded = base64::engine::general_purpose::STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded, raw);
    }

    #[tokio::test]
    async fn prekey_upload_body_from_real_records_serializes_correctly() {
        // Architect (c): build a PreKeyUploadBody from real
        // PreKeyRecord / SignedPreKeyRecord / KyberPreKeyRecord bytes
        // (not synthetic "AAEC" strings) and snapshot the field
        // structure of the resulting JSON. Catches encoding-layer bugs
        // (b64 padding, libsignal serialize() format changes) that the
        // synthetic test below cannot see.
        use crate::SqliteStore;
        use crate::crypto::prekeys::generate_batch;
        use libsignal_protocol::IdentityKeyPair;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let store = SqliteStore::open_in_memory().await.unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0DE);
        let identity = IdentityKeyPair::generate(&mut rng);
        store
            .save_identity_bundle(&identity, 12345, "+15555550100", 1, crate::storage::LinkStatus::Linked)
            .await
            .unwrap();
        // generate_batch produces records in memory; build_prekey_upload_body
        // now reads them directly from the batch without touching the
        // store, so no persist is needed for the test.
        let batch = generate_batch(&mut rng, &store, IdentityKind::Aci, 1).await.unwrap();
        let body = build_prekey_upload_body(&identity, &batch).unwrap();

        let json: serde_json::Value = serde_json::to_value(&body).unwrap();
        let obj = json.as_object().expect("body is a JSON object");

        // Required fields - presence + camelCase casing
        assert!(obj.contains_key("identityKey"), "identityKey present");
        assert!(obj.contains_key("preKeys"), "preKeys present");
        assert!(obj.contains_key("signedPreKey"), "signedPreKey present");
        assert!(obj.contains_key("pqLastResortPreKey"), "pqLastResortPreKey present");

        // pqPreKeys MUST be omitted when empty (Signal server rejects [])
        assert!(!obj.contains_key("pqPreKeys"), "empty pqPreKeys must be omitted");

        // Snake-case escapes that would indicate a serde rename mistake
        for snake in ["identity_key", "pre_keys", "signed_pre_key", "pq_last_resort_pre_key"] {
            assert!(!obj.contains_key(snake), "snake_case leak: {snake}");
        }

        // preKeys is the right length (PREKEY_BATCH_SIZE = 100)
        let pre_keys = obj["preKeys"].as_array().unwrap();
        assert_eq!(pre_keys.len(), crate::crypto::prekeys::PREKEY_BATCH_SIZE as usize);
        for pk in pre_keys {
            assert!(pk["keyId"].is_u64(), "preKey.keyId is uint");
            let pubkey = pk["publicKey"].as_str().unwrap();
            // libsignal-protocol's PublicKey::serialize() returns 33
            // bytes (1-byte type tag + 32-byte curve point). After
            // standard base64 with padding that's 44 chars.
            assert_eq!(pubkey.len(), 44, "preKey.publicKey b64 length");
        }

        // signedPreKey shape - keyId/publicKey/signature
        let spk = obj["signedPreKey"].as_object().unwrap();
        assert!(spk.contains_key("keyId"));
        assert!(spk.contains_key("publicKey"));
        assert!(spk.contains_key("signature"));

        // pqLastResortPreKey shape - same structure as signedPreKey but
        // a Kyber public key (much larger). Just check the fields are
        // present + signature non-empty.
        let pq = obj["pqLastResortPreKey"].as_object().unwrap();
        assert!(pq.contains_key("keyId"));
        assert!(pq.contains_key("publicKey"));
        assert!(pq.contains_key("signature"));
        assert!(!pq["signature"].as_str().unwrap().is_empty());

        // identityKey is base64(33-byte serialized public key)
        let id_key = obj["identityKey"].as_str().unwrap();
        assert_eq!(id_key.len(), 44, "identityKey b64 length");
    }

    #[test]
    fn prekey_upload_body_serializes_to_expected_camel_case_shape() {
        // Snapshot test: pin the wire shape so any future field rename
        // or casing drift fails CI rather than silently breaking the
        // live upload. Cross-check field names against signal-cli /
        // libsignal's registration request body.
        let body = PreKeyUploadBody {
            identity_key: "AAEC".to_string(),
            pre_keys: vec![
                PreKeyJson {
                    key_id: 1,
                    public_key: "AAAA".to_string(),
                },
                PreKeyJson {
                    key_id: 2,
                    public_key: "BBBB".to_string(),
                },
            ],
            signed_pre_key: SignedPreKeyJson {
                key_id: 101,
                public_key: "CCCC".to_string(),
                signature: "DDDD".to_string(),
            },
            pq_pre_keys: Vec::new(), // empty -> field should be omitted
            pq_last_resort_pre_key: KyberPreKeyJson {
                key_id: 102,
                public_key: "EEEE".to_string(),
                signature: "FFFF".to_string(),
            },
        };
        let json = serde_json::to_string(&body).unwrap();
        let expected = concat!(
            r#"{"identityKey":"AAEC","#,
            r#""preKeys":[{"keyId":1,"publicKey":"AAAA"},{"keyId":2,"publicKey":"BBBB"}],"#,
            r#""signedPreKey":{"keyId":101,"publicKey":"CCCC","signature":"DDDD"},"#,
            r#""pqLastResortPreKey":{"keyId":102,"publicKey":"EEEE","signature":"FFFF"}}"#,
        );
        assert_eq!(json, expected, "wire shape drift detected");
        // Explicitly verify pqPreKeys is omitted (not emitted as []),
        // since Signal's server rejects empty arrays for absent slots.
        assert!(!json.contains("pqPreKeys"), "empty pqPreKeys must be omitted");
    }
}
