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

use crate::crypto::prekeys::GeneratedBatch;
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
}

/// JSON body for `PUT /v1/devices/{verification_code}`. Signal's account
/// attributes for a new secondary device. Field names match Signal's
/// canonical server API.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct DeviceAttributes<'a> {
    name: &'a str,
    fetches_messages: bool,
    registration_id: u32,
    pni_registration_id: u32,
    capabilities: Capabilities,
    supports_sms: bool,
}

#[derive(Serialize, Debug, Default)]
struct Capabilities {
    // Empty for v0.1; future versions can advertise gv2/storage/etc. as
    // libsignal exposes them. Signal accepts a missing or empty object.
}

/// JSON response shape from `PUT /v1/devices/{verification_code}`.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct DeviceCompletionResponse {
    device_id: u32,
    // `uuid` and `pni` echo what the primary sent; we already stored those
    // from the ProvisionMessage so we ignore them on the response.
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

/// Complete the secondary-device registration after the
/// ProvisioningCipher decrypt step. Mints a password, PUTs the device
/// attributes to `/v1/devices/{provisioning_code}` with HTTP Basic auth,
/// stores the response's `device_id` and the minted password.
///
/// Returns the server-assigned `device_id`.
pub async fn complete_device_registration(
    store: &SqliteStore,
    provisioning_code: &str,
    device_name: &str,
    number: &str,
    registration_id: u32,
) -> Result<u32, ApiError> {
    debug!(
        "complete_device_registration: number={} registration_id={} device_name={}",
        number, registration_id, device_name
    );

    let password = mint_password()?;
    let attrs = DeviceAttributes {
        name: device_name,
        fetches_messages: true,
        registration_id,
        // For v0.1 we reuse `registration_id` as the PNI registration id;
        // Signal's server accepts independent PNI id but signal-cli passes
        // the same value for both on link.
        pni_registration_id: registration_id,
        capabilities: Capabilities::default(),
        supports_sms: false,
    };

    let url = format!("{CHAT_BASE_URL}/v1/devices/{provisioning_code}");
    let auth_header = basic_auth_header(number, &password);

    let client = http_client()?;
    let resp = client
        .put(&url)
        .header(AUTHORIZATION, auth_header)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .json(&attrs)
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

    let parsed: DeviceCompletionResponse = resp.json().await?;
    let device_id = parsed.device_id;

    // Persist credentials so subsequent calls (keys upload, send, receive)
    // can pick them up.
    store.set_password(&password).await?;
    store.set_device_id(device_id).await?;

    info!("complete_device_registration: device_id={} assigned", device_id);
    Ok(device_id)
}

/// Upload a generated prekey batch under the ACI identity. Issues
/// `PUT /v2/keys/?identity=aci` with HTTP Basic auth using
/// `aci.device_id:password`. The body encodes the identity public key and
/// all three prekey kinds (one-time, signed, kyber).
pub async fn upload_keys_for_aci(store: &SqliteStore, batch: &GeneratedBatch) -> Result<(), ApiError> {
    let identity = store.load_identity().await?;
    let aci = store.get_aci().await?.ok_or(ApiError::MissingCredential("aci"))?;
    let password = store
        .get_password()
        .await?
        .ok_or(ApiError::MissingCredential("password"))?;

    let body = build_prekey_upload_body(store, &identity.identity_keypair, batch).await?;

    let url = format!("{CHAT_BASE_URL}/v2/keys/?identity=aci");
    let user = format!("{aci}.{}", identity.device_id);
    let auth_header = basic_auth_header(&user, &password);

    debug!("upload_keys_for_aci: url={} user={}", url, user);

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

    info!("upload_keys_for_aci: status={}", status);
    Ok(())
}

/// Build the JSON body for a keys upload from a `GeneratedBatch` plus the
/// identity keypair the batch was signed with. The store is consulted to
/// recover the persisted public keys + signatures by id (the batch carries
/// only ids).
async fn build_prekey_upload_body(
    store: &SqliteStore,
    identity_keypair: &libsignal_protocol::IdentityKeyPair,
    batch: &GeneratedBatch,
) -> Result<PreKeyUploadBody, ApiError> {
    use libsignal_protocol::{
        KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, SignedPreKeyId,
        SignedPreKeyRecord, SignedPreKeyStore,
    };

    let identity_key_b64 = b64(identity_keypair.public_key().serialize().as_ref());

    // One-time prekeys
    let mut pre_keys = Vec::with_capacity(batch.one_time_prekey_ids.len());
    let store_mut = store.clone();
    for id in &batch.one_time_prekey_ids {
        let record: PreKeyRecord = PreKeyStore::get_pre_key(&store_mut, PreKeyId::from(*id)).await?;
        pre_keys.push(PreKeyJson {
            key_id: *id,
            public_key: b64(record.key_pair()?.public_key.serialize().as_ref()),
        });
    }

    // Signed prekey
    let signed: SignedPreKeyRecord =
        SignedPreKeyStore::get_signed_pre_key(&store_mut, SignedPreKeyId::from(batch.signed_prekey_id)).await?;
    let signed_kp = signed.key_pair()?;
    let signed_pre_key = SignedPreKeyJson {
        key_id: batch.signed_prekey_id,
        public_key: b64(signed_kp.public_key.serialize().as_ref()),
        signature: b64(signed.signature()?.as_ref()),
    };

    // Kyber last-resort prekey (one per batch in v0.1)
    let kyber: KyberPreKeyRecord =
        KyberPreKeyStore::get_kyber_pre_key(&store_mut, KyberPreKeyId::from(batch.kyber_prekey_id)).await?;
    let kyber_kp = kyber.key_pair()?;
    let pq_last_resort = KyberPreKeyJson {
        key_id: batch.kyber_prekey_id,
        public_key: b64(&kyber_kp.public_key.serialize()),
        signature: b64(kyber.signature()?.as_ref()),
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

/// Construct a fresh reqwest client. We keep this per-call rather than
/// pooling for v0.1; the link flow issues only two requests and the keys
/// upload one more, so connection-reuse pressure is low.
fn http_client() -> Result<HttpClient, ApiError> {
    Ok(HttpClient::builder()
        .user_agent(concat!("signal-rs/", env!("CARGO_PKG_VERSION")))
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
        use crate::crypto::prekeys::generate_and_persist_batch;
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
        let batch = generate_and_persist_batch(&mut rng, &store, 1).await.unwrap();
        let body = build_prekey_upload_body(&store, &identity, &batch).await.unwrap();

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
