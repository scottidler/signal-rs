use super::*;
use crate::link::{mark_linked, persist_provision_message};
use crate::storage::SqliteStore;

// Builds a minimal real ProvisionMessage, persists it via Phase 5's
// path, marks the store Linked, and returns the state directory path.
async fn linked_state_dir() -> (tempfile::TempDir, SqliteStore) {
    let tmp = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&tmp.path().join("store.db")).await.unwrap();

    use crate::crypto::provisioning::proto::ProvisionMessage;
    use libsignal_protocol::IdentityKeyPair;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    let mut rng = ChaCha20Rng::seed_from_u64(0x5151);
    let ikp = IdentityKeyPair::generate(&mut rng);
    let msg = ProvisionMessage {
        aci_identity_key_public: Some(ikp.identity_key().serialize().to_vec()),
        aci_identity_key_private: Some(ikp.private_key().serialize().to_vec()),
        pni_identity_key_public: Some(ikp.identity_key().serialize().to_vec()),
        pni_identity_key_private: Some(ikp.private_key().serialize().to_vec()),
        aci: Some("11111111-2222-3333-4444-555555555555".into()),
        pni: Some("66666666-7777-8888-9999-aaaaaaaaaaaa".into()),
        number: Some("+15555550100".into()),
        provisioning_code: Some("ABCDEFGH".into()),
        user_agent: Some("signal-rs-test".into()),
        profile_key: Some(vec![0xCD; 32]),
        read_receipts: Some(false),
        provisioning_version: Some(1),
        ephemeral_backup_key: None,
        account_entropy_pool: None,
        media_root_backup_key: None,
        aci_binary: None,
        pni_binary: None,
    };
    persist_provision_message(&store, &msg).await.unwrap();
    mark_linked(&store).await.unwrap();
    (tmp, store)
}

#[tokio::test]
async fn open_on_empty_state_dir_returns_not_linked() {
    let tmp = tempfile::tempdir().unwrap();
    match Client::open(tmp.path()).await {
        Err(OpenError::NotLinked) => {}
        other => panic!("expected NotLinked, got {:?}", other),
    }
}

#[tokio::test]
async fn open_on_partially_linked_state_dir_returns_partially_linked() {
    use crate::link::persist_provision_message;
    let tmp = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&tmp.path().join("store.db")).await.unwrap();

    use crate::crypto::provisioning::proto::ProvisionMessage;
    use libsignal_protocol::IdentityKeyPair;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    let mut rng = ChaCha20Rng::seed_from_u64(0x5252);
    let ikp = IdentityKeyPair::generate(&mut rng);
    let msg = ProvisionMessage {
        aci_identity_key_public: Some(ikp.identity_key().serialize().to_vec()),
        aci_identity_key_private: Some(ikp.private_key().serialize().to_vec()),
        pni_identity_key_public: Some(ikp.identity_key().serialize().to_vec()),
        pni_identity_key_private: Some(ikp.private_key().serialize().to_vec()),
        aci: None,
        pni: None,
        number: Some("+15555550100".into()),
        provisioning_code: None,
        user_agent: None,
        profile_key: None,
        read_receipts: None,
        provisioning_version: None,
        ephemeral_backup_key: None,
        account_entropy_pool: None,
        media_root_backup_key: None,
        aci_binary: None,
        pni_binary: None,
    };
    persist_provision_message(&store, &msg).await.unwrap();
    // Don't mark_linked - leaves state at IdentityPersisted.
    drop(store);

    match Client::open(tmp.path()).await {
        Err(OpenError::PartiallyLinked) => {}
        other => panic!("expected PartiallyLinked, got {:?}", other),
    }
}

#[tokio::test]
async fn open_succeeds_on_linked_state_dir_and_exposes_account_number() {
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    assert_eq!(client.account_number(), "+15555550100");
}

#[tokio::test]
async fn send_to_pni_recipient_rejects_with_pni_send_unsupported() {
    use crate::envelope::Recipient;
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    let pni_target = Recipient::Pni("cccccccc-cccc-cccc-cccc-cccccccccccc".to_string());
    match client.send(pni_target, "hello").await {
        Err(SendError::PniSendUnsupported) => {}
        other => panic!("expected PniSendUnsupported, got {:?}", other),
    }
}

#[tokio::test]
async fn send_to_aci_recipient_without_profile_key_or_session_errors_with_no_profile_key() {
    use crate::envelope::Recipient;
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    // A well-formed but unknown peer ACI. No peer_profile_keys row,
    // no session. Sealed path is impossible and unsealed fallback has
    // nothing to encrypt against, so the call must surface
    // NoProfileKey rather than attempt a network call.
    let peer = Recipient::Aci("11111111-1111-1111-1111-111111111111".to_string());
    match client.send(peer, "hi").await {
        Err(SendError::NoProfileKey(aci)) => {
            assert!(
                aci.contains("11111111-1111-1111-1111-111111111111"),
                "expected the ACI in the error, got {aci}"
            );
        }
        other => panic!("expected NoProfileKey, got {:?}", other),
    }
}

#[tokio::test]
async fn send_to_aci_recipient_with_invalid_uuid_rejects_with_invalid_recipient() {
    use crate::envelope::Recipient;
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    let bad = Recipient::Aci("not-a-uuid".to_string());
    match client.send(bad, "hi").await {
        Err(SendError::InvalidRecipient(_)) => {}
        other => panic!("expected InvalidRecipient, got {:?}", other),
    }
}

// run_receive_loop now opens a real chat WebSocket against Signal's
// production servers; it cannot be exercised in unit tests without a
// live account. Coverage moves to Phase 10's manual smoke test.

#[tokio::test]
async fn receive_returns_a_subscriber_even_before_loop_is_running() {
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    let mut rx = client.receive();
    // No producer yet, so the channel is empty - try_recv must say so.
    assert!(rx.try_recv().is_err(), "no envelopes yet");
}

// =============================================================================
// route_envelope_to_identity: PNI vs ACI routing on inbound envelopes
// =============================================================================
//
// process_envelope's full path requires a synthesized encrypted envelope,
// which in turn requires pre-established sessions for ACI and PNI. The
// routing decision itself was extracted to a pure free function so it
// can be tested directly. The Phase 5 smoke is necessary but not
// sufficient (primary-to-linked sync traffic is ACI-addressed); these
// tests are the unit-level proxy for the PNI receive path.

use crate::client::route_envelope_to_identity;
use crate::crypto::prekeys::IdentityKind;

const ACI: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const PNI: &str = "pppppppp-pppp-pppp-pppp-pppppppppppp";

#[test]
fn route_pni_destination_routes_to_pni_scope() {
    let (kind, local_service_id) = route_envelope_to_identity(Some(PNI), ACI, Some(PNI));
    assert_eq!(kind, IdentityKind::Pni);
    assert_eq!(local_service_id, PNI);
}

#[test]
fn route_aci_destination_routes_to_aci_scope() {
    let (kind, local_service_id) = route_envelope_to_identity(Some(ACI), ACI, Some(PNI));
    assert_eq!(kind, IdentityKind::Aci);
    assert_eq!(local_service_id, ACI);
}

#[test]
fn route_missing_destination_defaults_to_aci() {
    let (kind, local_service_id) = route_envelope_to_identity(None, ACI, Some(PNI));
    assert_eq!(kind, IdentityKind::Aci);
    assert_eq!(local_service_id, ACI);
}

#[test]
fn route_unknown_destination_defaults_to_aci() {
    let unknown = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";
    let (kind, local_service_id) = route_envelope_to_identity(Some(unknown), ACI, Some(PNI));
    assert_eq!(kind, IdentityKind::Aci);
    assert_eq!(local_service_id, ACI);
}

#[test]
fn route_pni_destination_without_local_pni_falls_through_to_aci() {
    // No PNI persisted yet (early-link bootstrap or single-identity
    // account). A destination that doesn't match ACI should route to
    // ACI with a warn rather than mis-route to PNI scope.
    let (kind, local_service_id) = route_envelope_to_identity(Some(PNI), ACI, None);
    assert_eq!(kind, IdentityKind::Aci);
    assert_eq!(local_service_id, ACI);
}

#[test]
fn route_aci_destination_works_without_local_pni() {
    let (kind, local_service_id) = route_envelope_to_identity(Some(ACI), ACI, None);
    assert_eq!(kind, IdentityKind::Aci);
    assert_eq!(local_service_id, ACI);
}

// =============================================================================
// decode_content / build_*_content: prost-generated round-trips
// =============================================================================
//
// Phase 1 replaced the hand-rolled minimal decoders/builders with the
// prost-generated signalservice::Content surface. These tests pin the
// public Envelope mapping to the new wire shape so a future drift in
// either the proto or the mapping is caught locally rather than through
// a production-smoke regression.

use crate::client::{
    build_delete_content, build_one_to_one_content, build_sync_delete_content, build_sync_self_content,
    build_typing_content, decode_content,
};
use crate::crypto::provisioning::proto;
use crate::envelope::{Envelope as PubEnvelope, ReceiptKind, Recipient, SyncMessage as PubSyncMessage};

#[test]
fn decode_content_data_message_round_trips_through_build_one_to_one() {
    let body = "hello from a peer";
    let ts = 1_700_000_000_123_u64;
    let plaintext = build_one_to_one_content(body, ts, &[]);

    let (env_opt, peer_pk) = decode_content(&plaintext, ACI, 1, ts);
    let env = env_opt.expect("DataMessage Content decodes");
    // build_one_to_one_content does not set profile_key, so we expect None.
    assert!(peer_pk.is_none(), "no profile_key was set in the build helper");
    let PubEnvelope::DataMessage {
        source,
        source_device,
        timestamp,
        body: env_body,
        ..
    } = env
    else {
        panic!("expected Envelope::DataMessage, got something else");
    };
    assert_eq!(source, Recipient::Aci(ACI.to_string()));
    assert_eq!(source_device, 1);
    assert_eq!(timestamp, ts);
    assert_eq!(env_body.as_deref(), Some(body));
}

#[test]
fn decode_content_sync_sent_round_trips_through_build_sync_self() {
    let body = "Note to Self from the phone";
    let own = "+15555550100";
    let ts = 1_700_000_000_456_u64;
    let plaintext = build_sync_self_content(body, own, ts, &[]);
    // Wire-envelope source is the primary's service-id; the public
    // SyncMessage::Sent.destination comes from the SyncMessage payload.
    // SelfSync remapping is done by process_envelope, not decode_content,
    // so here we expect Recipient::Aci(own) (the raw destination string).
    let env = decode_content(&plaintext, ACI, 1, ts)
        .0
        .expect("SyncMessage Content decodes");
    let PubEnvelope::SyncMessage(PubSyncMessage::Sent {
        destination,
        timestamp,
        body: env_body,
        ..
    }) = env
    else {
        panic!("expected Envelope::SyncMessage(Sent), got something else");
    };
    assert_eq!(destination, Some(Recipient::Aci(own.to_string())));
    assert_eq!(timestamp, ts);
    assert_eq!(env_body.as_deref(), Some(body));
}

#[test]
fn decode_content_typing_message_surfaces_typing_variant() {
    // Phase 3 surfaces TypingMessage as Envelope::Typing rather than
    // dropping it.
    use prost::Message as _;
    let typing = proto::TypingMessage {
        timestamp: Some(1_700_000_000_789),
        action: Some(proto::typing_message::Action::Started as i32),
        ..Default::default()
    };
    let content = proto::Content {
        content: Some(proto::content::Content::TypingMessage(typing)),
        ..Default::default()
    };
    let plaintext = content.encode_to_vec();
    let env = decode_content(&plaintext, ACI, 1, 0).0.expect("Typing surfaces");
    let PubEnvelope::Typing { started, timestamp, .. } = env else {
        panic!("expected Envelope::Typing");
    };
    assert!(started);
    assert_eq!(timestamp, 1_700_000_000_789);
}

#[test]
fn decode_content_receipt_message_surfaces_receipt_variant_with_kind() {
    use prost::Message as _;
    let receipt = proto::ReceiptMessage {
        r#type: Some(proto::receipt_message::Type::Read as i32),
        timestamp: vec![1_700_000_000, 1_700_000_001],
    };
    let content = proto::Content {
        content: Some(proto::content::Content::ReceiptMessage(receipt)),
        ..Default::default()
    };
    let plaintext = content.encode_to_vec();
    let env = decode_content(&plaintext, ACI, 1, 0).0.expect("Receipt surfaces");
    let PubEnvelope::Receipt {
        receipt_kind,
        timestamps,
        ..
    } = env
    else {
        panic!("expected Envelope::Receipt");
    };
    assert!(matches!(receipt_kind, ReceiptKind::Read));
    assert_eq!(timestamps, vec![1_700_000_000, 1_700_000_001]);
}

#[test]
fn decode_content_edit_message_surfaces_edit_variant() {
    use prost::Message as _;
    let inner_dm = proto::DataMessage {
        body: Some("edited body".to_string()),
        ..Default::default()
    };
    let edit = proto::EditMessage {
        target_sent_timestamp: Some(1_700_000_000),
        data_message: Some(inner_dm),
    };
    let content = proto::Content {
        content: Some(proto::content::Content::EditMessage(edit)),
        ..Default::default()
    };
    let plaintext = content.encode_to_vec();
    let env = decode_content(&plaintext, ACI, 1, 1_800_000_000)
        .0
        .expect("Edit surfaces");
    let PubEnvelope::Edit {
        target_sent_timestamp,
        body,
        timestamp,
        ..
    } = env
    else {
        panic!("expected Envelope::Edit");
    };
    assert_eq!(target_sent_timestamp, 1_700_000_000);
    assert_eq!(timestamp, 1_800_000_000);
    assert_eq!(body.as_deref(), Some("edited body"));
}

#[test]
fn decode_content_call_message_surfaces_call_variant_with_raw_bytes() {
    use prost::Message as _;
    let call = proto::CallMessage::default();
    let content = proto::Content {
        content: Some(proto::content::Content::CallMessage(call)),
        ..Default::default()
    };
    let plaintext = content.encode_to_vec();
    let env = decode_content(&plaintext, ACI, 1, 0).0.expect("Call surfaces");
    assert!(matches!(env, PubEnvelope::Call { .. }));
}

#[test]
fn decode_content_sync_read_surfaces_sync_read_variant() {
    use prost::Message as _;
    let sender_aci = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    let sm = proto::SyncMessage {
        read: vec![proto::sync_message::Read {
            sender_aci: Some(sender_aci.to_string()),
            timestamp: Some(1_700_000_000),
            ..Default::default()
        }],
        ..Default::default()
    };
    let content = proto::Content {
        content: Some(proto::content::Content::SyncMessage(sm)),
        ..Default::default()
    };
    let plaintext = content.encode_to_vec();
    let env = decode_content(&plaintext, ACI, 1, 0)
        .0
        .expect("SyncMessage::Read surfaces");
    let PubEnvelope::SyncMessage(PubSyncMessage::Read { reads }) = env else {
        panic!("expected Envelope::SyncMessage(Read)");
    };
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].timestamp, 1_700_000_000);
    assert_eq!(reads[0].sender, Recipient::Aci(sender_aci.to_string()));
}

#[test]
fn decode_content_surfaces_peer_profile_key_from_data_message() {
    // An inbound peer DataMessage with profile_key must surface that
    // key as the second element of decode_content's return tuple so
    // the caller can persist it for the sealed-sender outbound path.
    use prost::Message as _;
    let pk = vec![7u8; 32];
    let dm = proto::DataMessage {
        body: Some("hi with key".to_string()),
        timestamp: Some(1_800_000_000),
        profile_key: Some(pk.clone()),
        ..Default::default()
    };
    let content = proto::Content {
        content: Some(proto::content::Content::DataMessage(dm)),
        ..Default::default()
    };
    let plaintext = content.encode_to_vec();
    let (env, peer_pk) = decode_content(&plaintext, ACI, 1, 1_800_000_000);
    assert!(env.is_some(), "DataMessage decodes");
    assert_eq!(peer_pk, Some(pk));
}

#[test]
fn decode_content_does_not_surface_profile_key_from_sync_sent() {
    // SyncMessage::Sent.message.profile_key is OUR own key (we sent
    // the message from another device). decode_content must not
    // surface it as a peer key, or it would clobber the local
    // peer_profile_keys row for our own ACI.
    let body = "self-sync with our key";
    let own = "+15555550100";
    let ts = 1_900_000_000_u64;
    let plaintext = build_sync_self_content(body, own, ts, &[]);
    let (_, peer_pk) = decode_content(&plaintext, ACI, 1, ts);
    assert!(
        peer_pk.is_none(),
        "SyncMessage::Sent must not surface a peer profile_key"
    );
}

#[test]
fn decode_content_returns_none_for_empty_content() {
    // An empty Content (no oneof set, no `read` payload) must not
    // synthesize a DataMessage/SyncMessage from nothing.
    use prost::Message as _;
    let plaintext = proto::Content::default().encode_to_vec();
    assert!(decode_content(&plaintext, ACI, 1, 1_700_000_000).0.is_none());
}

#[test]
fn decode_content_returns_none_on_undecodable_bytes() {
    let plaintext = b"this is not a valid protobuf";
    assert!(decode_content(plaintext, ACI, 1, 0).0.is_none());
}

#[test]
fn service_id_to_recipient_classifies_pni_prefix() {
    use crate::client::service_id_to_recipient;
    let pni_input = "PNI:99999999-9999-9999-9999-999999999999";
    let r = service_id_to_recipient(pni_input);
    assert_eq!(r, Recipient::Pni("99999999-9999-9999-9999-999999999999".to_string()));
}

#[test]
fn service_id_to_recipient_classifies_bare_uuid_as_aci() {
    use crate::client::service_id_to_recipient;
    let aci_input = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let r = service_id_to_recipient(aci_input);
    assert_eq!(r, Recipient::Aci(aci_input.to_string()));
}

// --- Phase 6: attachment-pointer plumbing tests ---------------------------
//
// build_one_to_one_content and build_sync_self_content must carry through
// any attachment pointers we give them so peers / the receive path can
// pull the AttachmentPointer back out of the inbound Envelope. The
// attachment_pointer_to_proto helper bridges between our public type
// (flat bool flags + Option<String> cdn_key + plain u64 cdn_id) and
// the proto oneof+flags layout.

fn sample_pointer(cdn_key: &str) -> crate::envelope::AttachmentPointer {
    crate::envelope::AttachmentPointer {
        cdn_id: 0,
        cdn_key: Some(cdn_key.to_string()),
        cdn_number: 2,
        content_type: Some("image/png".to_string()),
        size: Some(1234),
        digest: vec![0xAB; 32],
        key: vec![0xCD; 64],
        file_name: Some("hello.png".to_string()),
        caption: None,
        width: None,
        height: None,
        voice_note: false,
        borderless: false,
        gif: true,
        upload_timestamp: Some(1_700_000_000_000),
        blurhash: None,
    }
}

#[test]
fn attachment_pointer_to_proto_maps_cdn_key_to_oneof() {
    use crate::crypto::provisioning::proto;
    let p = sample_pointer("AAA-server-cdn-key");
    let pp = attachment_pointer_to_proto(p);
    match pp.attachment_identifier {
        Some(proto::attachment_pointer::AttachmentIdentifier::CdnKey(k)) => {
            assert_eq!(k, "AAA-server-cdn-key");
        }
        other => panic!("expected CdnKey identifier, got {other:?}"),
    }
    assert_eq!(pp.cdn_number, Some(2));
    assert_eq!(pp.size, Some(1234));
    assert_eq!(pp.content_type.as_deref(), Some("image/png"));
    // Only `gif` is set in the sample → exactly the GIF flag bit.
    assert_eq!(pp.flags, Some(proto::attachment_pointer::Flags::Gif as u32));
}

#[test]
fn attachment_pointer_to_proto_falls_back_to_cdn_id_when_no_key() {
    use crate::crypto::provisioning::proto;
    let mut p = sample_pointer("ignored");
    p.cdn_key = None;
    p.cdn_id = 0xDEADBEEF;
    let pp = attachment_pointer_to_proto(p);
    match pp.attachment_identifier {
        Some(proto::attachment_pointer::AttachmentIdentifier::CdnId(id)) => assert_eq!(id, 0xDEADBEEF),
        other => panic!("expected CdnId identifier, got {other:?}"),
    }
}

#[test]
fn attachment_pointer_to_proto_combines_voice_borderless_gif_flags() {
    use crate::crypto::provisioning::proto;
    let mut p = sample_pointer("k");
    p.voice_note = true;
    p.borderless = true;
    p.gif = true;
    let pp = attachment_pointer_to_proto(p);
    let expected = (proto::attachment_pointer::Flags::VoiceMessage as u32)
        | (proto::attachment_pointer::Flags::Borderless as u32)
        | (proto::attachment_pointer::Flags::Gif as u32);
    assert_eq!(pp.flags, Some(expected));
}

#[test]
fn build_one_to_one_content_carries_attachment_pointers() {
    use prost::Message as _;
    let p1 = attachment_pointer_to_proto(sample_pointer("key-1"));
    let p2 = attachment_pointer_to_proto(sample_pointer("key-2"));
    let bytes = build_one_to_one_content("hi", 1_700_000_000_000, &[p1.clone(), p2.clone()]);
    let content = proto::Content::decode(&*bytes).expect("Content round-trips");
    let dm = match content.content {
        Some(proto::content::Content::DataMessage(dm)) => dm,
        other => panic!("expected Content::DataMessage, got {other:?}"),
    };
    assert_eq!(dm.attachments.len(), 2);
    assert_eq!(dm.body.as_deref(), Some("hi"));
    assert_eq!(dm.attachments[0].size, Some(1234));
}

#[test]
fn build_sync_self_content_carries_attachment_pointers() {
    use prost::Message as _;
    let p1 = attachment_pointer_to_proto(sample_pointer("self-1"));
    let bytes = build_sync_self_content(
        "self-body",
        "+15555550100",
        1_700_000_000_000,
        std::slice::from_ref(&p1),
    );
    let content = proto::Content::decode(&*bytes).expect("Content round-trips");
    let sm = match content.content {
        Some(proto::content::Content::SyncMessage(sm)) => sm,
        other => panic!("expected Content::SyncMessage, got {other:?}"),
    };
    let sent = match sm.content {
        Some(proto::sync_message::Content::Sent(sent)) => sent,
        other => panic!("expected SyncMessage::Sent, got {other:?}"),
    };
    let dm = sent.message.expect("Sent.message is set");
    assert_eq!(dm.attachments.len(), 1);
    assert_eq!(dm.attachments[0].size, Some(1234));
}

// --- Phase 7: typing + remote-delete builders --------------------------
//
// build_typing_content wraps a TypingMessage in a Content; build_delete_content
// wraps a DataMessage with the `delete` field set. Both must round-trip through
// prost so the wire bytes our peer dispatch sends are decodable.

#[test]
fn build_typing_content_started_decodes_to_typing_started() {
    use prost::Message as _;
    let ts = 1_700_000_000_111_u64;
    let bytes = build_typing_content(true, ts);
    let content = proto::Content::decode(&*bytes).expect("Content round-trips");
    let tm = match content.content {
        Some(proto::content::Content::TypingMessage(tm)) => tm,
        other => panic!("expected Content::TypingMessage, got {other:?}"),
    };
    assert_eq!(tm.timestamp, Some(ts));
    assert_eq!(tm.action(), proto::typing_message::Action::Started);
    assert!(tm.group_id.is_none());
}

#[test]
fn build_typing_content_stopped_decodes_to_typing_stopped() {
    use prost::Message as _;
    let ts = 1_700_000_000_222_u64;
    let bytes = build_typing_content(false, ts);
    let content = proto::Content::decode(&*bytes).expect("Content round-trips");
    let tm = match content.content {
        Some(proto::content::Content::TypingMessage(tm)) => tm,
        other => panic!("expected Content::TypingMessage, got {other:?}"),
    };
    assert_eq!(tm.action(), proto::typing_message::Action::Stopped);
}

#[test]
fn build_typing_content_round_trips_through_decode_content_as_typing_envelope() {
    // The peer-side public surface (decode_content) must surface a
    // build_typing_content blob as Envelope::Typing.
    let ts = 1_700_000_000_333_u64;
    let bytes = build_typing_content(true, ts);
    let env = decode_content(&bytes, ACI, 1, ts).0.expect("Typing decodes");
    let PubEnvelope::Typing { started, timestamp, .. } = env else {
        panic!("expected Envelope::Typing");
    };
    assert!(started);
    assert_eq!(timestamp, ts);
}

#[test]
fn build_sync_delete_content_wraps_delete_data_message_inside_sync_sent_addressed_to_peer() {
    // For the own-device sync of a remote delete: the SyncMessage::Sent
    // names the PEER (whose thread is being modified) as the destination,
    // and carries a DataMessage whose only field is the delete tombstone.
    use prost::Message as _;
    let peer = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    let target = 1_700_000_000_777_u64;
    let now = 1_700_000_000_888_u64;
    let bytes = build_sync_delete_content(peer, target, now);
    let content = proto::Content::decode(&*bytes).expect("Content round-trips");
    let sm = match content.content {
        Some(proto::content::Content::SyncMessage(sm)) => sm,
        other => panic!("expected Content::SyncMessage, got {other:?}"),
    };
    let sent = match sm.content {
        Some(proto::sync_message::Content::Sent(sent)) => sent,
        other => panic!("expected SyncMessage::Sent, got {other:?}"),
    };
    assert_eq!(sent.destination_service_id.as_deref(), Some(peer));
    assert_eq!(sent.timestamp, Some(now));
    let dm = sent.message.expect("Sent.message is set");
    assert!(dm.body.is_none(), "no body on a sync-delete payload");
    assert!(dm.attachments.is_empty(), "no attachments on a sync-delete payload");
    assert_eq!(dm.timestamp, Some(now));
    let delete = dm.delete.expect("delete field set");
    assert_eq!(delete.target_sent_timestamp, Some(target));
}

#[test]
fn build_delete_content_carries_target_sent_timestamp_in_data_message_delete() {
    use prost::Message as _;
    let target = 1_700_000_000_555_u64;
    let now = 1_700_000_000_999_u64;
    let bytes = build_delete_content(target, now);
    let content = proto::Content::decode(&*bytes).expect("Content round-trips");
    let dm = match content.content {
        Some(proto::content::Content::DataMessage(dm)) => dm,
        other => panic!("expected Content::DataMessage, got {other:?}"),
    };
    // No body, no attachments - just timestamp + delete.
    assert!(dm.body.is_none());
    assert!(dm.attachments.is_empty());
    assert_eq!(dm.timestamp, Some(now));
    let delete = dm.delete.expect("delete field set");
    assert_eq!(delete.target_sent_timestamp, Some(target));
}

#[tokio::test]
async fn typing_to_self_recipient_rejects_with_invalid_recipient() {
    use crate::envelope::Recipient;
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    match client.typing(Recipient::SelfSync, true).await {
        Err(SendError::InvalidRecipient(_)) => {}
        other => panic!("expected InvalidRecipient, got {:?}", other),
    }
}

#[tokio::test]
async fn typing_to_pni_recipient_rejects_with_pni_send_unsupported() {
    use crate::envelope::Recipient;
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    let pni = Recipient::Pni("cccccccc-cccc-cccc-cccc-cccccccccccc".to_string());
    match client.typing(pni, true).await {
        Err(SendError::PniSendUnsupported) => {}
        other => panic!("expected PniSendUnsupported, got {:?}", other),
    }
}

#[tokio::test]
async fn typing_to_aci_without_session_or_profile_key_errors_with_no_profile_key() {
    use crate::envelope::Recipient;
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    let peer = Recipient::Aci("22222222-2222-2222-2222-222222222222".to_string());
    match client.typing(peer, true).await {
        Err(SendError::NoProfileKey(_)) => {}
        other => panic!("expected NoProfileKey, got {:?}", other),
    }
}

#[tokio::test]
async fn delete_for_everyone_to_self_recipient_rejects_with_invalid_recipient() {
    use crate::envelope::Recipient;
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    match client.delete_for_everyone(Recipient::SelfSync, 1_700_000_000_000).await {
        Err(SendError::InvalidRecipient(_)) => {}
        other => panic!("expected InvalidRecipient, got {:?}", other),
    }
}

#[tokio::test]
async fn delete_for_everyone_to_pni_recipient_rejects_with_pni_send_unsupported() {
    use crate::envelope::Recipient;
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    let pni = Recipient::Pni("dddddddd-dddd-dddd-dddd-dddddddddddd".to_string());
    match client.delete_for_everyone(pni, 1_700_000_000_000).await {
        Err(SendError::PniSendUnsupported) => {}
        other => panic!("expected PniSendUnsupported, got {:?}", other),
    }
}

#[tokio::test]
async fn delete_for_everyone_to_aci_without_session_or_profile_key_errors_with_no_profile_key() {
    use crate::envelope::Recipient;
    let (tmp, _) = linked_state_dir().await;
    let client = Client::open(tmp.path()).await.unwrap();
    let peer = Recipient::Aci("33333333-3333-3333-3333-333333333333".to_string());
    match client.delete_for_everyone(peer, 1_700_000_000_000).await {
        Err(SendError::NoProfileKey(_)) => {}
        other => panic!("expected NoProfileKey, got {:?}", other),
    }
}
