//! Surface tests for the public envelope types: that they can be
//! constructed, matched, and serialized. The Note-to-Self filter
//! pattern (used by borg) is pinned here so a future change to
//! Recipient::SelfSync's wire shape lands as a test failure rather
//! than a silent contract drift.

use super::*;
use serde_json::json;

#[test]
fn note_to_self_filter_pattern_compiles_and_matches() {
    let envelope = Envelope::SyncMessage(SyncMessage::Sent {
        destination: Some(Recipient::SelfSync),
        group_id: None,
        timestamp: 1_700_000_000_000,
        body: Some("test note".into()),
        attachments: Vec::new(),
        edit_of_timestamp: None,
        expire_in_seconds: None,
    });

    let mut hit = false;
    if let Envelope::SyncMessage(SyncMessage::Sent {
        destination: Some(Recipient::SelfSync),
        body,
        ..
    }) = envelope
    {
        hit = true;
        assert_eq!(body.as_deref(), Some("test note"));
    }
    assert!(hit, "Note-to-Self filter must match Recipient::SelfSync");
}

#[test]
fn data_message_from_peer_is_not_a_self_sync() {
    let envelope = Envelope::DataMessage {
        source: Recipient::Aci("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into()),
        source_device: 1,
        timestamp: 1_700_000_000_000,
        group_id: None,
        body: Some("from someone else".into()),
        attachments: Vec::new(),
        quote: None,
        edit_of_timestamp: None,
        expire_in_seconds: None,
    };
    assert!(matches!(envelope, Envelope::DataMessage { .. }));
}

#[test]
fn outbound_sync_to_another_peer_does_not_match_note_to_self() {
    let envelope = Envelope::SyncMessage(SyncMessage::Sent {
        destination: Some(Recipient::Aci("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into())),
        group_id: None,
        timestamp: 1_700_000_000_000,
        body: Some("hi peer".into()),
        attachments: Vec::new(),
        edit_of_timestamp: None,
        expire_in_seconds: None,
    });

    let is_self_sync = matches!(
        &envelope,
        Envelope::SyncMessage(SyncMessage::Sent {
            destination: Some(Recipient::SelfSync),
            ..
        })
    );
    assert!(!is_self_sync, "outbound sync to a peer must NOT match SelfSync");
}

#[test]
fn data_message_serializes_with_kind_tag() {
    let envelope = Envelope::DataMessage {
        source: Recipient::Aci("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into()),
        source_device: 1,
        timestamp: 1_700_000_000_000,
        group_id: None,
        body: Some("hello".into()),
        attachments: Vec::new(),
        quote: None,
        edit_of_timestamp: None,
        expire_in_seconds: None,
    };
    let json_val = serde_json::to_value(&envelope).unwrap();
    assert_eq!(json_val["kind"], "data_message");
    assert_eq!(json_val["body"], "hello");
    // Recipient uses external tagging: tuple variants render as a
    // single-key object keyed by the variant name.
    assert_eq!(
        json_val["source"],
        json!({"aci": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"})
    );
    assert_eq!(json_val["source_device"], 1);
}

#[test]
fn note_to_self_serializes_with_self_sync_destination() {
    let envelope = Envelope::SyncMessage(SyncMessage::Sent {
        destination: Some(Recipient::SelfSync),
        group_id: None,
        timestamp: 1_700_000_000_000,
        body: Some("note to self".into()),
        attachments: Vec::new(),
        edit_of_timestamp: None,
        expire_in_seconds: None,
    });
    let json_val = serde_json::to_value(&envelope).unwrap();
    // Envelope's tag is "kind"; SyncMessage's tag is "sync_kind" so they
    // don't collide when SyncMessage is flattened into Envelope.
    assert_eq!(json_val["kind"], "sync_message");
    assert_eq!(json_val["sync_kind"], "sent");
    // Recipient::SelfSync is a unit variant: just the lowercased name.
    assert_eq!(json_val["destination"], json!("self_sync"));
    assert_eq!(json_val["body"], "note to self");
}

#[test]
fn receipt_serializes_receipt_kind_field_not_kind_field() {
    // The struct field is named `receipt_kind` because `kind` is the
    // serde tag for the variant discriminator. This test pins the wire
    // shape so a future rename can't silently break consumers.
    let envelope = Envelope::Receipt {
        receipt_kind: ReceiptKind::Read,
        source: Recipient::Aci("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into()),
        timestamps: vec![1_700_000_000_000],
    };
    let json_val = serde_json::to_value(&envelope).unwrap();
    assert_eq!(json_val["kind"], "receipt");
    assert_eq!(json_val["receipt_kind"], "read");
    assert_eq!(
        json_val["source"],
        json!({"aci": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"})
    );
}
