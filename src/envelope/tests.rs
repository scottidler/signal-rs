//! Surface tests for the public envelope types - that they can be
//! constructed, matched, and that the `destination == own_number`
//! Note-to-Self filter pattern compiles cleanly. The borg integration
//! depends on this pattern; the test exists to catch a future change
//! that breaks the SyncMessage::Sent shape.

use super::*;

#[test]
fn note_to_self_filter_pattern_compiles_and_matches() {
    let envelope = Envelope::SyncMessage(SyncMessage::Sent {
        destination: "+15555550100".to_string(),
        timestamp: 1_700_000_000_000,
        message: DataMessage {
            body: Some("test note".into()),
            timestamp: 1_700_000_000_000,
        },
    });
    let own_number = "+15555550100";
    let mut hit = false;
    if let Envelope::SyncMessage(SyncMessage::Sent {
        destination, message, ..
    }) = envelope
        && destination == own_number
    {
        hit = true;
        assert_eq!(message.body.as_deref(), Some("test note"));
    }
    assert!(hit, "Note-to-Self filter must match own destination");
}

#[test]
fn data_message_from_peer_is_not_a_self_sync() {
    let envelope = Envelope::DataMessage {
        source: "+19999999999".to_string(),
        timestamp: 1_700_000_000_000,
        message: DataMessage {
            body: Some("from someone else".into()),
            timestamp: 1_700_000_000_000,
        },
    };
    matches!(envelope, Envelope::DataMessage { .. });
}

#[test]
fn outbound_sync_to_another_peer_does_not_match_note_to_self() {
    let envelope = Envelope::SyncMessage(SyncMessage::Sent {
        destination: "+19999999999".into(),
        timestamp: 1_700_000_000_000,
        message: DataMessage {
            body: Some("a normal outbound message".into()),
            timestamp: 1_700_000_000_000,
        },
    });
    let own_number = "+15555550100";
    let matched = if let Envelope::SyncMessage(SyncMessage::Sent { destination, .. }) = &envelope {
        destination == own_number
    } else {
        false
    };
    assert!(
        !matched,
        "outbound sync to a different peer must NOT match the own-number filter"
    );
}
