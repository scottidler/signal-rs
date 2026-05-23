//! Public envelope types surfaced by `Client::receive`.
//!
//! Phase 3 of the message-surface buildout: replaces the impoverished
//! two-variant Envelope (DataMessage + SyncMessage::Sent body+timestamp
//! only) with the full surface borg needs to operate as a Signal
//! transport. All variants are `#[non_exhaustive]` so adding more later
//! is non-breaking.
//!
//! Serde: every type derives `Serialize` with `#[serde(tag = "kind")]`
//! discrimination on the enums so JSON output (one envelope per line)
//! is self-describing for `jq` consumers.

use serde::Serialize;

/// One envelope as surfaced by [`crate::Client::receive`].
///
/// The Note-to-Self filter for consumers like borg is:
/// `matches!(env, Envelope::SyncMessage(SyncMessage::Sent { destination: Some(Recipient::SelfSync), .. }))`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Envelope {
    /// Someone sent us a message.
    DataMessage {
        source: Recipient,
        source_device: u32,
        timestamp: u64,
        group_id: Option<Vec<u8>>,
        body: Option<String>,
        attachments: Vec<AttachmentPointer>,
        quote: Option<Quote>,
        edit_of_timestamp: Option<u64>,
        expire_in_seconds: Option<u32>,
    },
    /// We sent a message from another linked device, or the primary is
    /// syncing read/contacts/etc. state to us.
    SyncMessage(SyncMessage),
    /// A delivery / read / viewed receipt for one or more of our prior
    /// outbound messages. The field is named `receipt_kind` (not `kind`)
    /// because `serde(tag = "kind")` claims that name for the variant
    /// discriminator on the wire.
    Receipt {
        receipt_kind: ReceiptKind,
        source: Recipient,
        timestamps: Vec<u64>,
    },
    /// Someone started or stopped typing.
    Typing {
        source: Recipient,
        group_id: Option<Vec<u8>>,
        started: bool,
        timestamp: u64,
    },
    /// An edit of a previous message (target_sent_timestamp identifies
    /// the original).
    Edit {
        source: Recipient,
        timestamp: u64,
        target_sent_timestamp: u64,
        body: Option<String>,
    },
    /// Calls (offer / answer / busy / hangup / ice-update). The wire
    /// shape is forwarded as-is; consumers that don't care about call
    /// signalling simply skip this variant.
    Call { source: Recipient, raw: Vec<u8> },
    /// Forward-compat escape hatch. Any decoded `Content` whose shape we
    /// don't yet map (a new sync subtype, new envelope sub-message,
    /// etc.) surfaces here so consumers can log and skip without
    /// `process_envelope` silently dropping the envelope.
    Unknown { type_tag: String, raw: Vec<u8> },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "sync_kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SyncMessage {
    /// A message we sent from another linked device. `destination ==
    /// Some(Recipient::SelfSync)` is the Note-to-Self path; any other
    /// `destination` is a fan-out of a 1:1 send to a peer.
    Sent {
        destination: Option<Recipient>,
        group_id: Option<Vec<u8>>,
        timestamp: u64,
        body: Option<String>,
        attachments: Vec<AttachmentPointer>,
        edit_of_timestamp: Option<u64>,
        expire_in_seconds: Option<u32>,
    },
    /// Read-receipts that the primary device originated and is syncing
    /// to us.
    Read { reads: Vec<ReadReceipt> },
    // additional sync subtypes added later under #[non_exhaustive]
}

/// A typed sender / destination. Replaces the earlier loose `String`
/// fields so consumers can match on identity kind without string
/// inspection. Uses serde's default external tagging because the
/// `Aci(String)` / `Pni(String)` tuple variants are incompatible with
/// internally-tagged serde; the resulting JSON shape is
/// `"self_sync"` for the unit variant and `{"aci": "..."}` /
/// `{"pni": "..."}` for the tuple variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Recipient {
    /// Note-to-Self: the destination of an outbound `SyncMessage::Sent`
    /// where source == destination == our own ACI. Surfaced explicitly
    /// so consumers can filter without string-comparing.
    SelfSync,
    Aci(String),
    Pni(String),
    // E164(String) is intentionally NOT a variant. CDS-based E.164
    // resolution lands in its own design doc. #[non_exhaustive] keeps
    // that addition non-breaking.
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReceiptKind {
    Delivery,
    Read,
    Viewed,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadReceipt {
    pub sender: Recipient,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Quote {
    pub id: u64,
    pub author: Recipient,
    pub text: Option<String>,
}

/// A pointer to a CDN-hosted encrypted attachment blob. Phase 3 surfaces
/// the pointer; Phase 4 wires up `Client::download_attachment` which
/// fetches + AES-CBC decrypts + digest-verifies the blob.
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentPointer {
    pub cdn_id: u64,
    pub cdn_key: Option<String>,
    pub cdn_number: u32,
    pub content_type: Option<String>,
    pub size: Option<u32>,
    pub digest: Vec<u8>,
    pub key: Vec<u8>,
    pub file_name: Option<String>,
    pub caption: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub voice_note: bool,
    pub borderless: bool,
    pub gif: bool,
    pub upload_timestamp: Option<u64>,
    pub blurhash: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
