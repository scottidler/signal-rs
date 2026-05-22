//! Public envelope types surfaced by `Client::receive`. Designed for
//! borg's Note-to-Self filter: a `SyncMessage::Sent` carries the
//! `destination` field load-bearing for `destination == own_number`
//! detection.
//!
//! All variants are `#[non_exhaustive]` so adding more later is a
//! non-breaking change.

/// One envelope as surfaced by [`crate::Client::receive`]. The variant
/// tells the consumer whether the message was sent TO the user
/// (DataMessage) or BY the user from another linked device
/// (SyncMessage::Sent - the Note-to-Self path).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Envelope {
    /// Someone else sent the user a message.
    DataMessage {
        /// Sender E.164 number.
        source: String,
        /// Milliseconds since epoch (Signal's wire timestamp).
        timestamp: u64,
        message: DataMessage,
    },
    /// The user sent a message from another linked device.
    /// Filter on `destination == own_number` to detect Note-to-Self.
    SyncMessage(SyncMessage),
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DataMessage {
    pub body: Option<String>,
    pub timestamp: u64,
    // Attachments, mentions, quotes, reactions: deferred to a later
    // version. #[non_exhaustive] keeps adding them later additive.
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SyncMessage {
    Sent {
        /// E.164 of the original recipient. For Note-to-Self this equals
        /// the user's own account number; for any other outbound message
        /// fanned to linked devices, it's whoever the user sent to.
        destination: String,
        timestamp: u64,
        message: DataMessage,
    },
    // Read, Contacts, Configuration, etc.: deferred.
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
