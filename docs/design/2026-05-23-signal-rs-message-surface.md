# Design Document: signal-rs message surface buildout

**Author:** Scott Idler
**Date:** 2026-05-23
**Status:** Draft
**Review Passes Completed:** 5/5 + Architect Rounds 1-2

## Summary

signal-rs today links, receives, decrypts, and sends a narrow subset of
Signal traffic with an impoverished public `Envelope` enum and
hand-rolled "minimal" proto decoders that drop most real-world
messages on the floor. This doc closes that gap so the crate's
library surface is rich enough to be the in-process Signal transport
for any consumer (the immediate driver is feature-parity with our
Telegram path, but signal-rs ships as a standalone library + CLI;
integration with any consumer lives in the consumer's own repo).

## Problem Statement

### Background

signal-rs ships today as a library at `src/lib.rs` plus a thin CLI at
`src/main.rs`. The public surface exports `Client::open`,
`Client::receive` (a broadcast subscriber), `Client::send`, and an
`Envelope` enum with two variants.

`Envelope::DataMessage` carries `{ source, timestamp, message }` where
`message: DataMessage` is `{ body: Option<String>, timestamp: u64 }`.
`Envelope::SyncMessage(SyncMessage::Sent)` carries
`{ destination, timestamp, message }` with the same `DataMessage`
shape. Everything richer than "a string of text" is silently dropped.

Inside `client.rs`, `decode_content` is a hand-rolled prost
`Message`-deriving struct (`TopLevelContent`) that looks only at
fields 1 (`data_message`) and 2 (`sync_message`). It then dispatches
into `decode_data_message_body` (reads field 1 string `body`) or
`decode_sync_sent` (reads `sent` bytes and pulls `destination`,
`timestamp`, `message`). The decoder is intentionally minimal because
v0.1 only needed Note-to-Self to work.

That decision has now caught up to us. Three concrete problems:

1. **`decode_sync_sent` uses wrong proto field tags.** Our
   `MinimalSent` declares `message: tag = 1` and
   `destination_service_id: tag = 7`. The canonical
   `SyncMessage.Sent` shape (per Signal-Android / libsignal-service-java)
   has `message: DataMessage = 3`, `destination_service_id = 11`. The
   "minimal" decode happens to ignore the failures because every field
   is `optional`, so we silently return `None` from `decode_sync_sent`
   when the real fields don't match. Note-to-Self text from the phone
   round-tripped end to end in production smoke (decrypt succeeded,
   session committed, ACK sent) but never reached stdout because the
   decoder returned `None`.
2. **Sealed sender envelopes are skipped entirely.** `process_envelope`
   at `src/client.rs:763` matches on `envelope.r#type()`, handles
   `Ciphertext` and `PrekeyBundle`, and skips everything else
   including `UNIDENTIFIED_SENDER` (envelope.type = 6). The
   overwhelming majority of real Signal peer-to-peer traffic is
   sealed sender. Without this path wired up, signal-rs is structurally
   incapable of receiving most messages from contacts.
3. **No attachments, no rich DataMessage fields, no Receipt /
   Typing / Edit envelopes are surfaced.** Attachments are common on
   Signal; receipts are how a consumer knows their outbound landed;
   typing indicators are needed for the "show ... while a long
   operation is in flight" pattern documented as a Signal-vs-Telegram
   parity item in our second-brain reference doc.

The CLI also stops short of useful. `signal-rs receive` subscribes
to the broadcast channel and prints whatever `decode_content`
surfaces, which is currently almost nothing. `signal-rs send`
handles Note-to-Self and 1:1-by-ACI, not arbitrary E.164 recipients.

### Problem

signal-rs's library and CLI surface is too thin to be a real Signal
client. Specifically:

- Most real-world inbound messages are silently dropped (sealed sender
  skipped; SyncMessage decoder reads wrong proto field tags;
  attachments / receipts / typing / edits never surfaced).
- The outbound surface only sends Note-to-Self and 1:1-by-ACI.
- The CLI has no machine-readable output mode.
- The phone's Linked Devices UI shows "Unnamed device" because we
  send the device name in cleartext where the server expects it
  encrypted (it accepts the cleartext silently and substitutes the
  default).

### Goals

1. Replace hand-rolled minimal proto decoders with prost types
   generated from a vendored `SignalService.proto` from
   `libsignal-service-java`. Make the decode path honest.
2. Wire `libsignal_protocol::sealed_sender_decrypt` for
   `envelope.type = UNIDENTIFIED_SENDER`. Surface decoded sealed
   envelopes through the same `Envelope` enum.
3. Expand `Envelope` to carry the message-surface fields a consumer
   genuinely needs: source (ACI or E.164), source device, group id,
   attachments (as `AttachmentPointer` descriptors, not bytes),
   quote, edit-of-timestamp, expire-in-seconds, plus
   `Envelope::Receipt`, `Envelope::Typing`, and `Envelope::Edit`
   variants. Each variant `#[non_exhaustive]` so future additions
   stay non-breaking.
4. Add `Client::download_attachment(&AttachmentPointer, &Path)` that
   fetches from Signal's CDN, AES-CBC decrypts, verifies digest, and
   writes the plaintext to disk.
5. Expand `Client::send` to accept a `Recipient` enum with `SelfSync`
   (Note-to-Self via SyncMessage) and `Aci(String)` variants. The
   `Recipient` enum is `#[non_exhaustive]` so adding `E164` later
   when CDS lands is already a non-breaking change; we do NOT
   include a placeholder variant. Architect Round 1 finding 5:
   placeholder variants that always panic at runtime are footguns
   in a typed language.
6. Add `Client::send_with_attachments(Recipient, body, &[PathBuf])`
   that uploads to the CDN, builds `AttachmentPointer` descriptors,
   and includes them in the outbound `DataMessage`.
7. Add `Client::typing(Recipient, started: bool)` and
   `Client::delete_for_everyone(Recipient, target_timestamp: u64)`
   for the typing-indicator and remote-delete patterns called out in
   the second-brain reference doc.
8. Add `Client::status() -> ClientStatus { account, device_id, aci,
   pni, link_status, linked_devices: Vec<LinkedDevice> }`. The
   linked-devices list comes from a `/v1/devices` GET against the
   server.
9. CLI: `signal-rs receive --format=json|text` (defaults to `json` if
   stdout is not a TTY, `text` if it is). JSON mode emits one
   `Envelope` per line as a stable JSON schema. Text mode is human
   readable.
10. CLI: `signal-rs send --to aci:UUID|self --body TEXT
    [--attachment PATH ...]`. E.164 is not accepted as a `--to`
    value because CDS resolution is out of scope; the user is
    expected to read the contact's ACI from their phone or from a
    later synced-contacts list.
11. CLI: `signal-rs status` prints the `ClientStatus` to stdout
    (JSON or human depending on `--format`).
12. Encrypted device name during `/v1/devices/link`. Mirror
    `DeviceNameUtil.encryptDeviceName(name, aci_private_key)` from
    signal-cli so the phone shows "signal-rs" instead of "Unnamed
    device".
13. Pin libsignal at v0.94.1 (current pin) and keep it explicit in
    Cargo.toml. v0.94.1 is the latest tag in
    `~/repos/signalapp/libsignal`; no upgrade required for this doc.

### Non-Goals

- **Groups v2 internals.** Surfacing `group_id` on inbound messages
  is in scope; fetching encrypted group state, decrypting it,
  joining/leaving/admin actions, and sending to groups by id are not.
  v1 lets the consumer correlate messages by group; full group
  support is a v2 push.
- **Voice/video calls.** `CallMessage` envelopes (envelope.type = 7
  in `Content`'s union) are decoded but surfaced as a single opaque
  `Envelope::Call { raw: Vec<u8> }` variant so consumers can choose
  to ignore.
- **Stories, stickers, payments, sender-key distribution beyond the
  bare minimum libsignal does automatically.**
- **Account registration.** signal-rs only supports linking as a
  secondary device. Becoming a primary remains out of scope.
- **Daemon mode with JSON-RPC over a Unix socket** (signal-cli's
  shape). Consumers in Shape B (in-process Rust crate) don't need
  it. Re-evaluate if a non-Rust consumer materializes.
- **Reactions.** Confirmed out of scope this push.
- **Backfill / message history sync from primary.** Linked devices
  only see new envelopes after link; signal-rs does not request the
  primary's contact, group, or block list backfill.
- **E.164-to-ACI resolution via CDS (Contact Discovery Service).**
  An SGX-attested enclave call with Noise IK handshake,
  attestation verification, and batched lookup. Significant
  additional crypto. signal-cli has it; we land it in its own
  design doc. `Recipient::E164` is NOT added as a placeholder
  variant; `#[non_exhaustive]` already makes the future addition
  non-breaking (Architect Round 1 finding 5).

## Proposed Solution

### Overview

Vendor the canonical Signal protos, replace the hand-rolled
decoders, fan the decoded `Content` into a rich `Envelope` enum,
wire sealed sender, add attachment download + send-to-arbitrary +
typing + remote-delete + status, and round it off with a CLI surface
that emits JSON on a pipe.

### Architecture

```
                      Signal-Server
                       /          \
            chat WS   /            \  CDN HTTPS
        (authenticated)             (attachments)
                     /              \
              ┌─────▼────────────────▼─────┐
              │       Client (lib)         │
              │                            │
              │  receive() ──► Envelope    │ ◄── public surface
              │  send(Recipient, ...) ──► WS│
              │  download_attachment ─► CDN│
              │  typing / delete_for_everyone│
              │  status() ─► /v1/devices   │
              └────────────┬───────────────┘
                           │
                ┌──────────▼────────────┐
                │  process_envelope     │
                │   route by type:       │
                │   - Ciphertext         │
                │   - PrekeyBundle       │  ─► message_decrypt
                │   - UnidentifiedSender │  ─► sealed_sender_decrypt  (NEW)
                │   then decode Content  │
                │   via prost-generated  │
                │   SignalService types  │  ─► Envelope variants
                └────────────────────────┘
```

### Data Model

#### Public `Envelope` enum (replaces today's two-variant impoverished version)

```rust
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub enum Envelope {
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
    SyncMessage(SyncMessage),
    Receipt {
        kind: ReceiptKind,
        source: Recipient,
        timestamps: Vec<u64>,
    },
    Typing {
        source: Recipient,
        group_id: Option<Vec<u8>>,
        started: bool,
        timestamp: u64,
    },
    Edit {
        source: Recipient,
        timestamp: u64,
        target_sent_timestamp: u64,
        body: Option<String>,
    },
    Call {
        source: Recipient,
        raw: Vec<u8>,
    },
    /// Forward-compat escape hatch. Any decoded `Content` whose
    /// shape we don't yet map (new sync-subtype from the server,
    /// new envelope sub-message, etc.) surfaces here so consumers
    /// can log + skip without `process_envelope` silently dropping.
    Unknown {
        type_tag: String,
        raw: Vec<u8>,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub enum SyncMessage {
    Sent {
        destination: Option<Recipient>,
        group_id: Option<Vec<u8>>,
        timestamp: u64,
        body: Option<String>,
        attachments: Vec<AttachmentPointer>,
        edit_of_timestamp: Option<u64>,
        expire_in_seconds: Option<u32>,
    },
    Read {
        reads: Vec<ReadReceipt>,
    },
    // additional sync subtypes added later under #[non_exhaustive]
}

#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub enum Recipient {
    /// Note-to-Self: the destination of an outbound SyncMessage::Sent
    /// where source == destination == own_aci. Surfaced explicitly so
    /// consumers can filter for it without string-comparing.
    SelfSync,
    Aci(String),
    Pni(String),
    // E164(String) is intentionally NOT a variant. CDS-based E.164
    // resolution lands in its own design doc. `#[non_exhaustive]`
    // keeps that addition non-breaking.
}

#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub enum ReceiptKind {
    Delivery,
    Read,
    Viewed,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReadReceipt {
    pub sender: Recipient,
    pub timestamp: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Quote {
    pub id: u64,
    pub author: Recipient,
    pub text: Option<String>,
}
```

#### `AttachmentPointer`

```rust
#[derive(Debug, Clone, serde::Serialize)]
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
```

#### `ClientStatus`

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClientStatus {
    pub account_number: String,
    pub aci: Option<String>,
    pub pni: Option<String>,
    pub device_id: u32,
    pub link_status: LinkStatus,
    pub linked_devices: Vec<LinkedDevice>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LinkedDevice {
    pub id: u32,
    pub name: Option<String>,
    pub created: u64,
    pub last_seen: u64,
}
```

#### `/v1/devices` wire shape (consumed by `Client::status`)

Signal-Server's `DeviceController.java` returns a list of devices.
The serde-deserialized shape, verified against signal-cli's
`AccountsApi`:

```rust
#[derive(Debug, Deserialize)]
struct DeviceList {
    devices: Vec<RawLinkedDevice>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLinkedDevice {
    id: u32,
    name: Option<String>,
    last_seen: u64,
    created: u64,
}
```

Phase 8 fetches via authenticated `GET /v1/devices`, deserializes
this shape, maps each entry into a public `LinkedDevice`. The
`name` field is the base64'd encrypted-device-name payload (per
Phase 9); presented as-is until we add the
`decrypt_device_name(name, aci_identity_keypair)` helper.

### API Design

#### Library entry points

```rust
impl Client {
    pub async fn open(state_dir: &Path) -> Result<Self, OpenError>;
    pub fn receive(&self) -> broadcast::Receiver<Envelope>;
    pub async fn run_receive_loop(&self) -> Result<(), ReceiveError>;
    pub async fn send(&self, to: Recipient, body: &str) -> Result<u64, SendError>;
    pub async fn send_with_attachments(
        &self,
        to: Recipient,
        body: &str,
        attachments: &[PathBuf],
    ) -> Result<u64, SendError>;
    pub async fn download_attachment(
        &self,
        pointer: &AttachmentPointer,
        dest: &Path,
    ) -> Result<(), AttachmentError>;
    pub async fn typing(&self, to: Recipient, started: bool) -> Result<(), SendError>;
    pub async fn delete_for_everyone(
        &self,
        to: Recipient,
        target_timestamp: u64,
    ) -> Result<(), SendError>;
    pub async fn status(&self) -> Result<ClientStatus, StatusError>;
}
```

`send` and `send_with_attachments` return the outbound message
timestamp so the consumer can correlate the `Envelope::Receipt` that
arrives later.

#### CLI surface

```
signal-rs link [--name NAME]
signal-rs receive [--format json|text] [--once]
signal-rs send --to (aci:UUID|self) --body TEXT
              [--attachment PATH]...
signal-rs status [--format json|text]
signal-rs typing --to (aci:UUID|self) (--start|--stop)
signal-rs delete --to (aci:UUID|self) --target-timestamp MILLIS
signal-rs download --cdn-id N --cdn-number N --cdn-key BASE64
                   --key BASE64 --digest BASE64 --dest PATH
```

E.164 is intentionally not accepted as a recipient anywhere in
the CLI; see Non-Goals + Architect Round 1 finding 5.

`--format` defaults: `json` when stdout is not a TTY,
`text` when it is. Detected via `std::io::IsTerminal`. `--once`
does not change the default (it only changes how many envelopes
are emitted before exit).

JSON output is one `Envelope` per line, serialized via serde with
`#[serde(tag = "kind")]` discrimination. Receivers can pipe to `jq`
or write a `serde_json::from_str` loop. The
`docs/cli-json-schema.md` file documents the schema as it stabilises.

### Implementation Plan

Phases are sized so each ends with `otto ci` green and a commit. Each
phase delivers user-visible value; nothing leaves the receive path
worse than it found it.

#### Phase 1: Vendor SignalService.proto + replace decoders
**Model:** opus

- Fetch `SignalService.proto` from the active Turasa fork
  (`Turasa/libsignal-service-java` at tag
  `v2.15.3_unofficial_146`, the tag signal-cli pins via
  `signalnetwork`), path
  `lib/libsignal-service/src/main/protowire/SignalService.proto`.
  Place at `src/proto/service.proto`. The file header reads
  `SPDX-License-Identifier: AGPL-3.0-only`; the repo LICENSE is
  GPL-3.0; signal-rs is already `AGPL-3.0-or-later`, so compatible.
  Preserve the upstream copyright + SPDX header verbatim. The
  upstream `signalapp/libsignal-service-java` is archived; do not
  use it.
- Architect Round 1 finding 2 verification (done as part of this
  doc rev; field tags below were empirically read from the fetched
  v2.15.3_unofficial_146 .proto):
  - `Content.dataMessage = 1` ✓
  - `Content.syncMessage = 2` ✓
  - `Content.callMessage = 3`
  - `Content.receiptMessage = 5` ✓
  - `Content.typingMessage = 6` ✓
  - `Content.editMessage = 11`
  - `Content.storyMessage = 9`
  - `SyncMessage.Sent.message = 3` ✓
  - `SyncMessage.Sent.destinationServiceId = 7` (NOT 11 as
    earlier draft claimed; field 11 is `reserved /*destinationPni*/`)
  - `SyncMessage.Sent.destinationServiceIdBinary = 12` (the 16-byte
    binary form; prefer this over the string field where present,
    mirroring signal-cli)
  - `UnidentifiedSenderMessageContent` is the OUTER sealed-sender
    wrapper (used when `Envelope.type == UNIDENTIFIED_SENDER`); it
    is not a Content field. After `sealed_sender_decrypt_to_usmc`,
    `usmc.contents()` returns the inner serialized `Content` bytes
    which then decode as the normal Content above.
  The earlier draft of this doc named two of these wrong; the
  minimal-decoder bug we are fixing came from exactly this kind of
  unchecked memory, do not let it recur.
- Update `build.rs` to compile it alongside `envelope.proto` and
  `provisioning.proto`.
- Delete `decode_content`'s `TopLevelContent`,
  `MinimalDataMessage`, `MinimalSyncMessage`, `MinimalSent` from
  `src/client.rs`. Replace with the prost-generated
  `signalservice::{Content, DataMessage, SyncMessage}` types.
- Map prost types onto the new public `Envelope` enum
  (initially just `DataMessage` and `SyncMessage::Sent` populated
  end-to-end; receipts/typing/edit unimplemented but stubbed). The
  Note-to-Self body that round-tripped silently in production smoke
  must now appear on stdout.
- Acceptance: rerun the production smoke (`bin/relink` then send a
  Note-to-Self from the phone); the text must appear on stdout.
  Plus all existing tests pass.

#### Phase 2: Sealed sender decode
**Model:** opus

- Add `UNIDENTIFIED_SENDER` arm to the `proto::envelope::Type`
  match in `process_envelope`.
- Embed BOTH Signal production trust roots as a module-level
  `const TRUST_ROOTS: [PublicKey; 2]`. signal-cli's
  `lib/.../config/LiveConfig.java` ships them as
  `UNIDENTIFIED_SENDER_TRUST_ROOT` and
  `UNIDENTIFIED_SENDER_TRUST_ROOT2`; we copy both exact byte
  strings and cite the source. Architect Round 1 finding 1: a
  single trust root silently drops messages signed by the other
  root, defeating the entire phase.
- `libsignal_protocol::sealed_sender_decrypt` accepts only a
  single `trust_root: &PublicKey` (verified in
  `libsignal/rust/protocol/src/sealed_sender.rs`), so we cannot
  use the high-level wrapper. Instead:
  1. Call `sealed_sender_decrypt_to_usmc(ciphertext_bytes,
     identity_store).await?` to get a
     `UnidentifiedSenderMessageContent` (USMC) without validating
     the trust root.
  2. Pull `usmc.sender()?` to get the `SenderCertificate`. Validate
     it against ALL configured trust roots in one call using
     `SenderCertificate::validate_with_trust_roots(&[&r1, &r2],
     validation_time)` (verified in
     `libsignal/rust/protocol/src/sealed_sender.rs:331`). This is
     strictly safer than the iterate-and-short-circuit pattern the
     original draft sketched: libsignal's implementation walks every
     root in constant time via `subtle::Choice` to hide which root
     matched. Wrap the call in
     `crate::crypto::sealed::validate_against_trust_roots` so the
     decision is unit-testable independently of `process_envelope`.
  3. Self-send guard: if `sender_cert.sender_uuid() == local_service_id`
     and `sender_cert.sender_device_id() == local_device_id`, drop
     the envelope. This mirrors libsignal's high-level
     `SealedSenderSelfSend` return.
  4. Decrypt the inner `usmc.contents()?` payload via the same
     `libsignal_protocol::message_decrypt` path the unsealed branch
     uses, scoped to the destination identity (so it consumes ACI
     prekeys for ACI-destined sealed envelopes and PNI prekeys for
     PNI-destined sealed envelopes). Construct the inner
     `CiphertextMessage` from `usmc.msg_type()`:
     - `Whisper` -> `SignalMessage::try_from(usmc.contents()?)`
     - `PreKey`  -> `PreKeySignalMessage::try_from(usmc.contents()?)`
     - other -> warn + drop.
  5. Surface the result through the same `decode_content(plaintext,
     source, timestamp)` path the unsealed branch uses, passing
     `source = usmc.sender()?.sender_uuid()?` and
     `timestamp = wire.client_timestamp`. (The decoder was refactored
     to take source+timestamp as parameters in Phase 2 prep for
     exactly this reason; sealed envelopes carry no plaintext source
     on the wire.)
- Acceptance: send a 1:1 message from a non-primary peer (not the
  same phone) to our account via Signal app. Today's behaviour is
  silent drop (envelope skipped). After this phase, the message
  appears on stdout.
- Test: the multi-root validation lives in a pure helper
  (`crate::crypto::sealed::validate_against_trust_roots`); unit
  tests in `src/crypto/sealed/tests.rs` exercise BOTH trust roots
  (cert signed by root #1, cert signed by root #2) under BOTH
  orderings (roots listed [a, b] and [b, a]), to confirm the
  multi-root acceptance is order-independent. A
  `process_envelope`-level sealed-sender test would require full
  linked state + peer-prekey fixturing; following the precedent set
  by `route_envelope_to_identity` (extracted as a pure function for
  the same reason; see `src/client/tests.rs` comment), the multi-
  root concern is pinned at the helper boundary and the end-to-end
  path is covered by Phase 10's manual smoke.

#### Phase 3: Rich Envelope mapping (Receipt, Typing, Edit)
**Model:** sonnet

- Implement the `Content::receipt_message` -> `Envelope::Receipt`
  mapping (Delivery / Read / Viewed). The `ReceiptMessage` proto is
  small.
- Implement `Content::typing_message` -> `Envelope::Typing`.
- Implement `EditMessage` -> `Envelope::Edit`. Edit messages are an
  `EditMessage` wrapper around a `DataMessage` plus
  `target_sent_timestamp`.
- Implement `Content::call_message` -> `Envelope::Call { raw }`. We
  don't decode CallMessage internals; we surface it so consumers can
  choose to ignore.
- Implement `SyncMessage::Read` ->
  `SyncMessage::Read { reads: Vec<ReadReceipt> }`.
- Acceptance: all four envelope subtypes surface on stdout when
  exercised against the phone (read receipt by reading a message
  on the phone, typing indicator by starting to type, etc.).

#### Phase 4: Attachment download
**Model:** opus

- Add `attachments` field population to `DataMessage` and
  `SyncMessage::Sent` mapping.
- Add `Client::download_attachment(&pointer, &dest)`. Steps:
  1. GET the CDN URL based on `cdn_number`: cdn0 ->
     `https://cdn.signal.org/attachments/{cdn_id}`, cdn2 ->
     `https://cdn2.signal.org/attachments/{cdn_key}`, cdn3 ->
     `https://cdn3.signal.org/attachments/{cdn_key}`. signal-cli's
     `SignalServiceMessageReceiver.retrieveAttachment` is the
     reference.
  2. The downloaded blob has structure
     `IV(16) || ciphertext || HMAC(32)`. Split the 64-byte
     attachment key as `AES_KEY = key[0..32]`,
     `HMAC_KEY = key[32..64]`.
  3. Verify `HMAC-SHA256(HMAC_KEY, IV || ciphertext) == blob[blob.len()-32..]`.
  4. AES-256-CBC decrypt with PKCS#7 padding using AES_KEY and IV
     -> plaintext.
  5. Verify `SHA-256(blob) == pointer.digest`.
  6. Write plaintext to dest.
- Reference: signal-cli's `AttachmentCipherInputStream` for the
  cipher format; `SignalServiceMessageReceiver.retrieveAttachment`
  for the URL dispatch.
- Acceptance: receive an attachment from the phone; download it via
  `signal-rs download --cdn-id ... --cdn-key ... --cdn-number ...
  --key BASE64 --digest BASE64 --dest /tmp/x`; the bytes match what
  the phone sent.

#### Phase 5: Send to arbitrary ACI (sealed sender)
**Model:** opus

- Refactor `Client::send`'s signature: `pub async fn send(&self,
  to: Recipient, body: &str) -> Result<u64, SendError>`. Existing
  Note-to-Self path takes `Recipient::SelfSync` (sync-message
  via own ACI session, unchanged). New ACI peer path takes
  `Recipient::Aci(uuid)`.
- **Use sealed-sender encrypt for peer outbound, not the unsealed
  `message_encrypt`.** Architect Round 1 finding 2: a Signal
  client that sends unsealed messages to peers it has profile
  keys for is leaking sender identity to the server, a privacy
  downgrade vs. the official client. The sealed-sender encrypt
  flow:
  1. Fetch our own `SenderCertificate` from
     `GET /v1/certificate/delivery` (signal-cli pattern); cache
     it locally with its expiry. Refetch on expiry.
  2. Look up the recipient's profile key in our local store (today
     populated only from inline `DataMessage.profile_key` on inbound
     messages; `SyncMessage::Contacts` backfill is deferred per
     Non-Goals). If present, derive the unidentified-access key from
     it and proceed with sealed-sender encrypt (step 4). If absent,
     skip steps 3-5 entirely and fall back to the unsealed
     `message_encrypt` path with a `warn!` log that sender identity
     is leaking to the server. This is signal-cli's best-effort
     posture (see `UnidentifiedAccessHelper.getAccessFor` returning
     `@Nullable`). Strict mode is Future Work; see Risks row.
     Device-list discovery is lazy: the hot path encrypts to whatever
     devices we already have sessions for, and the server's
     `MismatchedDevices` 409 response (handled below) is what surfaces
     additions / removals. This matches signal-cli's
     `MessageSender.sendMessage` pattern. An eager
     `GET /v1/profile/{aci}` per send would just burn an RTT on the
     steady state; the 409-driven refetch is correct on the transient
     and free on the steady state.
  3. Fetch missing prekey bundles via libsignal-net-chat's
     `UnauthenticatedChatApi::get_pre_keys(aci, AllDevices)` — same
     server-side endpoint as `GET /v2/keys/{aci}/*`, tunnelled over
     the unauth chat websocket rather than a parallel REST client.
     Run `process_prekey_bundle` for each device we don't have a
     session with.
  4. For each of the peer's `ProtocolAddress`es, call
     `libsignal_protocol::sealed_sender_encrypt(remote_address,
     &sender_certificate, content_bytes, &mut session_store,
     &mut identity_store, rand)` to produce a
     `UnidentifiedSenderMessageContent`-wrapped ciphertext.
  5. PUT the sealed payloads to
     `PUT /v1/messages/{aci}?unidentified=true` with the
     unidentified-access key in the `Unidentified-Access-Key`
     header (the request is not authenticated with our device
     credentials in the sealed-sender case).
- Handle `MismatchedDevices` (HTTP 409) and `StaleDevices` by
  refetching the device list / specific bundles and retrying once.
  signal-cli's `MessageSender.sendMessage` is the canonical
  retry loop.
- Note-to-Self stays on the unsealed sync-message path: it's our
  own account sending to itself, so leaking "we sent" to the
  server is structurally unavoidable and not a privacy regression.
- Update CLI `send` subcommand: `--to aci:UUID|self`. E.164 sends
  are rejected at clap parse time (no `Recipient::E164` variant
  exists per finding 5).
- Acceptance: send a text to a known peer ACI (a contact whose
  ACI you can read off the phone's contact-details screen); the
  contact receives it; the server log (if we had access) would
  show no sender identity bound to the outbound envelope.

#### Phase 6: Send attachments
**Model:** opus

- Upload to Signal's attachment CDN. Use libsignal-net-chat's
  `AuthenticatedChatApi::get_upload_form(ciphertext_len)`, which
  hits `GET /v4/attachments/form/upload` server-side (`/v3` is
  legacy / removed from current Signal-Server; `/v4` is what
  signal-android and signal-cli use today). The form returns
  `{cdn: 2|3, key, headers, signed_upload_url}`; dispatch the
  byte upload by cdn:
  - cdn=2 (GCS resumable): POST `signed_upload_url` with the
    form's headers (which include `x-goog-resumable: start`) and
    `Content-Length: 0`. GCS returns 201 with a `Location` header
    pointing at the actual resumable session URI. PUT the bytes
    there with `Content-Type: application/octet-stream`.
  - cdn=3 (TUS): POST `signed_upload_url` with the form's headers
    plus `Tus-Resumable: 1.0.0`, `Upload-Length: N`, and
    `Content-Length: 0`. The server responds with a `Location`
    header for the upload resource. PATCH the bytes with
    `Upload-Offset: 0`, `Content-Type:
    application/offset+octet-stream`, `Tus-Resumable: 1.0.0`.
- Bucket-pad the plaintext before encrypt with signal-cli's
  `PaddingInputStream.getPaddedSize` formula:
  `max(541, floor(1.05^ceil(log_1.05(size))))`. The outer step is
  `floor`, not `ceil` — `ceil` would put every signal-rs
  ciphertext one byte above the canonical bucket and let a
  passive observer fingerprint our traffic on the CDN.
- AES-256-CBC + HMAC-SHA256 encrypt the padded plaintext to
  produce the wire blob `IV(16) || ciphertext || HMAC(32)`. The
  64-byte attachment key is `AES_KEY(32) || HMAC_KEY(32)`. Digest
  is `SHA-256(blob)`.
- Build `AttachmentPointer` from the upload result (cdn_id,
  cdn_key, cdn_number, digest, key, **unpadded** `size`) and
  include in outbound DataMessage's `attachments` repeated field.
- Side-fix Phase 4 download: truncate the decrypted plaintext to
  `pointer.size` before writing dest, so our own receive path
  doesn't write the zero pad to disk now that we bucket-pad on
  send.
- New `Client::send_with_attachments` API.
- Update CLI `send --attachment PATH` (may be repeated).
- Acceptance: send a text+attachment from CLI; phone receives the
  attachment with the correct caption and bytes.

#### Phase 7: Typing + remote delete
**Model:** sonnet

- `Client::typing(Recipient, started)`: build a `TypingMessage`
  proto with the `started` action (the proto carries `timestamp`,
  `action`, and optional `groupId` only; the target ACI is the
  *envelope* recipient, not a field on `TypingMessage` itself - an
  earlier draft of this bullet mistakenly named a "target service id"
  field that does not exist in `service.proto`). Encrypt + send
  through the same sealed-sender peer dispatch path as
  `Client::send` (typing rides the DataMessage encryption flow; it
  differs only in the Content oneof variant carried inside).
- `Client::delete_for_everyone(Recipient, target_timestamp)`:
  build a `DataMessage` with the `delete: Delete { target_sent_timestamp }`
  field set, no body, no attachments. Two-step dispatch:
  1. Send the bare DataMessage to the peer's devices via the same
     sealed-sender peer dispatch path used by `Client::send`.
  2. **After the peer dispatch succeeds**, also wrap that same
     DataMessage in a `SyncMessage::Sent { destination =
     <peer-ACI>, message = <delete-DataMessage> }` and dispatch
     to the user's own OTHER linked devices via `send_sync_message`.
     Without this second step the message vanishes from the peer's
     phone but stays visible on the user's own iPad / desktop -
     signal-cli and signal-android both fire this sync; an earlier
     revision of this bullet missed it (caught by Architect Round 3,
     post-Phase-7 implementation audit).
     The sync is **best-effort**: if the sync dispatch fails, the
     peer delete has already landed and returning Err to the caller
     would be misleading; instead `warn!` and continue. The user can
     trigger a manual re-sync later (sync-mechanism for that is
     post-v1 Future Work).
- CLI: `signal-rs typing --to ... --start|--stop`.
- CLI: `signal-rs delete --to ... --target-timestamp ...`.

#### Phase 8: status + CLI polish
**Model:** sonnet

- `Client::status() -> ClientStatus`: pull account, device_id,
  aci, pni, link_status from local store; do a `GET /v1/devices`
  for the linked-devices list.
- CLI `signal-rs status [--format json|text]`.
- CLI `signal-rs receive --format json|text [--once]`. JSON mode
  is one `Envelope` per line. Text mode is human-readable. Default
  determined by `std::io::IsTerminal` on stdout.
- Acceptance: `signal-rs receive | jq` works; `signal-rs receive`
  on a TTY shows readable output; `signal-rs status` works in both
  modes.

#### Phase 9: Encrypted device name
**Model:** opus

- Read signal-cli's
  `lib/.../util/DeviceNameUtil.encryptDeviceName(deviceName, identityKeyPair)`
  end-to-end before writing Rust. The algorithm uses the ACI
  IdentityKeyPair, generates an ephemeral curve25519 keypair, does
  ECDH between the ephemeral private and the ACI public key,
  derives a 32-byte AES key + a synthetic IV via HKDF, AES-CTR
  encrypts the name bytes, and packages the result as a protobuf
  `DeviceName { ephemeralPublic, syntheticIv, ciphertext }` then
  base64-encodes the whole thing. Write the Rust version to match
  exactly; do not paraphrase the algorithm from memory.
- Vendor a tiny `device_name.proto` (just `DeviceName { ephemeralPublic
  = 1, syntheticIv = 2, ciphertext = 3 }`).
- Pass encrypted name in `LinkDeviceRequest::accountAttributes::name`
  (or wherever the link PUT carries it).
- Test: round-trip encrypt + decrypt against a known keypair before
  shipping. The decrypt direction is also in
  `DeviceNameUtil.decryptDeviceName` if we need to cross-check.
- Acceptance: relink; phone's Linked Devices UI shows "signal-rs"
  (or whatever `--name` was) instead of "Unnamed device".

#### Phase 10: Smoke + ship
**Model:** opus

- Wipe, relink, exercise: send Note-to-Self, send to a contact,
  receive a text, receive an attachment, download the attachment,
  receive a read receipt, see typing indicator while typing on the
  phone.
- Mark design doc Status: Implemented.
- Commit, bump (minor: feature additions), push.

## Alternatives Considered

### Alternative 1: Keep hand-rolled minimal decoders, just fix the field tags

- **Description:** Patch `MinimalSent`'s `message: tag=3` and
  `destination_service_id: tag=11`, leave the rest of the
  architecture unchanged. Add new minimal structs for each new
  field we want to surface.
- **Pros:** Smallest possible change to ship a working
  Note-to-Self.
- **Cons:** Every field we add later needs another hand-roll. We
  remain blind to whatever fields we haven't decided to decode.
  Sealed sender, attachments, receipts, edits all need the same
  multi-step rebuild. We pay the proto-correctness tax incrementally
  instead of once.
- **Why not chosen:** Buys a day, costs a year. The vendored proto
  path is straightforward and locks in correctness.

### Alternative 2: Run signal-cli as an out-of-process daemon and shell out from signal-rs

- **Description:** Don't be a Signal client. Be a CLI wrapper over
  signal-cli's JSON-RPC.
- **Pros:** Inherits signal-cli's full feature coverage instantly.
- **Cons:** Adds JVM runtime dependency. Out-of-process boundary.
  Loses Shape B integration (consumer-in-process Rust crate).
  Contradicts the entire point of signal-rs existing.
- **Why not chosen:** signal-rs's reason for being is "Rust-native
  Signal client without the JVM tax."

### Alternative 3: Use presage

- **Description:** Use `whisperfish/presage` as the underlying
  client; expose a thinner signal-rs surface that wraps it.
- **Pros:** Inherits presage's existing message-surface coverage.
- **Cons:** presage has its own API design that doesn't match ours.
  Their public types would leak through. Less control over wire
  behaviour. presage's group v2 history (the weakest spot per the
  second-brain reference doc) is exactly where we'd be most
  exposed.
- **Why not chosen:** We're far enough along on our own
  implementation that the cost of switching exceeds the cost of
  building the remaining message-surface ourselves.

## Technical Considerations

### Dependencies

- libsignal-protocol / libsignal-net / libsignal-net-chat: pinned at
  v0.94.1, the current latest. No upgrade needed.
- New: vendored `src/proto/service.proto` from
  `libsignal-service-java`. prost-build already in tree.
- New crate-level: `aes` + `cbc` + `hmac` + `sha2` for attachment
  AES-CBC decrypt (already in tree from provisioning crypto, reuse).
- `serde_json` for the JSON `--format` output path.
- `std::io::IsTerminal` for tty detection.

### Performance

- `Content` decode is a one-time parse per envelope; the
  prost-generated path is faster than the hand-rolled one we have
  today (no double-parsing of inner bytes).
- Sealed sender decrypt adds one more crypto operation per
  envelope of `type=6`. Per-message cost is negligible compared to
  network RTT.
- Attachment download is a single CDN GET; bandwidth-bound, not
  CPU-bound. Decrypt is AES-CBC over a single buffer.

### Security

- Sealed sender decrypt: libsignal does the heavy lifting. Our
  job is to call the right function and trust its output.
- Attachment download: must verify the SHA-256 digest in the
  `AttachmentPointer` matches the decrypted plaintext, refuse to
  hand back bytes on mismatch (`AttachmentError::DigestMismatch`).
- Send-to-E.164: profile lookup is an unauthenticated endpoint
  that takes a phone number; nothing leaks beyond what was already
  in scope (we send a number, we get back a service id).
- Encrypted device name: removes the cleartext-name leak we have
  today (the phone shows the name; the server sees it).

### Testing Strategy

- **Unit tests:**
  - `process_envelope` routing tests already cover the kind-decision;
    extend with `process_envelope_decodes_sealed_sender_to_data_message`.
  - `decode_content` mapping tests for each `Envelope` variant
    against synthetic `Content` protobuf bytes (use prost to encode
    a fixture, feed through, assert the variant).
  - `download_attachment_verifies_digest` with a known
    plaintext + key + iv + digest test vector.
  - `send_resolves_e164_to_aci_then_sends` with a recording fake
    over the `api` module's HTTP layer.
  - `encrypt_device_name` round-trip test against a fixed RNG.
- **Integration tests:** the existing
  `link_persists_aci_and_pni_batches_without_collision` pattern,
  extended to cover an Envelope round-trip through `process_envelope`.
- **Smoke (Phase 10):** wipe, relink, exercise every Envelope
  variant via real phone traffic.

### Rollout Plan

- Phases land as separate commits; each ends with `otto ci` green.
- After Phase 9 ships, design doc Status -> Implemented; cut a
  release. v0.94.1 of libsignal stays pinned; if a libsignal bump
  is needed mid-stream we surface that as a separate decision.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| libsignal-service-java's SignalService.proto drifts away from what Signal-Server actually sends | Low | High | Pin the vendored proto file with a hash/version comment; cross-check against signal-cli's bundled copy at the time of vendoring; renew when bumping libsignal. |
| Sealed sender uses TWO trust roots concurrently; libsignal's high-level wrapper only accepts one | High | High | Phase 2 bypasses `sealed_sender_decrypt` and uses `sealed_sender_decrypt_to_usmc` + manual `SenderCertificate::validate` against an iterator of trust roots from `signal-cli/.../LiveConfig.java`. Architect Round 1 finding 1. |
| Sealed sender decrypt needs a server-provided sender certificate we don't have today | Low | Med | Phase 2 unwraps the `SenderCertificate` from the USMC itself; nothing fetched. |
| Sealed-sender SEND path requires our own `SenderCertificate` + recipient profile-key lookup | Med | High | Phase 5 fetches our cert via `GET /v1/certificate/delivery` and caches with expiry; profile-key lookup is from local store (populated from inbound `DataMessage.profile_key` on prior peer messages). signal-cli `MessageSender`/`ProfileService` is the reference. Without this, peer sends leak identity to the server (Architect Round 1 finding 2). |
| Attachment CDN URL format / CDN authentication changes | Low | Med | Phase 4 mirrors signal-cli's `AttachmentHelper.retrieveAttachment` exactly; cross-check `cdn0`, `cdn2`, `cdn3` paths against `cdn_number`. |
| Multi-device peer fan-out: a peer with multiple linked devices needs one ciphertext per device, plus a `MismatchedDevices` retry path when our cached device list goes stale | Med | Med | Phase 5 generalises today's send_to_aci multi-device pattern. Explicit handling for HTTP 409 `MismatchedDevices` to refetch and retry once. signal-cli's `MessageSender` is the reference. |
| Phase 5 sealed-sender encrypt path falls back to unsealed when we lack a profile key | Med | Med | Best-effort policy mirroring signal-cli's `UnidentifiedAccessHelper.getAccessFor` (returns @Nullable; null falls through to unsealed): try sealed sender first; if no profile key on file, fall back to unsealed `message_encrypt` and emit `warn!("sealed-sender unavailable for {recipient}, falling back to unsealed; sender identity leaks to server")`. v1 has no profile-key source besides inline `DataMessage.profile_key` (contacts backfill from `SyncMessage::Contacts` is explicitly deferred per Non-Goals), so a strict refuse policy would gate Goal 5 on a deferred feature. Strict-only mode (refuse-on-missing-profile-key) lands in Future Work once profile-key sync is implemented. Architect Round 2 consensus. |
| Encrypted device name implementation diverges from signal-cli and the phone shows garbage | Low | Low | Phase 9 starts by writing a test against signal-cli's encrypt + an independent decrypt to confirm round-trip; ship only after that passes. |
| Receive output JSON schema needs to change mid-development | Med | Low | `#[non_exhaustive]` on every variant + serde with explicit `#[serde(tag = "kind")]` means adding fields/variants is non-breaking. Document the schema in `docs/cli-json-schema.md` as it stabilises. |

## Future Work

Items deliberately deferred past this push but flagged for follow-up
work, with the trigger that unblocks each one.

- **Strict sealed-sender mode** — `Client::send_strict` (or a
  `strict_sealed_sender: bool` config flag) that refuses to send when
  no profile key is on file, instead of falling back to unsealed.
  Trigger: profile-key sync from `SyncMessage::Contacts` lands and
  signal-rs has reliable profile-key coverage for the address book.
  Becomes the default once coverage is broad enough that refusing is
  a sane default rather than a footgun. Architect Round 2 consensus.

- **`SyncMessage::Contacts` consumption** — decode the contacts-list
  backfill payload that the primary device pushes on link. Today
  it's explicitly a Non-Goal of this push. This is the unblocker for
  the strict sealed-sender mode above, and also the source of
  profile keys for contacts the user hasn't yet received a message
  from.

- **CallMessage internals** — Phase 3 surfaces `Envelope::Call { raw
  }` without decoding. If a consumer needs call signalling, decode
  the inner `CallMessage` proto.

## References

Code in this repo:

- `src/lib.rs` (public surface)
- `src/client.rs::process_envelope`, `decode_content`,
  `decode_data_message_body`, `decode_sync_sent` (the decoders this
  doc replaces)
- `src/envelope.rs` (current impoverished public types)
- `src/proto/envelope.proto`, `src/proto/provisioning.proto`
  (existing vendored protos; this doc adds `service.proto`)
- `build.rs` (proto compilation; this doc extends it)

Reference implementations:

- `signalapp/libsignal-service-java` (canonical `SignalService.proto`
  source). Online at
  https://github.com/signalapp/libsignal-service-java/blob/main/protobuf/src/main/proto/SignalService.proto
- `signalapp/libsignal/rust/protocol/src/proto/service.proto` (the
  minimal Content wrapper from libsignal itself; we vendored
  envelope.proto previously from here)
- `AsamK/signal-cli`:
  - `MessageSender` (send-to-arbitrary, attachment upload)
  - `AttachmentHelper.retrieveAttachment` (CDN download +
    AES-CBC decrypt)
  - `DeviceNameUtil.encryptDeviceName` (encrypted device name)
  - `ProfileService.getProfileByE164` (E.164 -> service id)
- `signalapp/Signal-Server/service/.../grpc/MessagesAnonymousGrpcService.java`
  (sealed sender wire shape, referenced by the per-identity prekey
  design doc's Round 2 Architect verification)

Reference docs:

- `~/repos/scottidler/second-brain/docs/signal-as-borg-transport.md`
  (the functional-equivalence target; what borg expects from any
  Signal transport)
- `~/repos/scottidler/second-brain/docs/signal-rs-consumer-integration-handoff.md`
  (the consumer's usage shape; signal-rs surfaces what this doc
  describes)
- `docs/design/2026-05-22-signal-rs-v0.1-design.md` (the original
  v0.1 design; this doc supersedes its "v0.1 surfaces just body +
  timestamp" limitations)
- `docs/design/2026-05-23-per-identity-prekey-storage.md` (the
  per-identity prekey + identity-keypair fix landed immediately
  before this work)
