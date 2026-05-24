# Phase 10 Manual Smoke Test Runbook

This runbook drives `signal-rs` against real Signal servers end to end:
link as a secondary device, receive a Note-to-Self from the phone,
send a Note-to-Self from `signal-rs` back to the phone, and capture
the artifacts needed to un-`#[ignore]` the Phase 4 known-vector test.

Every step states:

- the exact command to run,
- the output you should see if it works,
- the failure modes most likely to surface,
- what to capture and hand back for a fix if it fails.

The most likely class of failure is a server-side 4xx on a wire format
that compiles cleanly but does not match what Signal-Server actually
expects. When that happens, capture the failing log line plus the HTTP
status and request body and feed it back as a fix request.

## Prerequisites

- A Signal account on a phone, with that phone acting as the primary
  device. Note the account's E.164 number; you will use it in the
  send step.
- A clean state directory. Default platform paths apply:
  - Linux: `~/.local/share/signal-rs/`
  - macOS: `~/Library/Application Support/signal-rs/`
- `signal-rs` installed and on `$PATH`. Build from the working tree:
  ```
  cargo install --path .
  ```
- A terminal with enough vertical space to render a QR code (roughly
  60 lines). The QR uses Unicode block characters; a monospace font
  is required.

## Logging

All log output goes to `~/.local/share/signal-rs/logs/signal-rs.log`
(or the macOS equivalent). Stdout shows only the user-facing prompts
and the final result line. **Tail the log file in a separate terminal
for the entire smoke session:**

```
tail -F ~/.local/share/signal-rs/logs/signal-rs.log
```

Run every `signal-rs` command with `--log-level debug` so per-function
entry/exit logs land in the file. Without DEBUG the first failure
will be hard to diagnose.

## Step 1: Clean slate

If a prior smoke session left state behind, wipe it.

```
rkvr rmrf ~/.local/share/signal-rs
```

`rkvr` archives the directory so you can recover it if needed. Do
NOT use `rm -rf` here.

Confirm the directory is gone:

```
ls -la ~/.local/share/signal-rs
# ls: cannot access ...: No such file or directory
```

## Step 2: Link as a secondary device

In **terminal 1**, start the link flow:

```
signal-rs --log-level debug link --name "signal-rs-smoke"
```

**Expected output (stdout):**

```
Scan this with your primary device (Settings -> Linked Devices):

  ██  ██████  ██  ██████  ██████  ██████  ██  ██████
  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██  ██
  ...
  (QR code, roughly 50 lines)
  ...

Or manually copy: sgnl://linkdevice?uuid=...&pub_key=...

linked: account=+1XXXXXXXXXX device_id=2
```

**On the phone:** open Signal -> Settings -> Linked Devices -> Add a
new device (the + button) -> point the camera at the QR.

**What happens internally:**

1. `signal-rs` opens a provisioning WebSocket to `chat.signal.org`.
2. The server pushes a `ReceivedAddress` event; `signal-rs` renders
   the `sgnl://` URI as a QR.
3. The phone scans the QR, generates the cryptographic handshake,
   pushes a `ReceivedEnvelope` event back through the server.
4. `signal-rs` decrypts the envelope (Phase 4 ProvisioningCipher),
   persists the identity, calls `PUT /v1/devices/{provisioningCode}`
   to register, calls `PUT /v2/keys/?identity=aci` and (if PNI keys
   present) `PUT /v2/keys/?identity=pni` to upload the initial prekey
   batches, transitions `link_status` to `Linked`.

**Failure modes by step:**

| Symptom in stdout / log | Probable cause | Capture for fix |
|---|---|---|
| Timeout waiting for `ReceivedAddress` | Provisioning WebSocket couldn't establish; check `chat.signal.org` reachability | full log file |
| Timeout waiting for `ReceivedEnvelope` | QR scan never happened, or phone errored out silently | retry from step 1 |
| `ProvisioningCipherError::MacMismatch` or similar | ProvisioningCipher port bug; the encrypted envelope failed integrity check | full log file, the printed QR content, screenshot of phone's "Adding device" step |
| `DeviceCompletion(server returned 4xx)` with HTTP 400 | PUT `/v1/devices/{code}` JSON body shape wrong | log lines around `complete_device_registration`, the JSON body if printable |
| `Prekey(Upload(server returned 4xx))` | PUT `/v2/keys/?identity=aci` JSON body shape wrong | log lines around `upload_keys_for_identity`, the JSON body printed by `prekey_upload_body_*` test snapshot for comparison |
| `Prekey(Upload(server returned 4xx))` after ACI succeeds, before PNI | PNI prekey upload differs from ACI in some way | same as above, plus note the difference is PNI-only |

**Verification on success:**

```
sqlite3 ~/.local/share/signal-rs/store.db \
  "SELECT key, hex(value) FROM identity WHERE key IN ('account_number','aci','device_id','link_status')"
```

Expected:
- `account_number` matches your phone's E.164 in hex
- `aci` is a UUID string
- `device_id` is 2 or higher (1 is the phone)
- `link_status` decodes to `Linked`

On the phone: Settings -> Linked Devices should show a new entry
named "signal-rs-smoke" with the current timestamp.

## Step 3: Start the receive loop

In **terminal 1** (or a fresh terminal):

```
signal-rs --log-level debug receive
```

**Expected log lines (in the tail):**

```
Client::open: opened state_dir=... account=+1XXX device_id=2
connect_endpoint: env=Production endpoint_path=/v1/websocket/ ...
connect_endpoint: established (endpoint_path=/v1/websocket/, log_tag=auth-chat)
run_receive_loop: authenticated chat connected, entering event loop
```

Then silence (no events yet). Leave this running.

**Failure modes:**

| Symptom | Probable cause | Capture |
|---|---|---|
| WebSocket connect error 401 | Auth headers wrong: aci.device_id or password mismatch | log lines around `connect_chat_authenticated`, the auth header value (without the password itself) |
| WebSocket connects then immediately closes with `Stopped` | Server rejected the auth after the upgrade | full log file |
| Connects but never logs anything else | Listener thread isn't draining the ws channel; this is a code bug, not a wire bug | full log file with line numbers |

## Step 4: Send a message from the phone to Note to Self

On the phone, open the Note to Self conversation. Send a recognizable
test message:

```
phase10-smoke-test-001
```

**Expected log lines (in terminal 1's tail):**

```
process_envelope: envelope type=Ciphertext ...
TxStore::store_session: address=<your_aci>.1
run_receive_loop: ACK'd envelope after decrypt
```

If `signal-rs receive --once` mode is used, stdout prints the decoded
envelope:

```
Envelope::SyncMessage(SyncMessage::Sent {
    destination: "+1XXXXXXXXXX",
    timestamp: 1234567890123,
    message: DataMessage {
        body: Some("phase10-smoke-test-001"),
        ...
    },
})
```

The `destination` field equals your phone's E.164. The body is the
text you typed. This is the load-bearing surface: `borg` filters on
`destination == own_number` to identify Note-to-Self.

**Failure modes:**

| Symptom | Probable cause | Capture |
|---|---|---|
| Receive loop logs nothing despite messages on phone | Server isn't routing to this device, or the listener didn't connect | full log, check phone's Linked Devices shows the entry as recently active |
| `process_envelope: dropping envelope after decrypt failure` | Session state desync, identity mismatch, or PreKey session bootstrap failed | the WARN line including the peer address, full log around the failure |
| Decoded envelope has empty `body` | DataMessage proto decode missed the body field (encoding bug, not protocol bug) | the decoded envelope dump, the raw plaintext if dumpable |
| `destination` is missing or wrong | SyncMessage::Sent proto decode bug | same |

## Step 5: Send a message from signal-rs to the phone

In **terminal 2** (while terminal 1's receive loop is still running):

```
signal-rs --log-level debug send +1XXXXXXXXXX "phase10-smoke-from-signal-rs"
```

Use **your own E.164** as the target. Any other number returns
`SendError::TargetUnsupported`; CDSI lookup is out of v0.1 scope.

**Expected:**

- stdout: `send: dispatched to +1XXXXXXXXXX`
- The phone's Note to Self conversation receives
  `phase10-smoke-from-signal-rs` as if you had sent it from another
  linked device. It appears with no special UI marking; that is
  correct.

**What happens internally:**

1. `Client::send` detects the target equals own E.164, routes to
   `send_note_to_self`.
2. `send_note_to_self` checks for existing sessions with own_aci's
   other devices. If none, fetches all device bundles via
   `UnauthenticatedChatApi::get_pre_keys(own_aci, AllDevices)` using
   the access-key derived from the persisted profile-key, filters out
   self.device_id, processes each bundle into a session inside a
   `TxStore`-backed `sqlx::Transaction`.
3. Encrypts the payload to each other device, builds
   `SingleOutboundUnsealedMessage` per device, calls
   `AuthenticatedChatApi::send_sync_message`.

**Failure modes:**

| Symptom | Probable cause | Capture |
|---|---|---|
| `Server: get_pre_keys: ...` 401 / 403 | access-key derivation wrong, or own_aci isn't recognized | the log line, the (redacted) access-key bytes if dumpable |
| `Server: process_prekey_bundle: ...` | Bundle from server doesn't match libsignal-protocol's expectations | full bundle decode log, libsignal error |
| `Server: send_sync_message: ...` with mismatched-devices | Our device list is stale (a device was added since we linked) | the error variant, list of expected vs sent devices |
| Phone never receives the message | Send returned Ok but server didn't fan out; check phone's Note to Self conversation manually | the full send log, time-stamp the moment of send for correlation |

## Step 6: Verify replenishment (longer-running)

Send several more messages from the phone to Note to Self (one per
minute, ~5 of them). Watch the log for `maybe_replenish_one_identity`
entries on QueueEmpty events.

```
maybe_replenish_one_identity: identity=Aci server_count(ec=98, pq=99) watermark=25
```

If `ec` ever drops below 25, the next QueueEmpty triggers a
replenishment:

```
maybe_replenish_one_identity: refilled identity=Aci starting at id=...
```

Realistically the server count will not drop below 25 during a smoke
test (you would need ~75 incoming PreKey-bundle sessions, one per
unseen peer). The log line confirms the count query succeeded; that
is the actual verification.

**Failure modes:**

| Symptom | Probable cause |
|---|---|
| `get_available_prekey_count: server returned 4xx` | GET `/v2/keys/?identity=aci` URL shape or response JSON shape wrong |
| `get_available_prekey_count` succeeds but logs `count=0 pq=0` indefinitely | initial prekey upload (step 2) never actually persisted on the server |

## Step 7: Capture the Phase 4 known-vector fixture (optional)

The test `crypto::provisioning::tests::known_vector` is currently
`#[ignore]` because it requires a real (encrypted envelope, ephemeral
keypair) pair from a live link. Capturing one converts that test
from ignored to runnable forever.

This requires a one-line code change to dump the bytes during
linking, then re-running the link flow once to capture the artifact.

In `src/link.rs::drive_provisioning_handshake`, add a debug dump just
before `decrypt_envelope` is called:

```rust
// Phase 4 known-vector capture: dump the (keypair, envelope) pair
// to a file once, then revert this edit. Used to un-ignore
// crypto::provisioning::tests::known_vector.
if std::env::var("SIGNAL_RS_CAPTURE_FIXTURE").is_ok() {
    let dump = serde_json::json!({
        "keypair_private": hex::encode(keypair.private_key_bytes()),
        "keypair_public": hex::encode(keypair.public_key_bytes()),
        "envelope": hex::encode(&envelope_bytes),
    });
    std::fs::write("/tmp/known-vector.json", dump.to_string())
        .expect("dump");
}
```

Then:

1. Wipe state: `rkvr rmrf ~/.local/share/signal-rs`
2. Run with the env var: `SIGNAL_RS_CAPTURE_FIXTURE=1 signal-rs --log-level debug link --name fixture-capture`
3. Scan from the phone (this consumes the phone's link slot; you may
   want to unlink an old one first).
4. After the link completes, `/tmp/known-vector.json` exists.
5. Move it to `src/crypto/provisioning/tests/fixtures/known-vector.json`.
6. Revert the debug dump edit.
7. Update `crypto::provisioning::tests::known_vector` to load the
   fixture and remove the `#[ignore]`.
8. Commit the fixture and the test change.

The fixture is reusable forever; once captured, every test run can
prove the ProvisioningCipher port still decodes a real Signal-issued
envelope correctly.

## Step 8: Unlink and clean up

On the phone: Settings -> Linked Devices -> tap the `signal-rs-smoke`
entry -> Unlink.

In terminal 1, the receive loop logs:

```
run_receive_loop: chat connection stopped: LocalDisconnect
```

and exits with `Err(ReceiveError::Stopped("LocalDisconnect"))`. That is
the expected end-of-smoke state.

Wipe the state directory if you want a clean slate for the next
smoke:

```
rkvr rmrf ~/.local/share/signal-rs
```

## When a wire format fails

The dominant failure class will be: a PUT or GET that compiles cleanly
but Signal-Server returns 4xx because a field name, casing, or payload
shape is wrong. Recovery procedure:

1. Capture the full log line including the HTTP status and response
   body from `ApiError::Server { status, body }`.
2. Capture the request body. The snapshot tests in `src/api.rs`
   (`prekey_upload_body_serializes_to_expected_camel_case_shape`,
   `prekey_upload_body_from_real_records_serializes_correctly`) print
   the JSON we send for the prekey upload; run them with
   `cargo test --lib prekey_upload_body -- --nocapture` to see what
   we are emitting.
3. For the device-completion PUT, dump `DeviceAttributes` from
   `src/api.rs::complete_device_registration` if needed.
4. Compare against the Signal-Server documented schema or signal-cli's
   wire output.
5. File the diff as a fix request. The fix is usually a one-line
   serde rename or an `Option`-vs-required field flip.

After applying the fix, you do not need to re-link unless the failure
was in step 2 (linking itself). Receive and send can be retried
against an existing linked state.

## When you are done

Once the link, receive, and send loops all succeed end to end:

1. The implementation is validated against real Signal infrastructure.
2. You can cut the next release tag (`v0.1.1` or whichever bump is
   appropriate), which is the actual loop-validated release per the
   design doc's Phase 10.
3. Any further fixes for the architect's v0.2 items
   (MismatchedDevices retry, one-time PQ prekey replenishment,
   combined-PUT link) become genuine follow-up work rather than
   gating the first real consumer.
