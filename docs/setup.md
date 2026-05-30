# Setup: standing up signal-rs from scratch

This is the end-to-end, gotcha-aware walkthrough for installing `signal-rs`,
linking it to your Signal account, and confirming it can send and receive. The
[README](../README.md) has the canonical install and usage commands; this guide
is the linear path with the traps called out, plus the build dependencies that
make this *not* a one-line `cargo install`.

> **Wiring signal-rs in as second-brain's Signal transport?** That path is owned
> by second-brain's onboarding guide (its "Optional: Signal transport" section)
> - it links with a borg-owned `--state-dir`, pins `signal.host`, and handles
> the cold-start ping for you. This guide covers the **standalone CLI**: you run
> `signal-rs link`/`send`/`receive` directly.

## What you are signing up for

`signal-rs` is a from-scratch Rust implementation of the Signal protocol
(library + CLI) - **not** a wrapper around `signal-cli`. It links to your
existing Signal account as a **secondary device** (your phone stays the
primary), then receives and sends on that account's behalf.

The Rust code is portable, but it builds on `libsignal` (Signal's own crates),
which compiles **BoringSSL** from source. That means the one thing that turns a
clean `cargo install` into a wall of build errors is a missing C/C++ toolchain -
`cmake`, `clang`, `protoc`. Install those first (see below) and the rest is
linking a device and verifying.

There is **no YAML config to edit.** All state - your identity, session keys,
the SQLite store - lives in a per-host state directory (`store.db`). The only
"configuration" is *which* state directory, controlled by `--state-dir`.

## Dependency checklist

Install these before building. The build toolchain is required; the rest are
quality-of-life.

**Required to build (the load-bearing dependency):**
- **Rust toolchain** (`rustup`) - to build the crate.
- **C/C++ build toolchain for libsignal + BoringSSL.** On Debian/Ubuntu:
  ```bash
  sudo apt-get install -y build-essential pkg-config libssl-dev \
    cmake clang libclang-dev protobuf-compiler
  ```
  (`protobuf-compiler` provides `protoc`, which `build.rs` invokes to compile
  the vendored `.proto` files; `cmake`/`clang` build Signal's BoringSSL fork,
  which `signal-rs` pulls in via `boring-sys`.) On macOS you'll also need a C
  toolchain - `brew install cmake protobuf` plus the Xcode command-line tools
  is the usual set, though CI only builds linux-amd64, so treat the macOS recipe
  as a guideline rather than a tested one.

**Preferred but optional:**
- **`rkvr`** (github.com/scottidler/rkvr) - for *recoverable* state wipes when
  re-linking. `bin/relink` uses it if present and falls back to plain `rm -rf`
  with a WARN if it is not. Install it only if you want a deleted state dir to
  be recoverable.

## Step-by-step

### 1. Install the binary

From crates-via-git (latest released line):

```bash
cargo install --git https://github.com/scottidler/signal-rs --bin signal-rs
```

Or from a working tree you have cloned:

```bash
cargo install --path .
```

If the build fails compiling `boring-sys`, `libsignal-*`, or with a "protoc not
found" error, you are missing the toolchain from the checklist above - that is
the single most common failure. Fix that and re-run.

### 2. Know where state lives

`signal-rs` does not use a config file. It keeps everything in a per-host state
directory:

- Linux: `~/.local/share/signal-rs/`
- macOS: `~/Library/Application Support/signal-rs/`

Override it with the global `--state-dir <path>` flag (use this if you run more
than one identity on a box). Inside it you will find `store.db` (the SQLite
identity/session store), `link-qr.png` (the rendered link QR), and
`logs/signal-rs.log`.

> **Turn on the log file before anything else.** All diagnostic output goes to
> `~/.local/share/signal-rs/logs/signal-rs.log`; stdout shows only prompts and
> result lines. Tail it in a second terminal and run commands with
> `--log-level debug` the first time through, so a failure tells its own story:
> ```bash
> tail -F ~/.local/share/signal-rs/logs/signal-rs.log
> ```

### 3. Link as a secondary device

Your phone must already have a Signal account and be acting as the primary
device. Then:

```bash
signal-rs --log-level debug link --name "my-laptop"
```

This opens a provisioning WebSocket to `chat.signal.org` and renders an
`sgnl://` provisioning URI as **both** a PNG (`<state-dir>/link-qr.png`) and a
QR code printed to stdout. On the phone: **Signal -> Settings -> Linked Devices
-> Add (the + button) -> scan the QR.**

On success you will see a final line like:

```
linked: account=+1XXXXXXXXXX device_id=2
```

`device_id` is 2 or higher (1 is the phone). The phone's Linked Devices list now
shows an entry with the `--name` you gave.

> **The QR needs a tall terminal.** It renders as ~60 lines of Unicode block
> characters and requires a monospace font. If it is garbled or clipped, make
> the window bigger, or scan `<state-dir>/link-qr.png` directly. Over SSH, use
> `bin/relink` (see traps) - it scp's the PNG to your laptop for you.

### 4. Verify the link

```bash
signal-rs status
```

In a terminal this prints a small key/value block (account number, ACI,
device id, link status); piped, it emits one `ClientStatus` JSON object. The
linked-devices list is fetched live from the server (`GET /v1/devices`), so this
also confirms the account-side state, not just your local store.

### 5. Receive

```bash
signal-rs --log-level debug receive
```

This runs the receive loop, decrypting incoming envelopes. In a terminal it
prints a human-readable block per envelope; piped or redirected it emits NDJSON
(one `Envelope` per line, `jq`-friendly). Add `--once` to print a single
envelope and exit (handy for a smoke test).

> **Cold start: a freshly-linked device receives nothing until it has *sent*
> once.** The phone builds its sync session lazily, so right after linking the
> receive loop can sit silent even though linking succeeded. Kick it by sending
> a Note-to-Self (next step) or sending yourself a message from the phone; after
> the first message the session is established and it stays established.

### 6. Send

```bash
# Note-to-Self (fans out to your own other linked devices, incl. the phone)
signal-rs send --to self "hello from signal-rs"

# 1:1 to a peer by ACI (sealed-sender when a profile key is on file)
signal-rs send --to aci:<uuid> "hi"

# attachments (repeat --attachment for multiple; body may be empty)
signal-rs send --to self --attachment ./photo.png "caption"
```

`send` returns the millisecond send-timestamp; that timestamp is what
`delete --timestamp` and the attachment `download` flow key off of. Other
verbs: `typing --start/--stop`, `delete`, and `download` (pull and decrypt a
CDN attachment from the pointer fields a received envelope carried).
`signal-rs --help` and `signal-rs <cmd> --help` document each.

## Known traps (lived experience)

- **Missing build toolchain is the #1 failure.** `cargo install` errors deep in
  `boring-sys`/`libsignal` or "protoc not found" mean the C/C++ toolchain from
  the checklist is absent. It is not a code problem.
- **One account, one host for Note-to-Self.** Signal-Server fans Note-to-Self
  out to *every* linked device. If you link `signal-rs` on two machines under
  the same account and run `receive` on both, both ingest the same self-message.
  For a single consumer, link on one host (or use distinct `--state-dir`s
  deliberately).
- **Re-linking? Use `bin/relink`, don't hand-roll the wipe.** It wipes the state
  dir (via `rkvr` if available), starts `link`, and delivers the QR - opening the
  PNG locally, or scp'ing it to your laptop over SSH (`bin/relink --host ...`).
  `bin/relink --resume` keeps state for a half-linked retry. Don't reinvent the
  `rkvr rmrf` + `link` + scp sequence inline.
- **Cold-start silence is not a bug** - see step 5. Send once to establish the
  sync session.

## If a step fails

This guide is the happy path. When a command fails on a server-side 4xx or a
wire-format mismatch, switch to the **diagnostic runbook**:
[`docs/manual-smoke-test.md`](manual-smoke-test.md) walks link -> receive -> send
with per-step failure-mode tables and exactly what to capture for a fix.

## Where to go next

- [`docs/design/`](design/) - the design memos: the
  [v0.1 design](design/2026-05-22-signal-rs-v0.1-design.md) (architecture and
  the libsignal source-of-truth investigation),
  [per-identity prekey storage](design/2026-05-23-per-identity-prekey-storage.md),
  and the [message surface](design/2026-05-23-signal-rs-message-surface.md).
- [`docs/manual-smoke-test.md`](manual-smoke-test.md) - the end-to-end
  validation runbook.
- `signal-rs --help` - the CLI documents itself.
