# signal-rs

A from-scratch Rust implementation of the Signal protocol - **library + CLI**.
Not a wrapper around `signal-cli`: it builds directly on Signal's own
`libsignal` crates and links to your existing account as a **secondary device**
(your phone stays the primary), then sends and receives on its behalf.

The CLI covers `link`, `send` (Note-to-Self, 1:1 by ACI, attachments),
`receive` (decrypting loop, text or NDJSON), `status`, `typing`, `delete`, and
attachment `download`. The library re-exports `Client`, `Config`, `Envelope`,
and the storage/link types for embedding.

> **New here / setting up a fresh machine?** See [`docs/setup.md`](docs/setup.md)
> for the linear, gotcha-aware walkthrough - the full build-dependency checklist
> (the C/C++ toolchain this README lists but that trips most people up), device
> linking, and the known traps. This README is the install reference; the setup
> guide is the end-to-end path.

## Prerequisites

`signal-rs` builds on `libsignal`, which compiles BoringSSL from source and runs
`protoc` over vendored `.proto` files at build time. You need a C/C++ toolchain:

- **Rust toolchain** (`rustup`).
- **Build dependencies.** On Debian/Ubuntu:
  ```bash
  sudo apt-get install -y build-essential pkg-config libssl-dev \
    cmake clang libclang-dev protobuf-compiler
  ```
  On macOS you'll also need a C toolchain; `brew install cmake protobuf` plus
  the Xcode command-line tools is the usual set. (CI builds linux-amd64 only,
  so the macOS recipe is a guideline, not a tested one.)

A missing toolchain is the single most common build failure - it surfaces deep
in `boring-sys`/`libsignal` or as "protoc not found".

## Install

```bash
# Latest released line, from git
cargo install --git https://github.com/scottidler/signal-rs --bin signal-rs

# Or from a cloned working tree
cargo install --path .
```

## Quick start

```bash
# 1. Link this host as a secondary device; scan the printed QR with your
#    phone (Signal -> Settings -> Linked Devices -> +).
signal-rs --log-level debug link --name "my-laptop"

# 2. Confirm the link (local identity + server-side linked-devices list).
signal-rs status

# 3. Receive (text in a terminal, NDJSON when piped). --once for one envelope.
signal-rs receive

# 4. Send a Note-to-Self (fans out to your other linked devices).
signal-rs send --to self "hello from signal-rs"
```

State (the SQLite store, link QR, and logs) lives in a per-host directory -
`~/.local/share/signal-rs/` on Linux, `~/Library/Application Support/signal-rs/`
on macOS - overridable with the global `--state-dir` flag. There is no YAML
config to edit. Logs land in `<state-dir>/logs/signal-rs.log`; run with
`--log-level debug` and tail that file when diagnosing.

See [`docs/setup.md`](docs/setup.md) for the full walkthrough and the gotchas
(QR terminal height, cold-start sync, re-linking via `bin/relink`,
single-host Note-to-Self).

## References

- [`docs/setup.md`](docs/setup.md) - end-to-end setup and known traps.
- [`docs/manual-smoke-test.md`](docs/manual-smoke-test.md) - diagnostic runbook:
  link -> receive -> send with per-step failure-mode tables.
- [`docs/design/`](docs/design/) - design memos (v0.1 architecture and the
  libsignal source-of-truth investigation, per-identity prekey storage, the
  message surface).
