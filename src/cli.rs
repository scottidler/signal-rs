use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::sync::LazyLock;

/// Output format for commands that have to choose between line-delimited
/// JSON (one record per line, machine-consumable) and a human-readable
/// rendering. Default is left unset on the parsed value so `main.rs`
/// resolves it at runtime via `std::io::IsTerminal` on stdout.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum Format {
    Json,
    Text,
}

/// Resolve the effective output format from an explicit `--format` value
/// (if the user passed one) and whether stdout is currently a TTY.
/// Pure function so it can be unit-tested without monkey-patching the
/// process's actual stdout; `main.rs` supplies the `is_tty` bool from
/// `std::io::stdout().is_terminal()`.
pub fn format_or_default(explicit: Option<Format>, is_tty: bool) -> Format {
    if let Some(f) = explicit {
        return f;
    }
    if is_tty { Format::Text } else { Format::Json }
}

#[cfg(test)]
mod tests;

static AFTER_HELP: LazyLock<String> = LazyLock::new(after_help_text);

fn after_help_text() -> String {
    let state_dir = dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("signal-rs");
    let log_path = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("signal-rs")
        .join("logs")
        .join("signal-rs.log");
    format!(
        "PATHS:\n  State dir: {state_dir}\n  Log file:  {log_path}",
        state_dir = state_dir.display(),
        log_path = log_path.display(),
    )
}

#[derive(Parser)]
#[command(
    name = "signal-rs",
    about = "Native-Rust Signal client - v0.1 unblocks borg Note-to-Self ingest",
    long_about = "Native-Rust Signal client. Link as a secondary device, receive Signal\n\
                  envelopes, and send a 1:1 text message. Note-to-Self is the primary\n\
                  use case for borg ingest.",
    version = env!("GIT_DESCRIBE"),
    after_help = AFTER_HELP.as_str(),
)]
pub struct Cli {
    /// Override the state directory. Defaults to $XDG_DATA_HOME/signal-rs
    /// on Linux, ~/Library/Application Support/signal-rs on macOS.
    #[arg(long, global = true)]
    pub state_dir: Option<PathBuf>,

    /// Log level: error, warn, info, debug, trace. Default: info.
    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Link this host as a secondary device on the user's existing
    /// Signal account. Renders a `sgnl://` provisioning URI as both a
    /// PNG (at <state_dir>/link-qr.png) and ANSI to stdout; the primary
    /// device scans it to complete linking.
    Link {
        /// Friendly name shown in the primary's Linked Devices list.
        #[arg(long, default_value = "signal-rs")]
        name: String,
    },

    /// Send a 1:1 text message. `--to self` fans out a Note-to-Self
    /// to the user's other linked devices; `--to aci:UUID` sends a
    /// sealed-sender peer message (falling back to unsealed with a
    /// warning if we have no profile key on file for that peer).
    Send {
        /// Recipient. Accepted forms: `self`, `aci:<uuid>`.
        #[arg(long)]
        to: String,
        /// Attach a file to the message. Repeat the flag to attach
        /// multiple files. Each file is bucket-padded, AES-CBC + HMAC
        /// encrypted, and uploaded to Signal's CDN before the message
        /// itself is dispatched.
        #[arg(long = "attachment", value_name = "PATH")]
        attachments: Vec<PathBuf>,
        /// Message body. Wrap in quotes if it contains spaces. Can be
        /// empty (e.g. `signal-rs send --to self --attachment foo.png
        /// ""`) when only attachments are intended.
        message: String,
    },

    /// Run the receive loop, decrypting incoming envelopes and printing
    /// them to stdout. JSON mode emits one `Envelope` per line (NDJSON,
    /// `jq`-friendly); text mode renders each envelope as a human-readable
    /// debug block. Default is determined at runtime from `IsTerminal` on
    /// stdout: terminal -> text, non-terminal (pipe/file) -> json.
    Receive {
        /// Print one envelope and exit instead of looping. Smoke-test
        /// helper.
        #[arg(long)]
        once: bool,
        /// Output format. Omit to auto-detect from stdout: json when
        /// piped/redirected, text when attached to a terminal.
        #[arg(long, value_enum)]
        format: Option<Format>,
    },

    /// Print the local device's identity-level state plus the
    /// server-authoritative linked-devices list (`GET /v1/devices`).
    /// JSON mode emits a single `ClientStatus` object; text mode renders
    /// a small key/value block. Default is determined at runtime from
    /// `IsTerminal` on stdout.
    Status {
        /// Output format. Omit to auto-detect from stdout: json when
        /// piped/redirected, text when attached to a terminal.
        #[arg(long, value_enum)]
        format: Option<Format>,
    },

    /// Send a typing indicator to a peer. Carries no body or attachments;
    /// peer clients display "... is typing" until the typing-stopped
    /// indicator arrives or a real message lands. Only `aci:<uuid>`
    /// recipients are accepted - typing to self is meaningless.
    #[command(group(ArgGroup::new("typing_action").required(true).args(["start", "stop"])))]
    Typing {
        /// Recipient. Accepted form: `aci:<uuid>`.
        #[arg(long)]
        to: String,
        /// Send the typing-started indicator.
        #[arg(long)]
        start: bool,
        /// Send the typing-stopped indicator.
        #[arg(long)]
        stop: bool,
    },

    /// Send a remote-delete request for a previously-sent message. The
    /// target timestamp is the millisecond send-timestamp the original
    /// `send` returned (or that the receiving envelope carried). Only
    /// `aci:<uuid>` recipients are accepted.
    Delete {
        /// Recipient. Accepted form: `aci:<uuid>`.
        #[arg(long)]
        to: String,
        /// Millisecond send-timestamp of the message being deleted.
        #[arg(long)]
        target_timestamp: u64,
    },

    /// Download and decrypt an attachment from Signal's CDN. The pointer
    /// fields come from a prior received `Envelope::DataMessage` (or
    /// `SyncMessage::Sent`); pass them through to this subcommand. Either
    /// `--cdn-id` (cdn0) or `--cdn-key` (cdn2/cdn3) is required depending
    /// on the cdn_number the pointer reported.
    Download {
        /// cdn_id from the attachment pointer (used when cdn_number == 0).
        #[arg(long, default_value_t = 0)]
        cdn_id: u64,
        /// cdn_key from the attachment pointer (used when cdn_number == 2 or 3).
        #[arg(long)]
        cdn_key: Option<String>,
        /// cdn_number from the attachment pointer: 0, 2, or 3.
        #[arg(long)]
        cdn_number: u32,
        /// 64-byte attachment key, base64-encoded.
        #[arg(long)]
        key: String,
        /// 32-byte SHA-256 digest of the encrypted blob, base64-encoded.
        /// Pass empty string to skip digest verification (HMAC is still
        /// enforced).
        #[arg(long, default_value = "")]
        digest: String,
        /// Output path for the decrypted plaintext.
        #[arg(long)]
        dest: PathBuf,
    },
}
