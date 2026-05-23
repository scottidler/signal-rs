use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "signal-rs",
    about = "Native-Rust Signal client - v0.1 unblocks borg Note-to-Self ingest",
    long_about = "Native-Rust Signal client. v0.1 ships the surface needed to link\n\
                  as a secondary device, receive Signal envelopes, and send a 1:1 text message.\n\
                  The live network paths (link/send/receive) are wired in Phase 10's manual\n\
                  smoke test - they will currently exit with `not implemented`.",
    version = env!("GIT_DESCRIBE"),
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
    /// Signal account. Renders a `sgnl://` provisioning URI as a QR
    /// code; the primary device scans it to complete linking.
    ///
    /// Currently returns `LiveServerNotImplemented` - Phase 10 wires
    /// this to libsignal-net::chat's provisioning WebSocket.
    Link {
        /// Friendly name shown in the primary's Linked Devices list.
        #[arg(long, default_value = "signal-rs")]
        name: String,
    },

    /// Send a 1:1 text message. Pass your own E.164 to fan out a
    /// Note-to-Self.
    ///
    /// Currently returns `LiveSendNotImplemented` - Phase 10 wires
    /// this to libsignal-net-chat::AuthenticatedChatApi.
    Send {
        /// Recipient E.164 number (e.g. +15555550100).
        target: String,
        /// Message body. Wrap in quotes if it contains spaces.
        message: String,
    },

    /// Drain a single envelope from the receive loop and print it to
    /// stdout as pretty JSON, then exit. Smoke-test helper.
    ///
    /// Currently returns `LiveLoopNotImplemented` - Phase 10 wires
    /// this to libsignal-net::chat's ChatConnection.
    Receive {
        /// Only print one envelope and exit. v0.1 only supports this
        /// mode; long-running daemon mode is a later version.
        #[arg(long)]
        once: bool,
    },
}
