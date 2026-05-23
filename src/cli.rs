use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::LazyLock;

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

    /// Send a 1:1 text message. Pass your own E.164 to fan out a
    /// Note-to-Self.
    Send {
        /// Recipient E.164 number (e.g. +15555550100).
        target: String,
        /// Message body. Wrap in quotes if it contains spaces.
        message: String,
    },

    /// Run the receive loop, decrypting incoming envelopes and printing
    /// them to stdout as pretty JSON.
    Receive {
        /// Print one envelope and exit instead of looping. Smoke-test
        /// helper.
        #[arg(long)]
        once: bool,
    },
}
