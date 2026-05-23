#![deny(clippy::unwrap_used)]
#![deny(dead_code)]
#![deny(unused_variables)]

pub mod client;
pub mod config;
pub mod crypto;
pub mod envelope;
pub mod link;
pub mod storage;

pub use client::{Client, OpenError, ReceiveError, SendError};
pub use config::Config;
pub use envelope::{DataMessage, Envelope, SyncMessage};
pub use link::{LinkError, LinkOutcome, finalize_link, mark_linked, persist_provision_message, prepare_link_session};
pub use storage::{Identity, LinkStatus, SqliteStore, Store, StoreError, TxStore};

use colored::*;
use eyre::Result;
use log::info;

#[derive(Debug)]
pub struct RunResult {
    pub messages: Vec<String>,
}

pub fn run(config: &Config) -> Result<RunResult> {
    info!("run: name={} age={} debug={}", config.name, config.age, config.debug);

    let messages = vec![
        format!("{} Configuration loaded successfully", "✓".green()),
        format!("{} Hello from {}!", "🎉".green(), env!("CARGO_PKG_NAME").cyan()),
        format!("{} Author: {}", "👤".blue(), config.name),
        format!("{} Age: {}", "📅".blue(), config.age),
    ];

    Ok(RunResult { messages })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
