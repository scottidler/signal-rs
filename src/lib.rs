#![deny(clippy::unwrap_used)]
#![deny(dead_code)]
#![deny(unused_variables)]

pub mod config;
pub mod crypto;
pub mod storage;

pub use config::Config;
pub use storage::{Identity, LinkStatus, SqliteStore, Store, StoreError};

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
