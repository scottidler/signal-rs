#![deny(clippy::unwrap_used)]
#![deny(dead_code)]
#![deny(unused_variables)]

use clap::Parser;
use eyre::{Context, Result, eyre};
use log::{LevelFilter, info};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use signal_rs::{Client, link::prepare_link_session};

mod cli;
use cli::{Cli, Command};

fn default_state_dir() -> PathBuf {
    dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("signal-rs")
}

fn setup_logging(level: &str) -> Result<()> {
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("signal-rs")
        .join("logs");

    fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

    let log_file = log_dir.join("signal-rs.log");

    let target = Box::new(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .context("Failed to open log file")?,
    );

    let lvl = LevelFilter::from_str(level).unwrap_or(LevelFilter::Info);

    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Pipe(target))
        .filter_level(lvl)
        .init();

    info!("logging initialized: level={lvl} file={}", log_file.display());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    setup_logging(&cli.log_level).context("Failed to setup logging")?;

    let state_dir = cli.state_dir.unwrap_or_else(default_state_dir);
    fs::create_dir_all(&state_dir).context("Failed to create state directory")?;

    match cli.command {
        Command::Link { name } => {
            info!("link: state_dir={} name={name}", state_dir.display());
            // The post-decrypt half of linking is reachable through
            // signal_rs::link::finalize_link once a consumer drives the
            // provisioning WebSocket themselves. For the CLI, we surface
            // the v0.1 stub clearly.
            let mut rng = rand::rng();
            let (_, uri) = prepare_link_session(&mut rng, "<server-issued-address>");
            println!("Provisioning URI scaffolding (Phase 10 will replace this with real server-issued address):");
            println!("{uri}");
            println!();
            println!("error: live linking is Phase 10 manual smoke test (libsignal-net's ProvisioningConnection)");
            Err(eyre!("LinkError::LiveServerNotImplemented"))
        }
        Command::Send { target, message } => {
            info!("send: target={target} body_len={}", message.len());
            let client = Client::open(&state_dir).await.map_err(|e| eyre!("Client::open: {e}"))?;
            client
                .send(&target, &message)
                .await
                .map_err(|e| eyre!("Client::send: {e}"))?;
            Ok(())
        }
        Command::Receive { once } => {
            info!("receive: state_dir={} once={once}", state_dir.display());
            let client = Client::open(&state_dir).await.map_err(|e| eyre!("Client::open: {e}"))?;
            client
                .run_receive_loop()
                .await
                .map_err(|e| eyre!("Client::run_receive_loop: {e}"))?;
            Ok(())
        }
    }
}
