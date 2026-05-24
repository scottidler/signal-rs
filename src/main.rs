#![deny(clippy::unwrap_used)]
#![deny(dead_code)]
#![deny(unused_variables)]

use clap::Parser;
use eyre::{Context, Result, eyre};
use log::{LevelFilter, info};
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::str::FromStr;

use base64::Engine;
use signal_rs::{Client, ClientStatus, Envelope, Recipient, attachment, envelope::AttachmentPointer, link::link};

/// Parse the `--to` argument into a typed [`Recipient`]. Accepted
/// forms (lowercase): `self`, `aci:<uuid>`. Any other form (E.164
/// numbers, bare UUIDs, etc.) is rejected with a clear error rather
/// than being silently mis-interpreted.
fn parse_recipient(s: &str) -> Result<Recipient> {
    if s == "self" {
        return Ok(Recipient::SelfSync);
    }
    if let Some(uuid) = s.strip_prefix("aci:") {
        if uuid.is_empty() {
            return Err(eyre!("--to aci: requires a UUID after the colon"));
        }
        return Ok(Recipient::Aci(uuid.to_string()));
    }
    Err(eyre!(
        "--to must be `self` or `aci:<uuid>`; E.164 numbers and bare UUIDs are not accepted (got {s:?})"
    ))
}

mod cli;
use cli::{Cli, Command, Format, format_or_default};

/// Resolve the effective output format. Thin wrapper around the pure
/// [`format_or_default`] helper in `cli.rs` so the unit tests can drive
/// the precedence logic without monkey-patching the process's stdout.
fn resolve_format(explicit: Option<Format>) -> Format {
    format_or_default(explicit, std::io::stdout().is_terminal())
}

/// Render a single envelope. JSON mode prints one compact line so
/// consumers can `jq` it; text mode prints the `Debug` representation
/// (already structured + indented) so a human can read it.
fn print_envelope(envelope: &Envelope, format: Format) -> Result<()> {
    match format {
        Format::Json => {
            let line = serde_json::to_string(envelope).context("serialize envelope to json")?;
            println!("{line}");
        }
        Format::Text => {
            println!("{envelope:#?}");
        }
    }
    Ok(())
}

/// Render a `ClientStatus`. JSON mode emits a pretty-printed object
/// (single artifact, not a stream, so indentation is fine). Text mode
/// formats a small key/value block plus a per-device line for each
/// entry returned by the server.
fn print_status(status: &ClientStatus, format: Format) -> Result<()> {
    match format {
        Format::Json => {
            let body = serde_json::to_string_pretty(status).context("serialize status to json")?;
            println!("{body}");
        }
        Format::Text => {
            println!("account_number: {}", status.account_number);
            println!("device_id:      {}", status.device_id);
            println!("aci:            {}", status.aci.as_deref().unwrap_or("<unset>"));
            println!("pni:            {}", status.pni.as_deref().unwrap_or("<unset>"));
            println!("link_status:    {}", status.link_status);
            println!("linked_devices: {}", status.linked_devices.len());
            for d in &status.linked_devices {
                println!(
                    "  - id={} name={} created_ms={} last_seen_ms={}",
                    d.id,
                    d.name.as_deref().unwrap_or("<unset>"),
                    d.created_ms
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "<unset>".to_string()),
                    d.last_seen_ms
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "<unset>".to_string()),
                );
            }
        }
    }
    Ok(())
}

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
            // Live linking against Signal. Renders the provisioning URI
            // as a QR code so the operator can scan it from their primary
            // device's Linked Devices screen.
            let state_dir_for_qr = state_dir.clone();
            let outcome = link(&state_dir, &name, |uri| {
                println!();
                println!("Scan this with your primary device (Settings -> Linked Devices):");
                println!();
                // Render two ways:
                //   1. PNG file the operator can open in any image
                //      viewer. Reliable across terminals.
                //   2. ANSI block QR in stdout as a fallback.
                if let Ok(code) = qrcode::QrCode::new(uri.as_bytes()) {
                    // PNG version
                    let png_path = state_dir_for_qr.join("link-qr.png");
                    let image = code.render::<image::Luma<u8>>().min_dimensions(512, 512).build();
                    match image.save(&png_path) {
                        Ok(()) => {
                            println!("QR saved to: {}", png_path.display());
                            println!("Open it: xdg-open {}", png_path.display());
                            println!();
                        }
                        Err(e) => println!("(warning: could not save QR PNG: {e})"),
                    }

                    // ANSI block fallback in stdout, in case the user
                    // wants to scan from terminal. Renders the
                    // module-as-two-spaces variant (full-width blocks
                    // at full height) - far more robust than Dense1x2
                    // across terminals.
                    println!("ANSI fallback (scan from terminal if PNG opens are not convenient):");
                    println!();
                    let rendered = code
                        .render::<char>()
                        .quiet_zone(true)
                        .module_dimensions(2, 1)
                        .light_color(' ')
                        .dark_color('█')
                        .build();
                    println!("{rendered}");
                }
                println!("Or manually copy: {uri}");
                println!();
            })
            .await
            .map_err(|e| eyre!("link: {e}"))?;
            println!(
                "linked: account={} device_id={}",
                outcome.account_number, outcome.device_id
            );
            Ok(())
        }
        Command::Send {
            to,
            attachments,
            message,
        } => {
            let recipient = parse_recipient(&to)?;
            info!(
                "send: to={to} body_len={} attachments={}",
                message.len(),
                attachments.len()
            );
            let client = Client::open(&state_dir).await.map_err(|e| eyre!("Client::open: {e}"))?;
            let timestamp_ms = if attachments.is_empty() {
                client
                    .send(recipient, &message)
                    .await
                    .map_err(|e| eyre!("Client::send: {e}"))?
            } else {
                client
                    .send_with_attachments(recipient, &message, &attachments)
                    .await
                    .map_err(|e| eyre!("Client::send_with_attachments: {e}"))?
            };
            println!(
                "send: dispatched to={to} timestamp_ms={timestamp_ms} attachments={}",
                attachments.len()
            );
            Ok(())
        }
        Command::Receive { once, format } => {
            let fmt = resolve_format(format);
            info!("receive: state_dir={} once={once} format={fmt:?}", state_dir.display());
            let client = Client::open(&state_dir).await.map_err(|e| eyre!("Client::open: {e}"))?;
            if once {
                // --once: race the receive loop against the first
                // broadcast envelope; drop the loop future as soon as we
                // print one. libsignal-protocol's storage futures are
                // !Send so we cannot tokio::spawn the loop; tokio::select!
                // co-runs both futures on the same task.
                let mut rx = client.receive();
                let loop_fut = client.run_receive_loop();
                tokio::pin!(loop_fut);
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Ok(envelope) => print_envelope(&envelope, fmt)?,
                            Err(e) => eprintln!("receive: channel closed before first envelope: {e}"),
                        }
                    }
                    res = &mut loop_fut => {
                        res.map_err(|e| eyre!("run_receive_loop: {e}"))?;
                    }
                }
            } else {
                // Long-running mode: subscribe to the broadcast channel
                // and print every decoded envelope while the receive
                // loop runs in parallel. libsignal-protocol's storage
                // futures are !Send so we can't spawn the loop on a
                // separate task; tokio::select! co-runs both on the
                // current task. Without the explicit rx.recv() arm
                // envelopes are silently dropped - broadcast::send is
                // a no-op when no receivers are attached.
                let mut rx = client.receive();
                let loop_fut = client.run_receive_loop();
                tokio::pin!(loop_fut);
                loop {
                    tokio::select! {
                        msg = rx.recv() => {
                            match msg {
                                Ok(envelope) => print_envelope(&envelope, fmt)?,
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    eprintln!("receive: lagged, dropped {n} envelopes");
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    eprintln!("receive: channel closed");
                                    break;
                                }
                            }
                        }
                        res = &mut loop_fut => {
                            res.map_err(|e| eyre!("run_receive_loop: {e}"))?;
                            break;
                        }
                    }
                }
            }
            Ok(())
        }
        Command::Status { format } => {
            let fmt = resolve_format(format);
            info!("status: state_dir={} format={fmt:?}", state_dir.display());
            let client = Client::open(&state_dir).await.map_err(|e| eyre!("Client::open: {e}"))?;
            let status = client.status().await.map_err(|e| eyre!("Client::status: {e}"))?;
            print_status(&status, fmt)?;
            Ok(())
        }
        Command::Typing { to, start, stop } => {
            let recipient = parse_recipient(&to)?;
            // ArgGroup ensures exactly one of start/stop is set; map to
            // the bool the library API takes.
            let started = if start {
                true
            } else if stop {
                false
            } else {
                // Defensive: ArgGroup should have rejected this at parse time.
                return Err(eyre!("--start or --stop is required"));
            };
            info!("typing: to={to} started={started}");
            let client = Client::open(&state_dir).await.map_err(|e| eyre!("Client::open: {e}"))?;
            client
                .typing(recipient, started)
                .await
                .map_err(|e| eyre!("Client::typing: {e}"))?;
            println!("typing: dispatched to={to} started={started}");
            Ok(())
        }
        Command::Delete { to, target_timestamp } => {
            let recipient = parse_recipient(&to)?;
            info!("delete: to={to} target_timestamp={target_timestamp}");
            let client = Client::open(&state_dir).await.map_err(|e| eyre!("Client::open: {e}"))?;
            client
                .delete_for_everyone(recipient, target_timestamp)
                .await
                .map_err(|e| eyre!("Client::delete_for_everyone: {e}"))?;
            println!("delete: dispatched to={to} target_timestamp={target_timestamp}");
            Ok(())
        }
        Command::Download {
            cdn_id,
            cdn_key,
            cdn_number,
            key,
            digest,
            dest,
        } => {
            info!(
                "download: cdn_id={cdn_id} cdn_key={:?} cdn_number={cdn_number} dest={}",
                cdn_key,
                dest.display()
            );
            let key_bytes = base64::engine::general_purpose::STANDARD
                .decode(key.as_bytes())
                .map_err(|e| eyre!("--key base64 decode: {e}"))?;
            let digest_bytes = if digest.is_empty() {
                Vec::new()
            } else {
                base64::engine::general_purpose::STANDARD
                    .decode(digest.as_bytes())
                    .map_err(|e| eyre!("--digest base64 decode: {e}"))?
            };
            let pointer = AttachmentPointer {
                cdn_id,
                cdn_key,
                cdn_number,
                content_type: None,
                size: None,
                digest: digest_bytes,
                key: key_bytes,
                file_name: None,
                caption: None,
                width: None,
                height: None,
                voice_note: false,
                borderless: false,
                gif: false,
                upload_timestamp: None,
                blurhash: None,
            };
            attachment::download_attachment(&pointer, &dest)
                .await
                .map_err(|e| eyre!("download_attachment: {e}"))?;
            println!(
                "download: {} bytes written to {}",
                std::fs::metadata(&dest)?.len(),
                dest.display()
            );
            Ok(())
        }
    }
}
