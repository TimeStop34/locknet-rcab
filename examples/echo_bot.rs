//! Echo bot — the smallest useful LockNet client.
//!
//! Demonstrates:
//! - Registration, then connecting with the returned session.
//! - Subscribing to `HighEvent`s.
//! - Reacting to `HighEvent::NewMessage` by sending an `echo: <text>`
//!   reply back to the same chat.
//! - Graceful shutdown on Ctrl+C.
//!
//! Run against a local server:
//!
//! ```text
//! LOCKNET_URL=https://localhost:8000 LOCKNET_SPACE=localhost:8000 \
//!     cargo run --example echo_bot -- <username> <password>
//! ```
//!
//! The bot registers `username` if it does not exist; re-running with the
//! same username/password will log in instead.
//!
//! Stop with Ctrl+C.

use std::env;
use std::time::Duration;

use locknet_rcab::{Credentials, HighEvent, LockNetClient, LockNetConfig, LockNetError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <username> <password>", args[0]);
        std::process::exit(1);
    }
    let username = &args[1];
    let password = &args[2];

    let url = env::var("LOCKNET_URL").unwrap_or_else(|_| "https://localhost:8000".into());
    let space = env::var("LOCKNET_SPACE").unwrap_or_else(|_| "localhost:8000".into());

    let mut cfg = LockNetConfig::new(&url, &space)?;
    // Examples are meant for dev use against a self-signed server.
    cfg.accept_invalid_certs = true;
    cfg.sync_on_connect = true;

    let mut client = LockNetClient::new(cfg);

    // Try registering; if the username is taken, log in instead.
    let session = match client
        .connection_request(Credentials::Register {
            username: username.clone(),
            password: password.clone(),
            display_name: Some(username.clone()),
        })
        .await
    {
        Ok(s) => s,
        Err(LockNetError::Server { code, .. }) if code == "username_taken" => {
            eprintln!("[echo_bot] username taken, logging in");
            client
                .connection_request(Credentials::Login {
                    username: username.clone(),
                    password: password.clone(),
                })
                .await?
        }
        Err(e) => return Err(e.into()),
    };

    eprintln!(
        "[echo_bot] connected: user_id={} session_id={}",
        session.user_id, session.session_id
    );

    // The high-level agent is created lazily on first access. It processes
    // raw WebSocket events into HighEvents and keeps the state cache.
    let agent = client.get_agent().expect("agent must exist after connect");
    let our_uid = session.user_id;

    // `subscribe()` returns a broadcast receiver. Any event emitted *after*
    // this call will be seen; events before it are lost. That is fine here:
    // we only care about future messages.
    let mut rx = agent.subscribe();

    eprintln!("[echo_bot] listening for messages (Ctrl+C to stop)");

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                eprintln!("[echo_bot] Ctrl+C, shutting down");
                break;
            }
            evt = rx.recv() => {
                let evt = match evt {
                    Ok(e) => e,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("[echo_bot] lagged, dropped {n} events");
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        eprintln!("[echo_bot] event channel closed");
                        break;
                    }
                };

                if let HighEvent::NewMessage { chat, message } = evt {
                    // Do not reply to ourselves — that would loop forever.
                    if message.author.id == our_uid {
                        continue;
                    }
                    let Some(text) = message.text.as_deref() else {
                        // Either pending decryption or a non-text payload.
                        continue;
                    };

                    let reply = format!("echo: {text}");
                    match chat.send(reply).await {
                        Ok(_) => eprintln!(
                            "[echo_bot] replied in chat {} to msg {}",
                            chat.id(),
                            message.id
                        ),
                        Err(e) => eprintln!("[echo_bot] send failed: {e}"),
                    }
                }
            }
        }
    }

    // Give the runner a moment to flush (best-effort; ignores errors).
    let _ = tokio::time::timeout(Duration::from_secs(2), client.disconnect()).await;
    Ok(())
}
