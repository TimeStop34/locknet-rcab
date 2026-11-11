//! Send a single message to an existing chat and exit.
//!
//! Usage:
//!
//! ```text
//! LOCKNET_URL=https://localhost:8000 LOCKNET_SPACE=localhost:8000 \
//!     cargo run --example send_message -- <username> <password> <chat_id> <text...>
//! ```
//!
//! The text is joined from all remaining arguments with spaces, so quoting
//! is not strictly required for multi-word messages:
//!
//! ```text
//! cargo run --example send_message -- alice secret123 1234567890 hello world
//! ```
//!
//! `chat_id` must be a chat the user is a member of. Use
//! `cargo run --example list_chats` (not included) or inspect the server
//! logs to find one.

use std::env;

use locknet_rcab::{Credentials, LockNetClient, LockNetConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "usage: {} <username> <password> <chat_id> <text...>",
            args[0]
        );
        std::process::exit(1);
    }
    let username = &args[1];
    let password = &args[2];
    let chat_id: i64 = args[3].parse()?;
    let text = args[4..].join(" ");

    let url = env::var("LOCKNET_URL").unwrap_or_else(|_| "https://localhost:8000".into());
    let space = env::var("LOCKNET_SPACE").unwrap_or_else(|_| "localhost:8000".into());

    let mut cfg = LockNetConfig::new(&url, &space)?;
    cfg.accept_invalid_certs = true;
    cfg.sync_on_connect = false;

    let mut client = LockNetClient::new(cfg);
    let session = client
        .connection_request(Credentials::Login {
            username: username.clone(),
            password: password.clone(),
        })
        .await?;

    eprintln!(
        "[send_message] logged in as user_id={} session_id={}",
        session.user_id, session.session_id
    );

    let agent = client.get_agent().expect("agent must exist after connect");

    // `chat()` fetches the group DTO if it is not cached. Fails with a
    // server error if the user is not a member.
    let chat = match agent.chat(chat_id).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[send_message] cannot open chat {chat_id}: {e}");
            return Err(e.into());
        }
    };

    let sent = chat.send(text).await?;
    eprintln!(
        "[send_message] sent message_id={} (encrypted={})",
        sent.id, sent.encrypted
    );

    // Disconnect cleanly so the runner shuts down its WebSocket.
    client.disconnect().await?;
    Ok(())
}
