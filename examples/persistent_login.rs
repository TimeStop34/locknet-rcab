//! Persistent session and crypto state across restarts.
//!
//! Demonstrates the two pieces an application needs to persist:
//!
//! 1. **Refresh JWT** — printed after the first login; pass it back on the
//!    next run to skip the password. `Credentials::Session` reuses the
//!    same server-side `session_id`.
//! 2. **SQLite crypto store** — `SqliteStore` keeps the Olm account,
//!    Olm/Megolm sessions, cross-signing keys, and group policies on disk.
//!    The database is encrypted with a passphrase you provide.
//!
//! The passphrase itself must come from outside this library: on desktop,
//! use the OS keychain (macOS Keychain, Windows Credential Manager,
//! Linux Secret Service via `keyring`-like crates). On servers, an env
//! var read by the process supervisor is usually the right choice.
//!
//! First run:
//!
//! ```text
//! LOCKNET_URL=https://localhost:8000 LOCKNET_SPACE=localhost:8000 \
//! LOCKNET_DB_PATH=./locknet-persistent.db \
//! LOCKNET_DB_PASSPHRASE=change-me \
//! LOCKNET_USERNAME=alice LOCKNET_PASSWORD=secret123 \
//!     cargo run --example persistent_login
//! ```
//!
//! The example prints a `LOCKNET_RJWT=...` line. Copy it and use it on the
//! next run:
//!
//! ```text
//! LOCKNET_URL=... LOCKNET_SPACE=... \
//! LOCKNET_DB_PATH=./locknet-persistent.db \
//! LOCKNET_DB_PASSPHRASE=change-me \
//! LOCKNET_RJWT=<paste-here> \
//!     cargo run --example persistent_login
//! ```

use std::env;
use std::sync::Arc;
use std::time::Duration;

use locknet_rcab::{Credentials, LockNetClient, LockNetConfig, LockNetError, SqliteStore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::var("LOCKNET_URL").unwrap_or_else(|_| "https://localhost:8000".into());
    let space = env::var("LOCKNET_SPACE").unwrap_or_else(|_| "localhost:8000".into());

    let db_path = env::var("LOCKNET_DB_PATH").unwrap_or_else(|_| "./locknet-persistent.db".into());
    let db_pass = env::var("LOCKNET_DB_PASSPHRASE").map_err(|_| {
        "LOCKNET_DB_PASSPHRASE is required (the SQLite file is encrypted with it)"
    })?;

    let mut cfg = LockNetConfig::new(&url, &space)?;
    cfg.accept_invalid_certs = true;
    cfg.sync_on_connect = true;

    // Open the persistent store. On the first run this creates the file and
    // the schema; on subsequent runs it loads the existing Olm/Megolm/CS
    // state.
    let store = Arc::new(SqliteStore::open(&db_path, &db_pass)?);
    eprintln!("[persistent_login] opened store at {db_path}");

    let mut client = LockNetClient::with_store(cfg, store);

    // Prefer refresh JWT when it is available. Otherwise fall back to
    // username/password.
    let session = if let Ok(rjwt) = env::var("LOCKNET_RJWT") {
        eprintln!("[persistent_login] resuming via refresh JWT");
        match client
            .connection_request(Credentials::Session { refresh_jwt: rjwt })
            .await
        {
            Ok(s) => s,
            Err(LockNetError::SessionExpired) => {
                eprintln!(
                    "[persistent_login] refresh JWT expired; run again without \
                     LOCKNET_RJWT and provide LOCKNET_USERNAME / LOCKNET_PASSWORD"
                );
                return Err("refresh JWT expired".into());
            }
            Err(e) => return Err(e.into()),
        }
    } else {
        let username = env::var("LOCKNET_USERNAME")
            .map_err(|_| "LOCKNET_USERNAME is required on the first run")?;
        let password = env::var("LOCKNET_PASSWORD")
            .map_err(|_| "LOCKNET_PASSWORD is required on the first run")?;
        eprintln!("[persistent_login] logging in as {username}");
        client
            .connection_request(Credentials::Login { username, password })
            .await?
    };

    eprintln!(
        "[persistent_login] connected: user_id={} session_id={}",
        session.user_id, session.session_id
    );

    // Accessing the agent initialises it (lazy) so event processing and
    // policy handling start.
    let agent = client.get_agent().expect("agent must exist after connect");
    let chats = agent.chats().await?;
    eprintln!(
        "[persistent_login] member of {} chat(s): {:?}",
        chats.len(),
        chats.iter().map(|c| (c.id(), c.name())).collect::<Vec<_>>()
    );

    // Keep the connection alive for a short while so that background
    // activity (event sync, Megolm fan-out) has time to settle. In a real
    // application this would be your main loop instead of a sleep.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Print the current refresh JWT so the user can persist it for the next
    // run. In production, write it to your own durable storage (file,
    // database, keychain-backed value) — not to stdout.
    eprintln!();
    eprintln!("LOCKNET_RJWT={}", session.rjwt);
    eprintln!();

    client.disconnect().await?;
    Ok(())
}