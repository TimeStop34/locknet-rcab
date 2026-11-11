# LockNet RCAB

**Official Rust Client-API Binding for LockNet — a social network with End-to-End Encrypted (E2EE) messaging.**

[![License: AGPL-3.0](https://img.shields.io/github/license/TimeStop34/locknet-rcab?color=blue)](https://github.com/TimeStop34/locknet-rcab/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![GitHub last commit](https://img.shields.io/github/last-commit/TimeStop34/locknet-rcab)](https://github.com/TimeStop34/locknet-rcab/commits)
[![GitHub issues](https://img.shields.io/github/issues/TimeStop34/locknet-rcab)](https://github.com/TimeStop34/locknet-rcab/issues)
[![GitHub stars](https://img.shields.io/github/stars/TimeStop34/locknet-rcab?style=flat)](https://github.com/TimeStop34/locknet-rcab/stargazers)

## Features

- **End-to-End Encryption**: Uses Olm (1-to-1) and Megolm (group) sessions to ensure messages are only readable by intended recipients.
- **Web of Trust (WoT)**: Cross-signing with transitive trust verification. The server cannot forge trust.
- **Encrypted Group Policies**: `HistoryVisibility` and `MegolmRotationVisibility` policies are stored in `encrypted_group_data` blobs, unreadable by the server.
- **SAS & QR Verification**: Verify peers via emoji (SAS) or QR codes (user-to-user and self-device).
- **Encrypted Key Backup**: Export and import Megolm sessions using a secret recovery key.
- **Persistent State**: Pluggable `CryptoStore` with built-in `InMemoryStore` and SQLCipher-backed `SqliteStore`.
- **Automatic Megolm Rotation**: Rotates sessions based on message count and TTL.

## Usage

The crate is not published on crates.io. Add it to your `Cargo.toml` via git:

```toml
[dependencies]
locknet-rcab = { git = "https://github.com/TimeStop34/locknet-rcab" }
```

Or pin to a specific commit:

```toml
[dependencies]
locknet-rcab = { git = "https://github.com/TimeStop34/locknet-rcab", rev = "<commit-hash>" }
```

Or, if you have the repository checked out locally:

```toml
[dependencies]
locknet-rcab = { path = "../locknet-rcab" }
```

`locknet-rcab` requires **Rust 1.75** or newer.

## Quick Start

```rust,no_run
use locknet_rcab::{Credentials, LockNetClient, LockNetConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Connect
    let config = LockNetConfig::new("https://locknet.example.com", "example.com")?;
    let mut client = LockNetClient::new(config);

    let session = client
        .connection_request(Credentials::Login {
            username: "alice".into(),
            password: "secret".into(),
        })
        .await?;
    println!("Logged in as {} (session {})", session.user_id, session.session_id);

    // 2. Get the high-level agent
    let agent = client.get_agent().expect("agent");

    // 3. Set up cross-signing for WoT
    agent.security().setup_cross_signing().await?;

    // 4. Send a message
    let mut events = agent.subscribe();
    let chat = agent.chat(42).await?;
    chat.send("Hello, world!").await?;

    // 5. Process events
    while let Ok(event) = events.recv().await {
        println!("Event: {:?}", event);
    }

    client.disconnect().await?;
    Ok(())
}
```

## Examples

Check out the [`examples/`](./examples) directory for complete runnable programs:
- [`echo_bot.rs`](./examples/echo_bot.rs) — Connects, listens for messages, and echoes them back.
- [`send_message.rs`](./examples/send_message.rs) — CLI tool to log in and send a single message.
- [`persistent_login.rs`](./examples/persistent_login.rs) — Demonstrates using `SqliteStore` for session persistence.

## Security & Encryption

**Recovery Keys:** When exporting a key backup, you will receive a `RecoveryKey`. You **must** save this key securely. Losing it means losing access to your backed-up history; the server cannot recover it for you.

**Group Policies:** Policies like `HistoryVisibility` (who can read past messages) are enforced client-side. The server stores the policy as an opaque blob but cannot enforce or read it. A malicious server can withhold keys, but cannot grant unauthorized access.

## Docs

The crate is fully documented with [rustdoc](https://timestop34.github.io/locknet-rcab/). To view the generated documentation locally, run:

```bash
cargo doc --no-deps --open
```

## License

Licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).
