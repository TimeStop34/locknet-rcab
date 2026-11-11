# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/TimeStop34/locknet-rcab/security/advisories/new).

*(Для этого включи в репозитории: Settings → Security → Private vulnerability reporting → Enable.)*

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a minimal proof-of-concept.
- Affected versions of `locknet-rcab` (if known).
- Any suggested mitigations.

You can expect an initial response within **72 hours**. We ask that you give us reasonable time to address the issue and coordinate disclosure before making it public.

## Scope

**In scope:**

- The `locknet-rcab` library (`src/`), in particular:
  - Olm and Megolm session handling.
  - SAS and QR verification flows.
  - Cross-signing and Web-of-Trust resolution.
  - Group policy encryption (`encrypted_group_data`).
  - Key backup (recovery key handling, XSalsa20-Poly1305 item encryption).
- Cryptographic defaults (algorithm choices, key derivation, MAC verification).

**Out of scope:**

- The LockNet server (separate repository).
- Attacker models that require an already-compromised device, root, or memory access.
- Denial of service via unbounded client-side resources (rate limiting is the server's responsibility).
- Social engineering that does not exploit a flaw in the library.

## Supported Versions

Only the latest stable release (`1.0.x`) receives security fixes. Pre-release versions (`1.0.0-alpha`, `1.0.0-beta`) are development builds and are **not** supported for production use.

| Version      | Supported          |
|--------------|--------------------|
| 1.0.x        | :white_check_mark: |
| 1.0.0-beta   | :x:                |
| 1.0.0-alpha  | :x:                |

## Threat Model (summary)

`locknet-rcab` assumes:

- The server is **honest-but-curious**: it may read, store, and replay any plaintext metadata (group IDs, member lists, message timestamps, ciphertexts), but it cannot forge Olm/Megolm ciphertexts or tamper with `encrypted_group_data` without detection.
- The user's device is **not compromised** at the OS level. If the device is compromised, the attacker has access to the SQLite database and the (decrypted) session keys in memory — no client-side cryptography can prevent that.
- The recovery key for a key backup is stored **outside** this library by the application (Keychain, KWallet, TPM, user prompt) and is not accessible to a network attacker.

Known limitations are documented inline (`# Limitations` sections in rustdoc) and in the project README.