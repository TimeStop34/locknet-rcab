//! Cryptographically secure random bytes.
//!
//! Wraps `getrandom` into `Result`-returning helpers so library code never
//! panics on RNG failure. All public API that needs randomness goes through
//! this module.

use crate::core::errors::{LockNetError, Result};

/// Fill `buf` with cryptographically secure random bytes.
///
/// # Errors
///
/// Returns [`LockNetError::InvalidResponse`] if the OS RNG fails (extremely
/// rare on supported platforms — usually means `/dev/urandom` is unavailable
/// or `getrandom(2)` is not implemented).
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf)
        .map_err(|e| LockNetError::InvalidResponse(format!("RNG failure: {e}")))
}

/// Allocate `N` random bytes.
///
/// # Errors
///
/// Same as [`fill_random`].
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    fill_random(&mut buf)?;
    Ok(buf)
}

/// Generate a lowercase hex transaction ID (8 random bytes → 16 hex chars).
///
/// # Errors
///
/// Same as [`fill_random`].
pub fn random_txid() -> Result<String> {
    let bytes = random_bytes::<8>()?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}
