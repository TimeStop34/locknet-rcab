//! Web-of-Trust graph built from cross-signing signatures.
//!
//! A directed edge `A -> B` means "A's user-signing key (USK) has signed B's
//! master signing key (MSK)". Trust is transitive: if A trusts B and B trusts
//! C, A trusts C. The graph is validated locally — every edge requires a
//! verifiable Ed25519 signature; the server cannot forge trust.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use crate::api::low::agent::LockNetLowAgent;
use crate::core::crypto::signature::verify_b64;
use crate::core::errors::Result;

/// Web-of-Trust graph.
///
/// Node = `user_id`, edge `A -> B` = `A.user_signing_key` signed
/// `B.master_key`.
///
/// Built by [`TrustGraph::build`] from
/// [`crate::api::low::helpers::LockNetCryptoHelper::query_cross_signing_keys`];
/// every edge is verified with Ed25519, not trusted blindly.
#[derive(Debug, Default, Clone)]
pub struct TrustGraph {
    edges: HashMap<i64, HashSet<i64>>,
}

impl TrustGraph {
    /// Build a graph from the cross-signing keys of `user_ids`.
    ///
    /// Only edges with a valid Ed25519 signature are included. Missing keys
    /// and invalid signatures are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying `query_cross_signing_keys` call
    /// fails (e.g. transport error, request timeout).
    pub async fn build(low: &Arc<LockNetLowAgent>, user_ids: &[i64]) -> Result<Self> {
        if user_ids.is_empty() {
            return Ok(Self::default());
        }

        let query = low
            .crypto()
            .query_cross_signing_keys(user_ids.to_vec())
            .await?;

        let mut edges: HashMap<i64, HashSet<i64>> = HashMap::new();

        for (target_uid, target_entry) in &query {
            let target_msk_b64 = &target_entry.master_key.key;

            for (signer_uid_str, sigs) in &target_entry.master_key.signatures {
                let signer_uid: i64 = match signer_uid_str.parse() {
                    Ok(u) => u,
                    Err(_) => continue,
                };

                // Self-signatures carry no trust information.
                if signer_uid == *target_uid {
                    continue;
                }

                let Some(sig) = sigs.get("user_signing") else {
                    continue;
                };

                // We can only verify edges from signers we have keys for.
                let Some(signer_entry) = query.get(&signer_uid) else {
                    continue;
                };
                let Some(usk_key) = signer_entry.user_signing_key.as_ref() else {
                    continue;
                };

                if verify_b64(&usk_key.key, target_msk_b64, sig).is_ok() {
                    edges.entry(signer_uid).or_default().insert(*target_uid);
                }
            }
        }

        Ok(Self { edges })
    }

    /// BFS from `from`: every `user_id` reachable via the trust chain.
    ///
    /// `from` is included (a user trusts themself by definition).
    pub fn reachable_from(&self, from: i64) -> HashSet<i64> {
        let mut visited: HashSet<i64> = HashSet::new();
        visited.insert(from);

        let mut queue: VecDeque<i64> = VecDeque::from([from]);
        while let Some(uid) = queue.pop_front() {
            if let Some(neighbors) = self.edges.get(&uid) {
                for &n in neighbors {
                    if visited.insert(n) {
                        queue.push_back(n);
                    }
                }
            }
        }
        visited
    }

    /// Check for a direct edge only (no transitivity). Useful for tests and
    /// debugging.
    #[allow(dead_code)]
    pub fn has_direct(&self, from: i64, to: i64) -> bool {
        self.edges
            .get(&from)
            .map(|s| s.contains(&to))
            .unwrap_or(false)
    }
}
