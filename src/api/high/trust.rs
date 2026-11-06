use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use crate::api::low::agent::LockNetLowAgent;
use crate::core::crypto::signature::verify_b64;
use crate::core::errors::Result;

/// Граф доверия (Web of Trust) на основе cross-signing подписей.
///
/// Узел — user_id.
/// Ребро `A -> B` — `A.user_signing_key` подписал `B.master_key`.
///
/// Граф строится из `query_cross_signing_keys` и **верифицирует** каждую
/// подпись Ed25519, а не доверяет серверу на слово.
///
/// Транзитивность: `A -> B -> C` означает, что `A` доверяет `C`
/// через цепочку (B подтвердил C своим USK, A подтвердил B своим USK).
#[derive(Debug, Default, Clone)]
pub struct TrustGraph {
    edges: HashMap<i64, HashSet<i64>>,
}

impl TrustGraph {
    /// Строит граф из cross-signing ключей указанных user'ов.
    ///
    /// Возвращает граф с **уже проверенными** рёбрами.
    /// Невалидные подписи (или отсутствующие ключи) молча отбрасываются.
    pub async fn build(
        low: &Arc<LockNetLowAgent>,
        user_ids: &[i64],
    ) -> Result<Self> {
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

                // Самоподпись бессмысленна — MSK не подписывает сам себя
                // (в нашей схеме MSK подписывает SSK и USK, но не наоборот).
                if signer_uid == *target_uid {
                    continue;
                }

                let Some(sig) = sigs.get("user_signing") else {
                    continue;
                };

                // Публичный USK signer'а берём из того же query.
                // Если signer'а нет в query — не можем проверить, ребро отбрасываем.
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

    /// BFS от `from`: все user_id, достижимые по цепочке доверия.
    /// `from` включается в результат (я доверяю себе по определению).
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

    /// Проверка прямой подписи (без транзитивности). Полезно для отладки/тестов.
    #[allow(dead_code)]
    pub fn has_direct(&self, from: i64, to: i64) -> bool {
        self.edges
            .get(&from)
            .map(|s| s.contains(&to))
            .unwrap_or(false)
    }
}