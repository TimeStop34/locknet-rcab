mod common;

use std::collections::HashMap;
use std::time::Duration;

use locknet_rcab::core::crypto::signature::{sign_b64, CrossSigningKeysPrivate};
use locknet_rcab::models::{CrossSigningKey, CrossSigningKeys, Signatures};
use locknet_rcab::{Credentials, LockNetClient, LockNetLowAgent};

fn build_cs_payload(user_id: i64, keys: &CrossSigningKeysPrivate) -> CrossSigningKeys {
    let msk_pub = keys.msk_pub_b64();
    let ssk_pub = keys.ssk_pub_b64();
    let usk_pub = keys.usk_pub_b64();
    let ssk_sig = sign_b64(&keys.msk, &ssk_pub).expect("ssk sig");
    let usk_sig = sign_b64(&keys.msk, &usk_pub).expect("usk sig");

    let mut ssk_inner = HashMap::new();
    ssk_inner.insert("master".to_string(), ssk_sig);
    let mut ssk_sigs = HashMap::new();
    ssk_sigs.insert(user_id.to_string(), ssk_inner);

    let mut usk_inner = HashMap::new();
    usk_inner.insert("master".to_string(), usk_sig);
    let mut usk_sigs = HashMap::new();
    usk_sigs.insert(user_id.to_string(), usk_inner);

    CrossSigningKeys {
        master_key: CrossSigningKey { key: msk_pub, signatures: HashMap::new() },
        self_signing_key: CrossSigningKey { key: ssk_pub, signatures: ssk_sigs },
        user_signing_key: CrossSigningKey { key: usk_pub, signatures: usk_sigs },
    }
}

async fn setup_cs(low: &LockNetLowAgent) -> CrossSigningKeysPrivate {
    let uid = low.user_id();
    let sid = low.session_id();

    let keys = CrossSigningKeysPrivate::generate();
    low.crypto()
        .upload_cross_signing_keys(build_cs_payload(uid, &keys))
        .await
        .expect("upload cs");

    let own_ed = {
        let acc = low.store().account().await;
        let acc = acc.lock().await;
        acc.ed25519_public_b64()
    };
    let dev_sig = sign_b64(&keys.ssk, &own_ed).expect("sign device");
    low.crypto()
        .upload_signatures(Signatures {
            user_signatures: HashMap::new(),
            device_signatures: [(sid, dev_sig)].into_iter().collect(),
        })
        .await
        .expect("upload device sig");

    keys
}

async fn sign_msk(
    signer_low: &LockNetLowAgent,
    signer_keys: &CrossSigningKeysPrivate,
    target_uid: i64,
) -> Result<(), String> {
    let query = signer_low
        .crypto()
        .query_cross_signing_keys(vec![target_uid])
        .await
        .map_err(|e| format!("query target msk: {e:?}"))?;
    let target_msk = query
        .get(&target_uid)
        .map(|u| u.master_key.key.clone())
        .ok_or_else(|| format!("target {target_uid} msk not found"))?;

    let sig = sign_b64(&signer_keys.usk, &target_msk).map_err(|e| format!("sign: {e:?}"))?;

    signer_low
        .crypto()
        .upload_signatures(Signatures {
            user_signatures: [(target_uid, sig)].into_iter().collect(),
            device_signatures: HashMap::new(),
        })
        .await
        .map_err(|e| format!("upload sig: {e:?}"))?;

    Ok(())
}

// ---- тесты остаются как есть, они уже без `.store()` ----