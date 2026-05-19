use std::{collections::HashMap, sync::Arc, time::Duration};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    db::{export_todos, merge_todos, now},
    models::Todo,
    state::AppState,
};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ReplicationMsg {
    Challenge {
        nonce: String,
        user_hash: String,
    },
    ChallengeResponse {
        nonce: String,
        signature: String,
        verifying_key: String,
    },
    SyncRequest {
        user_hash: String,
    },
    SyncData {
        todos: Vec<Todo>,
    },
    Error {
        message: String,
    },
}

pub async fn run_replication_server(
    signing_key: Arc<SigningKey>,
    user_pools: Arc<RwLock<HashMap<String, SqlitePool>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = match TcpListener::bind("0.0.0.0:11204").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("❌ Replication server bind failed (11204): {e}");
            return;
        }
    };
    println!("🔒 Authenticated replication server on port 11204");

    loop {
        let Ok((mut stream, _addr)) = listener.accept().await else {
            continue;
        };
        let sk = signing_key.clone();
        let pools = user_pools.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            let Ok(ReplicationMsg::Challenge { nonce, user_hash: _ }) =
                serde_json::from_slice::<ReplicationMsg>(&buf[..n])
            else {
                let err = serde_json::to_vec(&ReplicationMsg::Error {
                    message: "expected Challenge".to_string(),
                })
                .unwrap_or_default();
                let _ = stream.write_all(&err).await;
                return;
            };

            let sig: Signature = sk.sign(nonce.as_bytes());
            let vk_hex = hex::encode(sk.verifying_key().to_bytes());
            let response = ReplicationMsg::ChallengeResponse {
                nonce: nonce.clone(),
                signature: hex::encode(sig.to_bytes()),
                verifying_key: vk_hex,
            };
            let resp_bytes = serde_json::to_vec(&response).unwrap_or_default();
            if stream.write_all(&resp_bytes).await.is_err() {
                return;
            }

            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            let Ok(ReplicationMsg::SyncRequest {
                user_hash: req_hash,
            }) = serde_json::from_slice::<ReplicationMsg>(&buf[..n])
            else {
                return;
            };

            let pools_r = pools.read().await;
            let Some(pool) = pools_r.get(&req_hash) else {
                let err = serde_json::to_vec(&ReplicationMsg::Error {
                    message: "no data for that user_hash".to_string(),
                })
                .unwrap_or_default();
                let _ = stream.write_all(&err).await;
                return;
            };

            let todos = export_todos(pool).await.unwrap_or_default();
            let data = ReplicationMsg::SyncData { todos };
            let data_bytes = serde_json::to_vec(&data).unwrap_or_default();
            let _ = stream.write_all(&data_bytes).await;
        });
    }
}

/// Returns `true` if the connection and sync succeeded, `false` on any failure.
pub async fn pull_from_peer(
    peer_addr: &str,
    peer_port: u16,
    user_hash: &str,
    signing_key: &SigningKey,
    local_pool: &SqlitePool,
) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let addr = format!("{}:{}", peer_addr, peer_port);
    let mut stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Replication connect to {addr}: {e}");
            return false;
        }
    };

    let nonce = Uuid::new_v4().to_string();
    let challenge = ReplicationMsg::Challenge {
        nonce: nonce.clone(),
        user_hash: user_hash.to_string(),
    };
    let challenge_bytes = serde_json::to_vec(&challenge).unwrap_or_default();
    if stream.write_all(&challenge_bytes).await.is_err() {
        return false;
    }

    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n == 0 {
        return false;
    }
    let Ok(ReplicationMsg::ChallengeResponse {
        signature,
        verifying_key,
        ..
    }) = serde_json::from_slice::<ReplicationMsg>(&buf[..n])
    else {
        return false;
    };

    let vk_bytes = match hex::decode(&verifying_key) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let vk_arr: [u8; 32] = match vk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&vk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(&signature) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_arr);
    if vk.verify(nonce.as_bytes(), &sig).is_err() {
        eprintln!("❌ Signature verification failed for peer {addr}");
        return false;
    }

    let req = ReplicationMsg::SyncRequest {
        user_hash: user_hash.to_string(),
    };
    let req_bytes = serde_json::to_vec(&req).unwrap_or_default();
    if stream.write_all(&req_bytes).await.is_err() {
        return false;
    }

    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n == 0 {
        return false;
    }
    let Ok(ReplicationMsg::SyncData { todos }) =
        serde_json::from_slice::<ReplicationMsg>(&buf[..n])
    else {
        return false;
    };

    let merged = merge_todos(local_pool, todos).await;
    if merged > 0 {
        println!("✅ Merged {merged} changes via authenticated replication from {addr}");
    }
    true
}

pub async fn run_mesh_worker(state: AppState) {
    use crate::state::MAX_PEER_FAILURES;

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;

        let user_hashes: Vec<String> = { state.user_pools.read().await.keys().cloned().collect() };

        // Collect fingerprints of peers that are still within the beacon window
        let discovered_peers: Vec<crate::state::DiscoveredPeer> = {
            let p = state.peers.read().await;
            p.values()
                .filter(|p| now() - p.last_seen < 30_000)
                .cloned()
                .collect()
        };

        // Track which peers failed this round: fingerprint -> failed
        let mut failed_fingerprints: Vec<String> = Vec::new();

        for user_hash in &user_hashes {
            let pools_r = state.user_pools.read().await;
            let Some(local_pool) = pools_r.get(user_hash).cloned() else {
                continue;
            };
            drop(pools_r);

            for peer in &discovered_peers {
                let ok = pull_from_peer(
                    &peer.addr,
                    peer.replication_port,
                    user_hash,
                    &state.signing_key,
                    &local_pool,
                )
                .await;

                if !ok {
                    failed_fingerprints.push(peer.pubkey_fingerprint.clone());
                }
            }

            let manual: Vec<String> = sqlx::query("SELECT url FROM manual_peers")
                .fetch_all(&state.users_pool)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r| {
                    use sqlx::Row;
                    r.get::<String, _>("url")
                })
                .collect();

            for raw_url in manual {
                let url = if !raw_url.starts_with("http") {
                    format!("http://{}", raw_url)
                } else {
                    raw_url
                };
                let target = format!("{}/api/replication", url);
                if let Ok(res) = http_client.get(&target).send().await {
                    if let Ok(remote_todos) = res.json::<Vec<Todo>>().await {
                        let merged = merge_todos(&local_pool, remote_todos).await;
                        if merged > 0 {
                            println!("✅ Merged {merged} via HTTP gossip from {url}");
                        }
                    }
                }
            }
        }

        // Increment failure counters; evict peers that exceed the threshold.
        // The beacon listener will re-insert them if they come back online.
        if !failed_fingerprints.is_empty() {
            let mut peers = state.peers.write().await;
            let mut to_evict: Vec<String> = Vec::new();

            for fp in &failed_fingerprints {
                if let Some(peer) = peers.get_mut(fp) {
                    peer.consecutive_failures += 1;
                    if peer.consecutive_failures >= MAX_PEER_FAILURES {
                        to_evict.push(fp.clone());
                    }
                }
            }

            for fp in to_evict {
                if let Some(peer) = peers.remove(&fp) {
                    println!(
                        "🔌 Peer {} ({}) evicted after {} failures — will rediscover via beacon",
                        &fp[..12],
                        peer.addr,
                        MAX_PEER_FAILURES
                    );
                }
            }
        }
    }
}
