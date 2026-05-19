use std::{collections::HashMap, sync::Arc};

use ed25519_dalek::SigningKey;
use serde::Serialize;
use sqlx::SqlitePool;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredPeer {
    pub addr: String,
    pub user_hash: String,
    pub pubkey_fingerprint: String,
    pub replication_port: u16,
    pub last_seen: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub users_pool: SqlitePool,
    pub user_pools: Arc<RwLock<HashMap<String, SqlitePool>>>,
    pub signing_key: Arc<SigningKey>,
    pub node_id: String,
    pub peers: Arc<RwLock<HashMap<String, DiscoveredPeer>>>,
    pub oauth_client_id: String,
    pub oauth_client_secret: String,
    pub oauth_redirect_uri: String,
}
