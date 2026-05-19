// =============================================================================
//  Autonomous Mesh CRDT Todo — Full Implementation
//  Steps: 1) Device Identity  2) Google OAuth PKCE  3) UDP Beacon
//         4) Authenticated Replication  5) LWW Tiebreaker  6) Frontend wiring
// =============================================================================

mod auth;
mod beacon;
mod db;
mod handlers;
mod identity;
mod models;
mod replication;
mod state;

use std::{collections::HashMap, str::FromStr, sync::Arc};

use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row,
};
use tokio::sync::RwLock;
use tower_http::services::ServeDir;

use auth::{
    delete_my_data, handle_login, handle_logout, handle_me, handle_oauth_callback,
};
use beacon::{run_udp_beacon_broadcaster, run_udp_beacon_listener};
use db::open_user_pool;
use handlers::{
    add_peer_manual, create_todo, delete_todo, export_all_data, get_peers_handler,
    list_active_todos, update_todo,
};
use identity::{load_or_generate_signing_key, pubkey_fingerprint};
use replication::{run_mesh_worker, run_replication_server};
use state::AppState;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let signing_key = Arc::new(load_or_generate_signing_key());
    let vk = signing_key.verifying_key();
    let node_id = pubkey_fingerprint(&vk);
    println!("🆔 Node ID (pubkey fingerprint): {}", &node_id[..16]);

    let users_opts = SqliteConnectOptions::from_str("sqlite://users.db")
        .expect("bad users.db path")
        .create_if_missing(true);
    let users_pool = SqlitePoolOptions::new()
        .connect_with(users_opts)
        .await
        .expect("failed to open users.db");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            user_hash TEXT PRIMARY KEY,
            pubkey_fingerprint TEXT NOT NULL,
            last_seen INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS manual_peers (
            url TEXT PRIMARY KEY
        );",
    )
    .execute(&users_pool)
    .await
    .expect("failed to init users.db schema");

    let oauth_client_id =
        std::env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID in .env");
    let oauth_client_secret =
        std::env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET in .env");
    let oauth_redirect_uri = std::env::var("OAUTH_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:8080/auth/callback".to_string());

    let state = AppState {
        users_pool: users_pool.clone(),
        user_pools: Arc::new(RwLock::new(HashMap::new())),
        signing_key: signing_key.clone(),
        node_id: node_id.clone(),
        peers: Arc::new(RwLock::new(HashMap::new())),
        oauth_client_id,
        oauth_client_secret,
        oauth_redirect_uri,
    };

    // ── Background tasks ──────────────────────────────────────────────────────
    {
        let sk = signing_key.clone();
        let nid = node_id.clone();
        tokio::spawn(async move { run_udp_beacon_broadcaster(sk, nid).await });
    }
    {
        let peers = state.peers.clone();
        tokio::spawn(async move { run_udp_beacon_listener(peers).await });
    }
    {
        let sk = signing_key.clone();
        let up = state.user_pools.clone();
        tokio::spawn(async move { run_replication_server(sk, up).await });
    }
    {
        let s = state.clone();
        tokio::spawn(async move { run_mesh_worker(s).await });
    }

    // ── Pre-load known users for background syncing ───────────────────────────
    println!("📦 Pre-loading user databases for background mesh sync...");
    let known_users: Vec<String> = sqlx::query("SELECT user_hash FROM users")
        .fetch_all(&users_pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.get("user_hash"))
        .collect();

    let mut pools_write = state.user_pools.write().await;
    for hash in known_users {
        let pool = open_user_pool(&hash).await;
        pools_write.insert(hash, pool);
    }
    drop(pools_write);
    // ─────────────────────────────────────────────────────────────────────────

    let app = Router::new()
        .route("/auth/login", get(handle_login))
        .route("/auth/logout", get(handle_logout))
        .route("/auth/callback", get(handle_oauth_callback))
        .route("/auth/me", get(handle_me))
        .route("/auth/delete-data", post(delete_my_data))
        .route("/api/todos", get(list_active_todos).post(create_todo))
        .route("/api/todos/{id}", patch(update_todo).delete(delete_todo))
        .route("/api/peers", get(get_peers_handler).post(add_peer_manual))
        .route("/api/replication", get(export_all_data))
        .fallback_service(ServeDir::new("assets"))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🚀 Autonomous Mesh Node running on http://0.0.0.0:8080");
    axum::serve(listener, app).await.unwrap();
}
