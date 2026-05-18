// =============================================================================
//  Autonomous Mesh CRDT Todo — Full Implementation
//  Steps: 1) Device Identity  2) Google OAuth PKCE  3) UDP Beacon
//         4) Authenticated Replication  5) LWW Tiebreaker  6) Frontend wiring
// =============================================================================

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row, SqlitePool,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use uuid::Uuid;

// =============================================================================
// STEP 1: Device Identity — Ed25519 keypair persisted to node.key
// =============================================================================

/// Loads the signing key from `node.key`, or generates and saves a new one.
fn load_or_generate_signing_key() -> SigningKey {
    if let Ok(bytes) = std::fs::read("node.key") {
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes.try_into().expect("node.key must be 32 bytes");
            return SigningKey::from_bytes(&arr);
        }
    }
    // Generate a fresh keypair and persist the secret bytes
    let signing_key = SigningKey::generate(&mut OsRng);
    std::fs::write("node.key", signing_key.to_bytes())
        .expect("Failed to write node.key — check filesystem permissions");
    println!("🔑 New Ed25519 keypair generated and saved to node.key");
    signing_key
}

/// Returns the hex-encoded SHA256 fingerprint of the verifying (public) key.
fn pubkey_fingerprint(vk: &VerifyingKey) -> String {
    let mut h = Sha256::new();
    h.update(vk.to_bytes());
    hex::encode(h.finalize())
}

// =============================================================================
// Data Structures
// =============================================================================

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Todo {
    id: String,
    title: String,
    completed: bool,
    deleted: bool,
    updated_at: i64,
    node_id: String,
}

#[derive(Deserialize, Debug)]
struct CreateTodo {
    title: String,
}

#[derive(Deserialize, Debug)]
struct UpdateTodo {
    completed: bool,
}

#[derive(Deserialize, Debug)]
struct PeerReq {
    url: String,
}

#[derive(Debug, Clone, Serialize)]
struct DiscoveredPeer {
    addr: String,
    user_hash: String,
    pubkey_fingerprint: String,
    replication_port: u16,
    last_seen: i64,
}

#[derive(Clone)]
struct AppState {
    users_pool: SqlitePool,
    user_pools: Arc<RwLock<HashMap<String, SqlitePool>>>,
    signing_key: Arc<SigningKey>,
    node_id: String,
    peers: Arc<RwLock<HashMap<String, DiscoveredPeer>>>,
    oauth_client_id: String,
    oauth_client_secret: String,
    oauth_redirect_uri: String,
}

// =============================================================================
// STEP 2: Google OAuth PKCE — login flow, token exchange, user_hash derivation
// =============================================================================

#[derive(Deserialize)]
struct OAuthCallback {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    id_token: String,
}

#[derive(Debug, Deserialize)]
struct GoogleClaims {
    sub: String,
    email: Option<String>,
}

fn user_hash_from_sub(sub: &str) -> String {
    let mut h = Sha256::new();
    h.update(sub.as_bytes());
    hex::encode(h.finalize())
}

enum GoogleClaimsErrors {
    String(String),
    Decode(base64::DecodeError),
    Json(serde_json::Error),
}

impl std::fmt::Display for GoogleClaimsErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoogleClaimsErrors::String(s) => write!(f, "Google Claims Error: {s}"),
            GoogleClaimsErrors::Decode(e) => write!(f, "Google Claims Error (base64): {e}"),
            GoogleClaimsErrors::Json(e) => write!(f, "Google Claims Error (json): {e}"),
        }
    }
}

fn decode_google_claims_unverified(id_token: &str) -> Result<GoogleClaims, GoogleClaimsErrors> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() < 2 {
        return Err(GoogleClaimsErrors::String("malformed id_token".to_string()));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| GoogleClaimsErrors::Decode(e))?;
    let claims: GoogleClaims =
        serde_json::from_slice(&payload).map_err(|e| GoogleClaimsErrors::Json(e))?;
    Ok(claims)
}

// =============================================================================
// STEP 3: UDP Beacon — broadcast + listener
// =============================================================================

#[derive(Serialize, Deserialize, Debug)]
struct BeaconPacket {
    user_hash: String,
    pubkey_fingerprint: String,
    replication_port: u16,
    nonce: String,
    nonce_sig: String,
}

async fn run_udp_beacon_broadcaster(signing_key: Arc<SigningKey>, node_id: String) {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ UDP broadcaster bind failed: {e}");
            return;
        }
    };
    sock.set_broadcast(true).ok();

    loop {
        let nonce = Uuid::new_v4().to_string();
        let sig: Signature = signing_key.sign(nonce.as_bytes());
        let packet = BeaconPacket {
            user_hash: "anonymous".to_string(),
            pubkey_fingerprint: node_id.clone(),
            replication_port: 11204,
            nonce: nonce.clone(),
            nonce_sig: hex::encode(sig.to_bytes()),
        };
        if let Ok(json) = serde_json::to_vec(&packet) {
            let _ = sock.send_to(&json, "255.255.255.255:8765").await;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run_udp_beacon_listener(peers: Arc<RwLock<HashMap<String, DiscoveredPeer>>>) {
    let sock = match UdpSocket::bind("0.0.0.0:8765").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ UDP listener bind failed (port 8765): {e}");
            return;
        }
    };
    let mut buf = [0u8; 4096];
    println!("📡 UDP beacon listener on port 8765");

    loop {
        let (len, src) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let Ok(packet) = serde_json::from_slice::<BeaconPacket>(&buf[..len]) else {
            continue;
        };

        let peer = DiscoveredPeer {
            addr: src.ip().to_string(),
            user_hash: packet.user_hash.clone(),
            pubkey_fingerprint: packet.pubkey_fingerprint.clone(),
            replication_port: packet.replication_port,
            last_seen: now(),
        };
        peers.write().await.insert(packet.pubkey_fingerprint, peer);
    }
}

// =============================================================================
// STEP 4: Authenticated Replication on port 11204
// =============================================================================

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
enum ReplicationMsg {
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

async fn run_replication_server(
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
            let Ok(ReplicationMsg::Challenge { nonce, user_hash }) =
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

async fn pull_from_peer(
    peer_addr: &str,
    peer_port: u16,
    user_hash: &str,
    signing_key: &SigningKey,
    local_pool: &SqlitePool,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let addr = format!("{}:{}", peer_addr, peer_port);
    let mut stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Replication connect to {addr}: {e}");
            return;
        }
    };

    let nonce = Uuid::new_v4().to_string();
    let challenge = ReplicationMsg::Challenge {
        nonce: nonce.clone(),
        user_hash: user_hash.to_string(),
    };
    let challenge_bytes = serde_json::to_vec(&challenge).unwrap_or_default();
    if stream.write_all(&challenge_bytes).await.is_err() {
        return;
    }

    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n == 0 {
        return;
    }
    let Ok(ReplicationMsg::ChallengeResponse {
        signature,
        verifying_key,
        ..
    }) = serde_json::from_slice::<ReplicationMsg>(&buf[..n])
    else {
        return;
    };

    let vk_bytes = match hex::decode(&verifying_key) {
        Ok(b) => b,
        Err(_) => return,
    };
    let vk_arr: [u8; 32] = match vk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return,
    };
    let vk = match VerifyingKey::from_bytes(&vk_arr) {
        Ok(k) => k,
        Err(_) => return,
    };
    let sig_bytes = match hex::decode(&signature) {
        Ok(b) => b,
        Err(_) => return,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return,
    };
    let sig = Signature::from_bytes(&sig_arr);
    if vk.verify(nonce.as_bytes(), &sig).is_err() {
        eprintln!("❌ Signature verification failed for peer {addr}");
        return;
    }

    let req = ReplicationMsg::SyncRequest {
        user_hash: user_hash.to_string(),
    };
    let req_bytes = serde_json::to_vec(&req).unwrap_or_default();
    if stream.write_all(&req_bytes).await.is_err() {
        return;
    }

    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n == 0 {
        return;
    }
    let Ok(ReplicationMsg::SyncData { todos }) =
        serde_json::from_slice::<ReplicationMsg>(&buf[..n])
    else {
        return;
    };

    let merged = merge_todos(local_pool, todos).await;
    if merged > 0 {
        println!("✅ Merged {merged} changes via authenticated replication from {addr}");
    }
}

// =============================================================================
// STEP 5: LWW Tiebreaker — (updated_at, node_id) lexicographic merge
// =============================================================================

async fn merge_todos(pool: &SqlitePool, todos: Vec<Todo>) -> usize {
    let merge_query = "
        INSERT INTO todos (id, title, completed, deleted, updated_at, node_id)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            title       = excluded.title,
            completed   = excluded.completed,
            deleted     = excluded.deleted,
            updated_at  = excluded.updated_at,
            node_id     = excluded.node_id
        WHERE
            (excluded.updated_at || '_' || excluded.node_id)
            > (todos.updated_at || '_' || todos.node_id);
    ";

    let mut count = 0usize;
    for t in todos {
        if let Ok(r) = sqlx::query(merge_query)
            .bind(&t.id)
            .bind(&t.title)
            .bind(t.completed)
            .bind(t.deleted)
            .bind(t.updated_at)
            .bind(&t.node_id)
            .execute(pool)
            .await
        {
            if r.rows_affected() > 0 {
                count += 1;
            }
        }
    }
    count
}

// =============================================================================
// Database helpers
// =============================================================================

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn row_to_todo(row: sqlx::sqlite::SqliteRow) -> Todo {
    Todo {
        id: row.get("id"),
        title: row.get("title"),
        completed: row.get("completed"),
        deleted: row.get("deleted"),
        updated_at: row.get("updated_at"),
        node_id: row.try_get("node_id").unwrap_or_default(),
    }
}

async fn open_user_pool(user_hash: &str) -> SqlitePool {
    let path = format!("sqlite://todos_{}.db", user_hash);
    let opts = SqliteConnectOptions::from_str(&path)
        .expect("bad sqlite path")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .connect_with(opts)
        .await
        .expect("failed to open user DB");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS todos (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            completed BOOLEAN NOT NULL DEFAULT 0,
            deleted BOOLEAN NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL,
            node_id TEXT NOT NULL DEFAULT ''
        );",
    )
    .execute(&pool)
    .await
    .expect("failed to init todos table");

    pool
}

async fn export_todos(pool: &SqlitePool) -> Result<Vec<Todo>, sqlx::Error> {
    let rows = sqlx::query("SELECT * FROM todos").fetch_all(pool).await?;
    Ok(rows.into_iter().map(row_to_todo).collect())
}

// =============================================================================
// HTTP Handlers
// =============================================================================

async fn handle_login(State(state): State<AppState>) -> Response {
    let verifier_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let code_verifier = URL_SAFE_NO_PAD.encode(&verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

    let csrf = Uuid::new_v4().to_string();

    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?\
         client_id={client_id}\
         &redirect_uri={redirect_uri}\
         &response_type=code\
         &scope=openid%20email%20profile\
         &code_challenge={code_challenge}\
         &code_challenge_method=S256\
         &state={csrf}",
        client_id = state.oauth_client_id,
        redirect_uri = urlencoding_encode(&state.oauth_redirect_uri),
        code_challenge = code_challenge,
        csrf = csrf,
    );

    let cookie_val = format!("{}:{}", csrf, code_verifier);
    let mut response = Redirect::temporary(&auth_url).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("pkce_state={}; HttpOnly; Path=/; Max-Age=600", cookie_val)
            .parse()
            .unwrap(),
    );
    response
}

async fn handle_oauth_callback(
    State(state): State<AppState>,
    Query(params): Query<OAuthCallback>,
    jar: CookieJar,
) -> Response {
    let pkce_cookie = match jar.get("pkce_state") {
        Some(c) => c.value().to_string(),
        None => return (StatusCode::BAD_REQUEST, "Missing pkce_state cookie").into_response(),
    };
    let parts: Vec<&str> = pkce_cookie.splitn(2, ':').collect();
    if parts.len() != 2 || parts[0] != params.state {
        return (StatusCode::BAD_REQUEST, "CSRF state mismatch").into_response();
    }
    let code_verifier = parts[1].to_string();

    let client = Client::new();
    let res = match client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", params.code.as_str()),
            ("client_id", state.oauth_client_id.as_str()),
            ("client_secret", state.oauth_client_secret.as_str()), // Added this!
            ("redirect_uri", state.oauth_redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", code_verifier.as_str()),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("token exchange network error: {e}"),
            )
                .into_response()
        }
    };

    // Better error surfacing if Google rejects the token request
    if !res.status().is_success() {
        let err_body = res.text().await.unwrap_or_default();
        return (
            StatusCode::BAD_REQUEST,
            format!("Google OAuth rejected the exchange: {err_body}"),
        )
            .into_response();
    }

    let token_res: GoogleTokenResponse = match res.json().await {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("token parse: {e}")).into_response(),
    };

    let claims = match decode_google_claims_unverified(&token_res.id_token) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("jwt: {e}")).into_response(),
    };

    let user_hash = user_hash_from_sub(&claims.sub);

    sqlx::query(
        "INSERT OR REPLACE INTO users (user_hash, pubkey_fingerprint, last_seen)
         VALUES (?, ?, ?)",
    )
    .bind(&user_hash)
    .bind(&state.node_id)
    .bind(now())
    .execute(&state.users_pool)
    .await
    .ok();

    {
        let mut pools = state.user_pools.write().await;
        if !pools.contains_key(&user_hash) {
            let pool = open_user_pool(&user_hash).await;
            pools.insert(user_hash.clone(), pool);
        }
    }

    let session_payload = format!("{}:{}", user_hash, now());
    let sig: ed25519_dalek::Signature = state.signing_key.sign(session_payload.as_bytes());
    let session_token = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(session_payload.as_bytes()),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    );

    let mut resp = Redirect::temporary("/").into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::SET_COOKIE,
        format!(
            "session={}; HttpOnly; Path=/; Max-Age=2592000",
            session_token
        ) // Changed to 30 days
        .parse()
        .unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        "pkce_state=; HttpOnly; Path=/; Max-Age=0".parse().unwrap(),
    );
    resp
}

#[derive(Serialize)]
struct MeResponse {
    user_hash: String,
    node_id: String,
    logged_in: bool,
}

async fn handle_me(State(state): State<AppState>, jar: CookieJar) -> Json<MeResponse> {
    if let Some(user_hash) = verify_session(&jar, &state.signing_key) {
        Json(MeResponse {
            user_hash,
            node_id: state.node_id.clone(),
            logged_in: true,
        })
    } else {
        Json(MeResponse {
            user_hash: String::new(),
            node_id: state.node_id.clone(),
            logged_in: false,
        })
    }
}

fn verify_session(jar: &CookieJar, signing_key: &SigningKey) -> Option<String> {
    let cookie_val = jar.get("session")?.value().to_string();
    let mut parts = cookie_val.splitn(2, '.');
    let payload_b64 = parts.next()?;
    let sig_b64 = parts.next()?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().ok()?;
    let sig = Signature::from_bytes(&sig_arr);

    signing_key
        .verifying_key()
        .verify(&payload_bytes, &sig)
        .ok()?;

    let payload_str = std::str::from_utf8(&payload_bytes).ok()?;
    let user_hash = payload_str.split(':').next()?.to_string();
    Some(user_hash)
}

async fn get_user_pool(jar: &CookieJar, state: &AppState) -> Option<SqlitePool> {
    // 1. Verify the cookie signature is valid
    let user_hash = verify_session(jar, &state.signing_key)?;

    // 2. Fast path: Is the pool already in memory?
    {
        let pools = state.user_pools.read().await;
        if let Some(pool) = pools.get(&user_hash) {
            return Some(pool.clone());
        }
    }

    // 3. Slow path (Server restarted): Cookie is valid, but memory is empty.
    // Re-open the SQLite database and cache it in the HashMap.
    println!("♻️ Restoring session pool for user {}", &user_hash[..8]);
    let mut pools = state.user_pools.write().await;
    let pool = open_user_pool(&user_hash).await;
    pools.insert(user_hash.clone(), pool.clone());

    Some(pool)
}

async fn list_active_todos(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<Todo>>, (StatusCode, String)> {
    let pool = get_user_pool(&jar, &state)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "not logged in".to_string()))?;

    let rows = sqlx::query("SELECT * FROM todos WHERE deleted = 0 ORDER BY updated_at DESC")
        .fetch_all(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(rows.into_iter().map(row_to_todo).collect()))
}

async fn create_todo(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<CreateTodo>,
) -> Result<(StatusCode, Json<Todo>), (StatusCode, String)> {
    let pool = get_user_pool(&jar, &state)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "not logged in".to_string()))?;

    let id = Uuid::new_v4().to_string();
    let updated_at = now();

    sqlx::query(
        "INSERT INTO todos (id, title, completed, deleted, updated_at, node_id)
         VALUES (?, ?, 0, 0, ?, ?)",
    )
    .bind(&id)
    .bind(&payload.title)
    .bind(updated_at)
    .bind(&state.node_id)
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(Todo {
            id,
            title: payload.title,
            completed: false,
            deleted: false,
            updated_at,
            node_id: state.node_id.clone(),
        }),
    ))
}

async fn update_todo(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<UpdateTodo>,
) -> Result<StatusCode, (StatusCode, String)> {
    let pool = get_user_pool(&jar, &state)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "not logged in".to_string()))?;

    sqlx::query("UPDATE todos SET completed = ?, updated_at = ?, node_id = ? WHERE id = ?")
        .bind(payload.completed)
        .bind(now())
        .bind(&state.node_id)
        .bind(id)
        .execute(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::OK)
}

async fn delete_todo(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let pool = get_user_pool(&jar, &state)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "not logged in".to_string()))?;

    sqlx::query("UPDATE todos SET deleted = 1, updated_at = ?, node_id = ? WHERE id = ?")
        .bind(now())
        .bind(&state.node_id)
        .bind(id)
        .execute(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn get_peers_handler(State(state): State<AppState>) -> Json<Vec<serde_json::Value>> {
    let auto_peers: Vec<serde_json::Value> = {
        let p = state.peers.read().await;
        p.values()
            .map(|peer| {
                serde_json::json!({
                    "addr": peer.addr,
                    "user_hash": peer.user_hash,
                    "fingerprint": peer.pubkey_fingerprint,
                    "port": peer.replication_port,
                    "last_seen": peer.last_seen,
                    "source": "udp"
                })
            })
            .collect()
    };
    Json(auto_peers)
}

async fn add_peer_manual(
    State(state): State<AppState>,
    Json(peer): Json<PeerReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query("INSERT OR IGNORE INTO manual_peers (url) VALUES (?)")
        .bind(peer.url.trim_end_matches('/'))
        .execute(&state.users_pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::CREATED)
}

async fn export_all_data(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<Todo>>, (StatusCode, String)> {
    let pool = get_user_pool(&jar, &state)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "not logged in".to_string()))?;
    let todos = export_todos(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(todos))
}

async fn run_mesh_worker(state: AppState) {
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;

        let user_hashes: Vec<String> = { state.user_pools.read().await.keys().cloned().collect() };

        let discovered_peers: Vec<DiscoveredPeer> = {
            let p = state.peers.read().await;
            p.values()
                .filter(|p| now() - p.last_seen < 30_000)
                .cloned()
                .collect()
        };

        for user_hash in &user_hashes {
            let pools_r = state.user_pools.read().await;
            let Some(local_pool) = pools_r.get(user_hash).cloned() else {
                continue;
            };
            drop(pools_r);

            for peer in &discovered_peers {
                pull_from_peer(
                    &peer.addr,
                    peer.replication_port,
                    user_hash,
                    &state.signing_key,
                    &local_pool,
                )
                .await;
            }

            let manual: Vec<String> = sqlx::query("SELECT url FROM manual_peers")
                .fetch_all(&state.users_pool)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r| r.get::<String, _>("url"))
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
    }
}

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

    {
        let sk = signing_key.clone();
        let nid = node_id.clone();
        tokio::spawn(async move {
            run_udp_beacon_broadcaster(sk, nid).await;
        });
    }
    {
        let peers = state.peers.clone();
        tokio::spawn(async move {
            run_udp_beacon_listener(peers).await;
        });
    }

    {
        let sk = signing_key.clone();
        let up = state.user_pools.clone();
        tokio::spawn(async move {
            run_replication_server(sk, up).await;
        });
    }

    {
        let s = state.clone();
        tokio::spawn(async move {
            run_mesh_worker(s).await;
        });
    }

    // ── Pre-load known users for background syncing ──────────────────────────
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
        .route("/auth/callback", get(handle_oauth_callback))
        .route("/auth/me", get(handle_me))
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

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
