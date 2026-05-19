use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    db::{get_user_pool, now, open_user_pool},
    identity::{urlencoding_encode, verify_session},
    state::AppState,
};

// ── OAuth types ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct OAuthCallback {
    pub code: String,
    pub state: String,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    id_token: String,
}

#[derive(Debug, Deserialize)]
struct GoogleClaims {
    sub: String,
    #[allow(dead_code)]
    email: Option<String>,
}

enum GoogleClaimsError {
    String(String),
    Decode(base64::DecodeError),
    Json(serde_json::Error),
}

impl std::fmt::Display for GoogleClaimsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoogleClaimsError::String(s) => write!(f, "Google Claims Error: {s}"),
            GoogleClaimsError::Decode(e) => write!(f, "Google Claims Error (base64): {e}"),
            GoogleClaimsError::Json(e) => write!(f, "Google Claims Error (json): {e}"),
        }
    }
}

fn decode_google_claims_unverified(id_token: &str) -> Result<GoogleClaims, GoogleClaimsError> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() < 2 {
        return Err(GoogleClaimsError::String("malformed id_token".to_string()));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(GoogleClaimsError::Decode)?;
    let claims: GoogleClaims =
        serde_json::from_slice(&payload).map_err(GoogleClaimsError::Json)?;
    Ok(claims)
}

pub fn user_hash_from_sub(sub: &str) -> String {
    let mut h = Sha256::new();
    h.update(sub.as_bytes());
    hex::encode(h.finalize())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

pub async fn handle_login(State(state): State<AppState>) -> Response {
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

pub async fn handle_logout() -> Response {
    let mut resp = Redirect::temporary("/").into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        "session=; HttpOnly; Path=/; Max-Age=0".parse().unwrap(),
    );
    resp
}

pub async fn handle_oauth_callback(
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
            ("client_secret", state.oauth_client_secret.as_str()),
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
        )
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
pub struct MeResponse {
    user_hash: String,
    node_id: String,
    logged_in: bool,
}

pub async fn handle_me(State(state): State<AppState>, jar: CookieJar) -> Json<MeResponse> {
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

pub async fn delete_my_data(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, (StatusCode, String)> {
    let user_hash = verify_session(&jar, &state.signing_key)
        .ok_or((StatusCode::UNAUTHORIZED, "not logged in".to_string()))?;

    // Mark every todo as deleted (CRDT tombstone — propagates to peers)
    {
        let pools = state.user_pools.read().await;
        if let Some(pool) = pools.get(&user_hash) {
            sqlx::query("UPDATE todos SET deleted = 1, updated_at = ?, node_id = ?")
                .bind(now())
                .bind(&state.node_id)
                .execute(pool)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    // Clear session
    let mut resp = (StatusCode::OK, "data deleted").into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        "session=; HttpOnly; Path=/; Max-Age=0".parse().unwrap(),
    );
    Ok(resp)
}

// Need the Signer trait in scope for signing_key.sign()
use ed25519_dalek::Signer;
