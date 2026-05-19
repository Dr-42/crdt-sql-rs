use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;

use crate::{
    db::{export_todos, get_user_pool, now},
    models::{CreateTodo, PeerReq, Todo, UpdateTodo},
    state::AppState,
};

pub async fn list_active_todos(
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

    Ok(Json(
        rows.into_iter()
            .map(crate::db::row_to_todo)
            .collect(),
    ))
}

pub async fn create_todo(
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

pub async fn update_todo(
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

pub async fn delete_todo(
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

pub async fn get_peers_handler(State(state): State<AppState>) -> Json<Vec<serde_json::Value>> {
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

pub async fn add_peer_manual(
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

pub async fn export_all_data(
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
