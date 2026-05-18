use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, patch, post},
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower_http::services::ServeDir;
use uuid::Uuid;

// --- Data Structures ---

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Todo {
    id: String,
    title: String,
    completed: bool,
    deleted: bool,
    updated_at: i64,
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
struct Peer {
    url: String,
}

// Utility for Wall Clock time
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

// --- Main Engine ---

#[tokio::main]
async fn main() {
    let connect_options = SqliteConnectOptions::from_str("sqlite://todos.db")
        .expect("Invalid connection string")
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .connect_with(connect_options)
        .await
        .expect("Failed to connect to SQLite database");

    // Initialize Schema
    sqlx::query(
        "
        CREATE TABLE IF NOT EXISTS todos (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            completed BOOLEAN NOT NULL DEFAULT 0,
            deleted BOOLEAN NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS peers (
            url TEXT PRIMARY KEY
        );
        ",
    )
    .execute(&pool)
    .await
    .expect("Failed to initialize database schema");

    // 🚀 SPAWN THE MESH WORKER
    // This runs completely independently of the web server
    let worker_pool = pool.clone();
    tokio::spawn(async move {
        run_mesh_gossip_protocol(worker_pool).await;
    });

    // Route mapping
    let app = Router::new()
        .route("/api/todos", get(list_active_todos).post(create_todo))
        .route("/api/todos/{id}", patch(update_todo).delete(delete_todo))
        .route("/api/peers", get(get_peers).post(add_peer))
        .route("/api/replication", get(export_all_data))
        .fallback_service(ServeDir::new("assets"))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("Autonomous Mesh Node running on port 8080");

    axum::serve(listener, app).await.unwrap();
}

// --- The Autonomous Mesh Worker ---

async fn run_mesh_gossip_protocol(pool: SqlitePool) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;

        let peers: Vec<String> = match sqlx::query("SELECT url FROM peers").fetch_all(&pool).await {
            Ok(rows) => rows.into_iter().map(|r| r.get("url")).collect(),
            Err(_) => continue,
        };

        for peer_url in peers {
            // 1. Auto-inject http:// if forgotten
            let url = if !peer_url.starts_with("http") {
                format!("http://{}", peer_url)
            } else {
                peer_url.clone()
            };

            let target = format!("{}/api/replication", url);

            // 2. Add verbose terminal logging
            match client.get(&target).send().await {
                Ok(res) => {
                    if let Ok(remote_todos) = res.json::<Vec<Todo>>().await {
                        let merge_query = "
                            INSERT INTO todos (id, title, completed, deleted, updated_at)
                            VALUES (?, ?, ?, ?, ?)
                            ON CONFLICT(id) DO UPDATE SET
                                title = excluded.title,
                                completed = excluded.completed,
                                deleted = excluded.deleted,
                                updated_at = excluded.updated_at
                            WHERE excluded.updated_at > todos.updated_at;
                        ";

                        let mut merged_count = 0;
                        for t in remote_todos {
                            let result = sqlx::query(merge_query)
                                .bind(t.id)
                                .bind(t.title)
                                .bind(t.completed)
                                .bind(t.deleted)
                                .bind(t.updated_at)
                                .execute(&pool)
                                .await;

                            // Count how many rows were actually updated/inserted
                            if let Ok(q) = result {
                                if q.rows_affected() > 0 {
                                    merged_count += 1;
                                }
                            }
                        }

                        if merged_count > 0 {
                            println!(
                                "✅ Successfully merged {} changes from {}",
                                merged_count, url
                            );
                        }
                    } else {
                        println!("⚠️ Reached {}, but couldn't parse the CRDT JSON.", url);
                    }
                }
                Err(e) => {
                    println!("❌ Network block trying to reach {}: {}", url, e);
                }
            }
        }
    }
}

// --- Peer Management ---

async fn get_peers(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    let rows = sqlx::query("SELECT url FROM peers")
        .fetch_all(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let peers = rows.into_iter().map(|r| r.get("url")).collect();
    Ok(Json(peers))
}

async fn add_peer(
    State(pool): State<SqlitePool>,
    Json(peer): Json<Peer>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Clean trailing slashes
    let clean_url = peer.url.trim_end_matches('/').to_string();

    sqlx::query("INSERT OR IGNORE INTO peers (url) VALUES (?)")
        .bind(clean_url)
        .execute(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::CREATED)
}

// --- CRUD Operations (UI) ---

async fn list_active_todos(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<Todo>>, (StatusCode, String)> {
    let rows = sqlx::query("SELECT * FROM todos WHERE deleted = 0 ORDER BY updated_at DESC")
        .fetch_all(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let todos = rows.into_iter().map(row_to_todo).collect();
    Ok(Json(todos))
}

async fn create_todo(
    State(pool): State<SqlitePool>,
    Json(payload): Json<CreateTodo>,
) -> Result<(StatusCode, Json<Todo>), (StatusCode, String)> {
    let id = Uuid::new_v4().to_string();
    let updated_at = now();

    sqlx::query(
        "INSERT INTO todos (id, title, completed, deleted, updated_at) VALUES (?, ?, 0, 0, ?)",
    )
    .bind(&id)
    .bind(&payload.title)
    .bind(updated_at)
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let todo = Todo {
        id,
        title: payload.title,
        completed: false,
        deleted: false,
        updated_at,
    };
    Ok((StatusCode::CREATED, Json(todo)))
}

async fn update_todo(
    State(pool): State<SqlitePool>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateTodo>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query("UPDATE todos SET completed = ?, updated_at = ? WHERE id = ?")
        .bind(payload.completed)
        .bind(now())
        .bind(id)
        .execute(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::OK)
}

async fn delete_todo(
    State(pool): State<SqlitePool>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query("UPDATE todos SET deleted = 1, updated_at = ? WHERE id = ?")
        .bind(now())
        .bind(id)
        .execute(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

// --- CRDT Export Endpoint ---

async fn export_all_data(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<Todo>>, (StatusCode, String)> {
    let rows = sqlx::query("SELECT * FROM todos")
        .fetch_all(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let todos = rows.into_iter().map(row_to_todo).collect();
    Ok(Json(todos))
}

fn row_to_todo(row: sqlx::sqlite::SqliteRow) -> Todo {
    Todo {
        id: row.get("id"),
        title: row.get("title"),
        completed: row.get("completed"),
        deleted: row.get("deleted"),
        updated_at: row.get("updated_at"),
    }
}
