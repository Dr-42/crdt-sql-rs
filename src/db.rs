use std::{str::FromStr, time::{SystemTime, UNIX_EPOCH}};

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row, SqlitePool,
};

use axum_extra::extract::cookie::CookieJar;

use crate::{models::Todo, state::AppState, identity::verify_session};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub fn row_to_todo(row: sqlx::sqlite::SqliteRow) -> Todo {
    Todo {
        id: row.get("id"),
        title: row.get("title"),
        completed: row.get("completed"),
        deleted: row.get("deleted"),
        updated_at: row.get("updated_at"),
        node_id: row.try_get("node_id").unwrap_or_default(),
    }
}

pub async fn open_user_pool(user_hash: &str) -> SqlitePool {
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

pub async fn export_todos(pool: &SqlitePool) -> Result<Vec<Todo>, sqlx::Error> {
    let rows = sqlx::query("SELECT * FROM todos").fetch_all(pool).await?;
    Ok(rows.into_iter().map(row_to_todo).collect())
}

/// LWW (Last-Write-Wins) tiebreaker merge using (updated_at, node_id) lexicographic ordering.
pub async fn merge_todos(pool: &SqlitePool, todos: Vec<Todo>) -> usize {
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

pub async fn get_user_pool(jar: &CookieJar, state: &AppState) -> Option<SqlitePool> {
    // 1. Verify the cookie signature is valid
    let user_hash = verify_session(jar, &state.signing_key)?;

    // 2. Fast path: pool already in memory
    {
        let pools = state.user_pools.read().await;
        if let Some(pool) = pools.get(&user_hash) {
            return Some(pool.clone());
        }
    }

    // 3. Slow path (server restarted): cookie is valid, but memory is empty.
    //    Re-open the SQLite database and cache it in the HashMap.
    println!("♻️ Restoring session pool for user {}", &user_hash[..8]);
    let mut pools = state.user_pools.write().await;
    let pool = open_user_pool(&user_hash).await;
    pools.insert(user_hash.clone(), pool.clone());

    Some(pool)
}
