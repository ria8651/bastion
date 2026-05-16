use anyhow::Result;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{ConnectOptions, SqlitePool};
use std::path::Path;
use std::str::FromStr;

pub async fn connect(database_path: &str) -> Result<SqlitePool> {
    if let Some(parent) = Path::new(database_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }

    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", database_path))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .log_statements(tracing::log::LevelFilter::Trace);

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;

    bootstrap(&pool).await?;
    Ok(pool)
}

/// Idempotent schema sync. Matches the Drizzle schema in the SvelteKit codebase
/// so an existing `data/bastion.db` from there can be read without conversion.
async fn bootstrap(pool: &SqlitePool) -> Result<()> {
    let sql = r#"
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      github_id     INTEGER NOT NULL,
      username      TEXT NOT NULL,
      email         TEXT,
      avatar        TEXT,
      status        TEXT NOT NULL DEFAULT 'pending',
      is_admin      INTEGER NOT NULL DEFAULT 0,
      created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
      last_login_at INTEGER
    );
    CREATE UNIQUE INDEX IF NOT EXISTS users_github_id_idx ON users(github_id);
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_idx ON users(username);

    CREATE TABLE IF NOT EXISTS services (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      slug       TEXT NOT NULL,
      name       TEXT NOT NULL,
      return_url TEXT NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (unixepoch())
    );
    CREATE UNIQUE INDEX IF NOT EXISTS services_slug_idx ON services(slug);

    CREATE TABLE IF NOT EXISTS permissions (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      service_id  INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
      key         TEXT NOT NULL,
      description TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS permissions_service_key_idx ON permissions(service_id, key);

    CREATE TABLE IF NOT EXISTS grants (
      user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      service_id  INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
      granted_at  INTEGER NOT NULL DEFAULT (unixepoch()),
      granted_by  INTEGER REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS grants_pk ON grants(user_id, service_id);

    CREATE TABLE IF NOT EXISTS user_perms (
      user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE
    );
    CREATE UNIQUE INDEX IF NOT EXISTS user_perms_pk ON user_perms(user_id, permission_id);

    CREATE TABLE IF NOT EXISTS sessions (
      id          TEXT PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      user_agent  TEXT,
      ip          TEXT,
      created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
      expires_at  INTEGER NOT NULL,
      revoked_at  INTEGER
    );
    CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);

    CREATE TABLE IF NOT EXISTS access_requests (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      service_id   INTEGER REFERENCES services(id) ON DELETE CASCADE,
      note         TEXT,
      requested_at INTEGER NOT NULL DEFAULT (unixepoch()),
      resolved_at  INTEGER,
      resolved_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
      decision     TEXT
    );
    CREATE INDEX IF NOT EXISTS access_requests_user_idx ON access_requests(user_id);
    CREATE INDEX IF NOT EXISTS access_requests_pending_idx ON access_requests(resolved_at);

    CREATE TABLE IF NOT EXISTS audit_log (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action   TEXT NOT NULL,
      target   TEXT,
      meta     TEXT,
      at       INTEGER NOT NULL DEFAULT (unixepoch())
    );
    CREATE INDEX IF NOT EXISTS audit_log_at_idx ON audit_log(at);
    CREATE INDEX IF NOT EXISTS audit_log_actor_idx ON audit_log(actor_id);

    CREATE TABLE IF NOT EXISTS oauth_providers (
      provider      TEXT PRIMARY KEY,
      client_id     TEXT NOT NULL,
      client_secret TEXT NOT NULL,
      enabled       INTEGER NOT NULL DEFAULT 1,
      updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
    );

    CREATE TABLE IF NOT EXISTS signing_keys (
      kid         TEXT PRIMARY KEY,
      alg         TEXT NOT NULL DEFAULT 'RS256',
      public_jwk  TEXT NOT NULL,
      private_jwk TEXT NOT NULL,
      created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
      retired_at  INTEGER
    );
    "#;

    let mut tx = pool.begin().await?;
    for stmt in sql.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        sqlx::query(stmt).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
