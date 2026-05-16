use anyhow::Result;
use serde_json::Value;
use sqlx::SqlitePool;

pub async fn audit(
    pool: &SqlitePool,
    actor_id: Option<i64>,
    action: &str,
    target: Option<&str>,
    meta: Option<Value>,
) -> Result<()> {
    let meta_str = meta.map(|m| m.to_string());
    sqlx::query("INSERT INTO audit_log (actor_id, action, target, meta) VALUES (?, ?, ?, ?)")
        .bind(actor_id)
        .bind(action)
        .bind(target)
        .bind(meta_str)
        .execute(pool)
        .await?;
    Ok(())
}
