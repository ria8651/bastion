use anyhow::Result;
use chrono::Utc;
use data_encoding::BASE32_NOPAD;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tower_cookies::{cookie::SameSite, Cookie, Cookies};

use crate::models::User;

pub const SESSION_COOKIE: &str = "bastion_session";
const SESSION_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;
const RENEW_THRESHOLD_SECONDS: i64 = 15 * 24 * 60 * 60;

pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes).to_lowercase()
}

fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

pub async fn create_session(
    pool: &SqlitePool,
    token: &str,
    user_id: i64,
    user_agent: Option<&str>,
    ip: Option<&str>,
) -> Result<i64> {
    let id = hash_token(token);
    let expires_at = Utc::now().timestamp() + SESSION_TTL_SECONDS;
    sqlx::query(
        "INSERT INTO sessions (id, user_id, user_agent, ip, expires_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(user_agent)
    .bind(ip)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(expires_at)
}

/// Returns Some((user, session_id)) if the token is valid; renews if near expiry.
pub async fn validate_session_token(
    pool: &SqlitePool,
    token: &str,
) -> Result<Option<(User, String)>> {
    let id = hash_token(token);
    let row: Option<(
        i64,
        Option<i64>,
        i64,
        String,
        Option<String>,
        Option<String>,
        String,
        bool,
        i64,
        Option<i64>,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT s.expires_at, s.revoked_at, u.id,
                u.username, u.email, u.avatar, u.status, u.is_admin,
                u.created_at, u.last_login_at,
                u.sub_anchor_provider, u.sub_anchor_provider_id
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.id = ?",
    )
    .bind(&id)
    .fetch_optional(pool)
    .await?;

    let Some((
        expires_at,
        revoked_at,
        uid,
        username,
        email,
        avatar,
        status,
        is_admin,
        created_at,
        last_login_at,
        sub_anchor_provider,
        sub_anchor_provider_id,
    )) = row
    else {
        return Ok(None);
    };
    if revoked_at.is_some() {
        return Ok(None);
    }
    let now = Utc::now().timestamp();
    if expires_at < now {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(&id)
            .execute(pool)
            .await?;
        return Ok(None);
    }
    if expires_at - now < RENEW_THRESHOLD_SECONDS {
        let new_exp = now + SESSION_TTL_SECONDS;
        sqlx::query("UPDATE sessions SET expires_at = ? WHERE id = ?")
            .bind(new_exp)
            .bind(&id)
            .execute(pool)
            .await?;
    }

    let user = User {
        id: uid,
        username,
        email,
        avatar,
        status,
        is_admin,
        created_at,
        last_login_at,
        sub_anchor_provider,
        sub_anchor_provider_id,
    };
    Ok(Some((user, id)))
}

pub async fn invalidate_session(pool: &SqlitePool, token: &str) -> Result<()> {
    let id = hash_token(token);
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(&id)
        .execute(pool)
        .await?;
    Ok(())
}

pub fn set_session_cookie(cookies: &Cookies, token: &str, secure: bool, expires_at_unix: i64) {
    let mut c = Cookie::new(SESSION_COOKIE, token.to_string());
    c.set_path("/");
    c.set_http_only(true);
    c.set_same_site(SameSite::Lax);
    c.set_secure(secure);
    if let Ok(t) =
        tower_cookies::cookie::time::OffsetDateTime::from_unix_timestamp(expires_at_unix)
    {
        c.set_expires(t);
    }
    cookies.add(c);
}

pub fn clear_session_cookie(cookies: &Cookies) {
    let mut c = Cookie::from(SESSION_COOKIE);
    c.set_path("/");
    cookies.remove(c);
}

pub fn read_session_cookie(cookies: &Cookies) -> Option<String> {
    cookies.get(SESSION_COOKIE).map(|c| c.value().to_string())
}
