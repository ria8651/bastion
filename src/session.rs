use anyhow::Result;
use axum::http::{header::SET_COOKIE, HeaderValue};
use axum::response::Response;
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

/// Expiry of a live session, for re-issuing its cookie without disturbing the
/// session itself. `None` if the token is unknown, revoked or expired.
pub async fn session_expiry(pool: &SqlitePool, token: &str) -> Option<i64> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT expires_at FROM sessions
         WHERE id = ? AND revoked_at IS NULL AND expires_at > unixepoch()",
    )
    .bind(hash_token(token))
    .fetch_optional(pool)
    .await
    .ok()?;
    row.map(|(e,)| e)
}

pub async fn invalidate_session(pool: &SqlitePool, token: &str) -> Result<()> {
    let id = hash_token(token);
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(&id)
        .execute(pool)
        .await?;
    Ok(())
}

/// `domain` scopes the cookie to a parent domain (`.example.com`) so it is
/// also sent on requests to proxied hosts — which is what makes proxy mode
/// work, since sign-in happens on bastion's own hostname.
/// `None` leaves the cookie host-only, the right default when nothing is being
/// proxied.
pub fn set_session_cookie(
    cookies: &Cookies,
    token: &str,
    secure: bool,
    expires_at_unix: i64,
    domain: Option<&str>,
) {
    let mut c = Cookie::new(SESSION_COOKIE, token.to_string());
    c.set_path("/");
    if let Some(d) = domain {
        c.set_domain(d.to_string());
    }
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

/// Clears the session cookie. With a domain configured this clears the
/// domain-scoped one; pair it with [`expire_host_only_session`] to also drop a
/// leftover host-only cookie.
pub fn clear_session_cookie(cookies: &Cookies, domain: Option<&str>) {
    let mut c = Cookie::from(SESSION_COOKIE);
    c.set_path("/");
    if let Some(d) = domain {
        c.set_domain(d.to_string());
    }
    cookies.remove(c);
}

/// Appends a `Set-Cookie` expiring the *host-only* session cookie.
///
/// This can't go through the cookie jar: the `cookie` crate keys both its
/// original and its delta sets by cookie name alone, so a jar carries at most
/// one `bastion_session` removal and the domain-scoped one wins.
///
/// It matters when `cookie_domain` is turned on with sessions already in the
/// wild. A browser then holds two `bastion_session` cookies and sends both;
/// RFC 6265 orders them by path length then creation time, so the older
/// host-only one comes first and is the one parsed, shadowing every new
/// domain-scoped session indefinitely. Expiring by name with no Domain
/// attribute removes only the host-only cookie — cookie deletion matches on
/// (name, domain, path), so the domain-scoped one is untouched.
pub fn expire_host_only_session(res: &mut Response) {
    if let Ok(v) = HeaderValue::from_str(&format!(
        "{}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        SESSION_COOKIE
    )) {
        res.headers_mut().append(SET_COOKIE, v);
    }
}

pub fn read_session_cookie(cookies: &Cookies) -> Option<String> {
    cookies.get(SESSION_COOKIE).map(|c| c.value().to_string())
}
