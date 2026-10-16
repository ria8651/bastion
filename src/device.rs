//! Device sign-in: the OAuth device authorization grant (RFC 8628).
//!
//! For clients that can't show bastion's login page — a TV app has no browser
//! to run OAuth in. The device signs in on someone else's screen:
//!
//!   device → POST /api/device/code   client_id=<slug>&name=…
//!          ← device_code, user_code, verification_uri(_complete), interval
//!   device shows user_code and a QR of verification_uri_complete
//!   phone  → /device?code=… → signs in if needed → confirms
//!   device → POST /api/device/token  grant_type=…:device_code, polling
//!          ← access_token (the usual JWT) + refresh_token
//!   device → POST /api/device/token  grant_type=refresh_token, before expiry
//!
//! The refresh token is the long-lived credential, kept only as a hash. Every
//! refresh re-reads the user, the service and the grant and mints a JWT with
//! the current perms, so the app verifies one kind of token whichever way the
//! user arrived, and revoking anything in bastion reaches a TV within one JWT
//! lifetime. Refresh tokens don't rotate: a TV that lost the response to a
//! rotation would be locked out and have to pair again, which costs more than
//! rotation buys when the token never leaves one device.

use chrono::Utc;
use data_encoding::BASE64URL_NOPAD;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::audit::audit;

/// How long a code can wait for someone to confirm it.
pub const CODE_TTL_SECONDS: i64 = 10 * 60;
/// RFC 8628's default poll interval.
pub const POLL_INTERVAL_SECONDS: i64 = 5;
/// A device unused for this long has to pair again.
pub const IDLE_TTL_SECONDS: i64 = 90 * 24 * 60 * 60;
/// `/api/device/code` is unauthenticated; cap the pairings it can leave open.
/// Per service, so flooding one can't stop pairing for the others.
const MAX_PENDING: i64 = 50;
/// Wrong codes a signed-in user may enter per window before being refused.
const MAX_MISSES: u32 = 10;
const MISS_WINDOW_SECONDS: i64 = 10 * 60;
/// No vowels (no accidental words) and nothing that reads as another
/// character, per RFC 8628 §6.1. 20^8 ≈ 2.6e10 codes, of which at most
/// `MAX_PENDING` per service are live.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LEN: usize = 8;

pub const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub const GRANT_REFRESH: &str = "refresh_token";

/// An RFC 6749 §5.2 / RFC 8628 §3.5 error: a code the client branches on and
/// a description for whoever is debugging it.
#[derive(Debug)]
pub struct OAuthError {
    pub code: &'static str,
    pub description: String,
}

impl OAuthError {
    fn new(code: &'static str, description: impl Into<String>) -> Self {
        OAuthError {
            code,
            description: description.into(),
        }
    }
}

impl From<sqlx::Error> for OAuthError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = ?e, "device grant");
        OAuthError::new("server_error", "database error")
    }
}

impl From<anyhow::Error> for OAuthError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = ?e, "device grant");
        OAuthError::new("server_error", "could not issue token")
    }
}

type Result<T> = std::result::Result<T, OAuthError>;

fn now() -> i64 {
    Utc::now().timestamp()
}

fn hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    BASE64URL_NOPAD.encode(&bytes)
}

fn new_user_code() -> String {
    let mut rng = rand::thread_rng();
    (0..USER_CODE_LEN)
        .map(|_| USER_CODE_ALPHABET[rng.gen_range(0..USER_CODE_ALPHABET.len())] as char)
        .collect()
}

/// A typed code in the canonical stored form, or `None` if it can't be one.
/// Forgiving about case, the dash and stray spaces; nothing else.
pub fn normalize_user_code(input: &str) -> Option<String> {
    let code: String = input
        .chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let valid =
        code.len() == USER_CODE_LEN && code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b));
    valid.then_some(code)
}

/// `BCDFGHJK` → `BCDF-GHJK`, for people to read.
pub fn display_user_code(code: &str) -> String {
    let (a, b) = code.split_at(code.len().min(USER_CODE_LEN / 2));
    format!("{}-{}", a, b)
}

pub fn confirm_path(code: &str) -> String {
    format!("/device?code={}", display_user_code(code))
}

/// Whatever the device called itself, made safe to show on a confirm page.
/// Bidi controls go too: they aren't `is_control`, and a name that renders
/// backwards is a phishing aid.
fn clean_name(name: Option<&str>) -> String {
    let n: String = name
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control() && !is_bidi_control(*c))
        .take(64)
        .collect();
    let n = n.trim();
    if n.is_empty() {
        "Unnamed device".into()
    } else {
        n.to_string()
    }
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

// -------------------- Device side --------------------

pub struct Started {
    pub device_code: String,
    pub user_code: String,
}

pub async fn start(pool: &SqlitePool, client_id: &str, name: Option<&str>) -> Result<Started> {
    let service: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM services
         WHERE slug = ? AND status = 'approved' AND deleted_at IS NULL AND device_login = 1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?;
    let Some((service_id,)) = service else {
        return Err(OAuthError::new(
            "invalid_client",
            "no such service, or device sign-in is off for it",
        ));
    };

    sqlx::query("DELETE FROM device_codes WHERE expires_at <= ?")
        .bind(now())
        .execute(pool)
        .await?;
    let (pending,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM device_codes WHERE service_id = ?")
            .bind(service_id)
            .fetch_one(pool)
            .await?;
    if pending >= MAX_PENDING {
        return Err(OAuthError::new(
            "slow_down",
            "too many pairings in progress, try again later",
        ));
    }

    let device_code = random_secret();
    let name = clean_name(name);
    // A collision on user_code is a 1-in-500-million event per live code;
    // retrying beats surfacing it.
    for _ in 0..5 {
        let user_code = new_user_code();
        let inserted = sqlx::query(
            "INSERT INTO device_codes (device_code_hash, user_code, service_id, name, expires_at)
             VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_code) DO NOTHING",
        )
        .bind(hash(&device_code))
        .bind(&user_code)
        .bind(service_id)
        .bind(&name)
        .bind(now() + CODE_TTL_SECONDS)
        .execute(pool)
        .await?;
        if inserted.rows_affected() == 1 {
            return Ok(Started {
                device_code,
                user_code,
            });
        }
    }
    Err(OAuthError::new("server_error", "could not allocate a code"))
}

pub struct Tokens {
    pub access_token: String,
    pub expires_in: i64,
    /// Only on the poll that completes pairing.
    pub refresh_token: Option<String>,
}

/// One poll of `grant_type=device_code`. Consumes the code on success.
pub async fn poll(
    pool: &SqlitePool,
    issuer: &str,
    client_id: &str,
    device_code: &str,
) -> Result<Tokens> {
    let code_hash = hash(device_code);
    let code_hash = code_hash.as_str();
    #[allow(clippy::type_complexity)]
    let row: Option<(String, i64, Option<i64>, Option<i64>, bool)> = sqlx::query_as(
        "SELECT s.slug, dc.expires_at, dc.last_poll_at, dc.approved_by, dc.denied
         FROM device_codes dc JOIN services s ON s.id = dc.service_id
         WHERE dc.device_code_hash = ?",
    )
    .bind(code_hash)
    .fetch_optional(pool)
    .await?;
    let Some((slug, expires_at, last_poll, approved_by, denied)) = row else {
        return Err(OAuthError::new("invalid_grant", "unknown device code"));
    };
    if slug != client_id {
        return Err(OAuthError::new(
            "invalid_client",
            "device code belongs to another service",
        ));
    }
    let now = now();
    let gone = |code, msg: &'static str| async move {
        sqlx::query("DELETE FROM device_codes WHERE device_code_hash = ?")
            .bind(code_hash)
            .execute(pool)
            .await?;
        Err(OAuthError::new(code, msg))
    };
    if expires_at <= now {
        return gone(
            "expired_token",
            "the code expired before anyone confirmed it",
        )
        .await;
    }
    if denied {
        return gone("access_denied", "the user declined").await;
    }

    if approved_by.is_none() {
        sqlx::query("UPDATE device_codes SET last_poll_at = ? WHERE device_code_hash = ?")
            .bind(now)
            .bind(code_hash)
            .execute(pool)
            .await?;
        // A second's slack: timestamps are whole seconds, so a client polling
        // at exactly the interval can land a second short.
        if last_poll.is_some_and(|t| now - t < POLL_INTERVAL_SECONDS - 1) {
            return Err(OAuthError::new(
                "slow_down",
                "polling faster than the interval",
            ));
        }
        return Err(OAuthError::new(
            "authorization_pending",
            "waiting for the user to confirm",
        ));
    }

    // Approved. Taking the row is the claim: of two racing polls, one gets it.
    let taken: Option<(i64, i64, String)> = sqlx::query_as(
        "DELETE FROM device_codes WHERE device_code_hash = ? AND approved_by IS NOT NULL
         RETURNING approved_by, service_id, name",
    )
    .bind(code_hash)
    .fetch_optional(pool)
    .await?;
    let Some((user_id, service_id, name)) = taken else {
        return Err(OAuthError::new("invalid_grant", "device code already used"));
    };
    // Re-checked rather than trusted from approval time: a grant revoked in
    // the seconds between confirming and this poll is revoked.
    let Some(who) = eligible(pool, user_id, service_id).await? else {
        return Err(OAuthError::new(
            "access_denied",
            "the user no longer has access",
        ));
    };

    let refresh_token = random_secret();
    let (device_id,): (i64,) = sqlx::query_as(
        "INSERT INTO devices (user_id, service_id, name, token_hash, last_used_at)
         VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(user_id)
    .bind(service_id)
    .bind(&name)
    .bind(hash(&refresh_token))
    .bind(now)
    .fetch_one(pool)
    .await?;
    audit(
        pool,
        Some(user_id),
        "device.paired",
        Some(&format!("device:{}", device_id)),
        Some(serde_json::json!({ "service": who.slug, "name": name })),
    )
    .await?;

    let access = mint(pool, issuer, user_id, service_id, device_id, who).await?;
    Ok(Tokens {
        refresh_token: Some(refresh_token),
        ..access
    })
}

/// `grant_type=refresh_token`: a fresh JWT for a paired device.
pub async fn refresh(
    pool: &SqlitePool,
    issuer: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<Tokens> {
    let row: Option<(i64, i64, i64, String, i64)> = sqlx::query_as(
        "SELECT d.id, d.user_id, d.service_id, s.slug, COALESCE(d.last_used_at, d.created_at)
         FROM devices d JOIN services s ON s.id = d.service_id
         WHERE d.token_hash = ? AND d.revoked_at IS NULL",
    )
    .bind(hash(refresh_token))
    .fetch_optional(pool)
    .await?;
    let Some((device_id, user_id, service_id, slug, last_used)) = row else {
        return Err(OAuthError::new(
            "invalid_grant",
            "unknown or revoked refresh token",
        ));
    };
    if slug != client_id {
        return Err(OAuthError::new(
            "invalid_client",
            "refresh token belongs to another service",
        ));
    }
    let now = now();
    if now - last_used > IDLE_TTL_SECONDS {
        revoke(pool, device_id, None, None, "device.expired").await?;
        return Err(OAuthError::new(
            "invalid_grant",
            "unused for too long; pair again",
        ));
    }
    // Not revoked: a grant restored, or device sign-in switched back on,
    // brings the device back without pairing again.
    let Some(who) = eligible(pool, user_id, service_id).await? else {
        return Err(OAuthError::new(
            "invalid_grant",
            "the user no longer has access to this service",
        ));
    };
    sqlx::query("UPDATE devices SET last_used_at = ? WHERE id = ?")
        .bind(now)
        .bind(device_id)
        .execute(pool)
        .await?;
    mint(pool, issuer, user_id, service_id, device_id, who).await
}

/// Who a device acts as, if they may still use the service from a device.
struct Eligible {
    username: String,
    anchor_provider: String,
    anchor_id: String,
    slug: String,
}

async fn eligible(pool: &SqlitePool, user_id: i64, service_id: i64) -> Result<Option<Eligible>> {
    let row: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT u.username, u.sub_anchor_provider, u.sub_anchor_provider_id, s.slug
         FROM users u, services s
         WHERE u.id = ? AND u.status = 'active'
           AND s.id = ? AND s.status = 'approved' AND s.deleted_at IS NULL
           AND s.device_login = 1",
    )
    .bind(user_id)
    .bind(service_id)
    .fetch_optional(pool)
    .await?;
    let Some((username, anchor_provider, anchor_id, slug)) = row else {
        return Ok(None);
    };
    if !crate::grants::is_granted(pool, user_id, service_id).await? {
        return Ok(None);
    }
    Ok(Some(Eligible {
        username,
        anchor_provider,
        anchor_id,
        slug,
    }))
}

async fn mint(
    pool: &SqlitePool,
    issuer: &str,
    user_id: i64,
    service_id: i64,
    device_id: i64,
    who: Eligible,
) -> Result<Tokens> {
    let perms = crate::routes::auth::load_user_perms(pool, user_id, service_id)
        .await
        .map_err(|e| anyhow::anyhow!("load perms: {}", e))?;
    let issued = crate::jwt::issue_service_token(
        pool,
        crate::jwt::IssueArgs {
            issuer,
            user_id,
            provider: &who.anchor_provider,
            provider_user_id: &who.anchor_id,
            username: &who.username,
            service: &who.slug,
            perms,
            device: Some(device_id),
        },
    )
    .await?;
    Ok(Tokens {
        access_token: issued.jwt,
        expires_in: issued.expires_at - now(),
        refresh_token: None,
    })
}

// -------------------- Browser side --------------------

/// A pairing waiting for someone to confirm it.
pub struct Pending {
    pub user_code: String,
    pub device_name: String,
    pub service_id: i64,
    pub slug: String,
    pub service_name: String,
}

/// The live, undecided pairing with this code, if there is one.
pub async fn pending(pool: &SqlitePool, user_code: &str) -> sqlx::Result<Option<Pending>> {
    let row: Option<(String, i64, String, String)> = sqlx::query_as(
        "SELECT dc.name, s.id, s.slug, s.name
         FROM device_codes dc JOIN services s ON s.id = dc.service_id
         WHERE dc.user_code = ? AND dc.expires_at > ?
           AND dc.approved_by IS NULL AND dc.denied = 0
           AND s.status = 'approved' AND s.deleted_at IS NULL AND s.device_login = 1",
    )
    .bind(user_code)
    .bind(now())
    .fetch_optional(pool)
    .await?;
    Ok(
        row.map(|(device_name, service_id, slug, service_name)| Pending {
            user_code: user_code.to_string(),
            device_name,
            service_id,
            slug,
            service_name,
        }),
    )
}

/// Record the decision on a pending pairing. False if it was no longer
/// pending — expired, or decided in another tab.
pub async fn decide(
    pool: &SqlitePool,
    user_code: &str,
    user_id: i64,
    approve: bool,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "UPDATE device_codes SET approved_by = ?, denied = ?
         WHERE user_code = ? AND expires_at > ? AND approved_by IS NULL AND denied = 0",
    )
    .bind(approve.then_some(user_id))
    .bind(!approve)
    .bind(user_code)
    .bind(now())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Note a code that matched nothing. True once this user has missed too often.
pub fn record_miss(user_id: i64) -> bool {
    let mut misses = misses().lock().expect("device misses poisoned");
    let now = now();
    misses.retain(|_, (_, since)| now - *since < MISS_WINDOW_SECONDS);
    let entry = misses.entry(user_id).or_insert((0, now));
    entry.0 += 1;
    entry.0 >= MAX_MISSES
}

pub fn too_many_misses(user_id: i64) -> bool {
    let misses = misses().lock().expect("device misses poisoned");
    misses
        .get(&user_id)
        .is_some_and(|(n, since)| *n >= MAX_MISSES && now() - since < MISS_WINDOW_SECONDS)
}

/// Kept in memory: a restart forgetting them costs an attacker nothing they
/// couldn't get by waiting out the window.
fn misses() -> &'static Mutex<HashMap<i64, (u32, i64)>> {
    static MISSES: OnceLock<Mutex<HashMap<i64, (u32, i64)>>> = OnceLock::new();
    MISSES.get_or_init(Default::default)
}

// -------------------- Management --------------------

pub struct Device {
    pub id: i64,
    pub name: String,
    pub slug: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// A user's paired devices, newest first.
pub async fn list_for_user(pool: &SqlitePool, user_id: i64) -> sqlx::Result<Vec<Device>> {
    let rows: Vec<(i64, String, String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT d.id, d.name, s.slug, d.created_at, d.last_used_at
         FROM devices d JOIN services s ON s.id = d.service_id
         WHERE d.user_id = ? AND d.revoked_at IS NULL AND s.deleted_at IS NULL
         ORDER BY d.created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, slug, created_at, last_used_at)| Device {
            id,
            name,
            slug,
            created_at,
            last_used_at,
        })
        .collect())
}

/// Revoke one device. `owner` restricts it to that user's devices; `actor` is
/// who gets the audit entry. False if there was nothing to revoke.
pub async fn revoke(
    pool: &SqlitePool,
    device_id: i64,
    owner: Option<i64>,
    actor: Option<i64>,
    action: &str,
) -> anyhow::Result<bool> {
    let row: Option<(i64,)> = sqlx::query_as(
        "UPDATE devices SET revoked_at = unixepoch()
         WHERE id = ? AND revoked_at IS NULL AND (? IS NULL OR user_id = ?)
         RETURNING user_id",
    )
    .bind(device_id)
    .bind(owner)
    .bind(owner)
    .fetch_optional(pool)
    .await?;
    let Some((user_id,)) = row else {
        return Ok(false);
    };
    audit(
        pool,
        actor,
        action,
        Some(&format!("device:{}", device_id)),
        Some(serde_json::json!({ "userId": user_id })),
    )
    .await?;
    Ok(true)
}

/// Revoke every device a user has paired.
pub async fn revoke_all_for_user(pool: &SqlitePool, user_id: i64) -> sqlx::Result<u64> {
    let res = sqlx::query(
        "UPDATE devices SET revoked_at = unixepoch() WHERE user_id = ? AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_normalize_forgivingly_but_not_loosely() {
        assert_eq!(
            normalize_user_code("bcdf-ghjk").as_deref(),
            Some("BCDFGHJK")
        );
        assert_eq!(
            normalize_user_code(" BCDF GHJK ").as_deref(),
            Some("BCDFGHJK")
        );
        assert_eq!(normalize_user_code("BCDFGHJ"), None);
        assert_eq!(normalize_user_code("BCDFGHJKL"), None);
        // Vowels never appear in a generated code.
        assert_eq!(normalize_user_code("ABCDEFGH"), None);
        assert_eq!(normalize_user_code("BCDF/GHJ"), None);
        assert_eq!(display_user_code("BCDFGHJK"), "BCDF-GHJK");
        assert!(normalize_user_code(&new_user_code()).is_some());
    }

    #[test]
    fn device_names_are_trimmed_and_capped() {
        assert_eq!(clean_name(None), "Unnamed device");
        assert_eq!(clean_name(Some("  \n ")), "Unnamed device");
        assert_eq!(clean_name(Some("Living\u{0}Room")), "LivingRoom");
        assert_eq!(clean_name(Some("TV\u{202E}moc.evil")), "TVmoc.evil");
        assert_eq!(clean_name(Some(&"x".repeat(200))).len(), 64);
    }

    async fn pool() -> SqlitePool {
        let dir = std::env::temp_dir().join(format!(
            "bastion-device-{}-{}",
            std::process::id(),
            random_secret()
        ));
        let pool = crate::db::connect(dir.join("t.db").to_str().unwrap())
            .await
            .unwrap();
        crate::keys::get_active_signing_key(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, github_id, username, status, sub_anchor_provider, sub_anchor_provider_id)
               VALUES (1, 1, 'alice', 'active', 'github', '1');
             INSERT INTO services (id, slug, name, return_url, device_login)
               VALUES (1, 'tv', 'TV', 'https://tv.example.com/cb', 1),
                      (2, 'other', 'Other', 'https://o.example.com/cb', 0);
             INSERT INTO grants (user_id, service_id) VALUES (1, 1);",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn pairing_then_refresh_tracks_the_grant() {
        let pool = pool().await;
        assert_eq!(
            start(&pool, "other", None).await.err().unwrap().code,
            "invalid_client"
        );

        let s = start(&pool, "tv", Some("Living Room")).await.unwrap();
        let err = poll(&pool, "iss", "tv", &s.device_code)
            .await
            .err()
            .unwrap();
        assert_eq!(err.code, "authorization_pending");
        assert_eq!(
            poll(&pool, "iss", "other", &s.device_code)
                .await
                .err()
                .unwrap()
                .code,
            "invalid_client"
        );

        assert!(pending(&pool, &s.user_code).await.unwrap().is_some());
        assert!(decide(&pool, &s.user_code, 1, true).await.unwrap());
        // Decided once; a second tab can't flip it.
        assert!(!decide(&pool, &s.user_code, 1, false).await.unwrap());

        let t = poll(&pool, "iss", "tv", &s.device_code).await.unwrap();
        let refresh_token = t.refresh_token.unwrap();
        let claims = crate::jwt::verify_service_token(&pool, "iss", &t.access_token)
            .await
            .unwrap();
        assert_eq!(claims.claim("svc").and_then(|v| v.as_str()), Some("tv"));
        assert!(claims.claim("device_id").is_some());
        // Single use.
        assert_eq!(
            poll(&pool, "iss", "tv", &s.device_code)
                .await
                .err()
                .unwrap()
                .code,
            "invalid_grant"
        );

        assert!(refresh(&pool, "iss", "tv", &refresh_token).await.is_ok());
        sqlx::query("DELETE FROM grants")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            refresh(&pool, "iss", "tv", &refresh_token)
                .await
                .err()
                .unwrap()
                .code,
            "invalid_grant"
        );
        sqlx::query("INSERT INTO grants (user_id, service_id) VALUES (1, 1)")
            .execute(&pool)
            .await
            .unwrap();
        assert!(refresh(&pool, "iss", "tv", &refresh_token).await.is_ok());

        let devices = list_for_user(&pool, 1).await.unwrap();
        assert_eq!(devices.len(), 1);
        assert!(
            revoke(&pool, devices[0].id, Some(1), Some(1), "device.revoke")
                .await
                .unwrap()
        );
        assert!(refresh(&pool, "iss", "tv", &refresh_token).await.is_err());
    }

    #[tokio::test]
    async fn a_declined_code_is_gone() {
        let pool = pool().await;
        let s = start(&pool, "tv", None).await.unwrap();
        assert!(decide(&pool, &s.user_code, 1, false).await.unwrap());
        assert_eq!(
            poll(&pool, "iss", "tv", &s.device_code)
                .await
                .err()
                .unwrap()
                .code,
            "access_denied"
        );
        assert_eq!(
            poll(&pool, "iss", "tv", &s.device_code)
                .await
                .err()
                .unwrap()
                .code,
            "invalid_grant"
        );
    }
}
