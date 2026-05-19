use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use josekit::jwk::Jwk;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashMap;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::verify_service_jwt;
use crate::state::{origin_from, AppState};

#[derive(Debug, Deserialize)]
pub struct PermissionEntry {
    pub key: String,
    #[serde(default)]
    pub description: Option<String>,
    /// When true, this permission is auto-granted to any user with a grant
    /// on this service. See migration 0005 for the lifecycle semantics.
    #[serde(default)]
    pub default_allow: bool,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub slug: String,
    #[serde(default)]
    pub name: String,
    /// Optional suggested return URL. Only used as the initial value for a
    /// brand-new service; admin sets the authoritative URL at approval time.
    /// Services may omit it entirely since they typically can't know their
    /// own public URL.
    #[serde(default)]
    pub return_url: Option<String>,
    pub public_jwk: Value,
    #[serde(default)]
    pub permissions: Vec<PermissionEntry>,
}

#[derive(Debug, Deserialize)]
pub struct PermissionsBody {
    pub permissions: Vec<PermissionEntry>,
}

pub struct SyncStats {
    pub added: i64,
    pub updated: i64,
    pub removed: i64,
}

/// POST /api/services/register — public. Services use this on boot to
/// announce themselves (new) or re-assert their catalog (existing).
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> AppResult<Response> {
    let suggested_return_url = req.return_url.as_deref().unwrap_or("").trim().to_string();
    let (slug, name) = validate_basics(&req.slug, &req.name).map_err(AppError::BadRequest)?;
    // Suggested URL is optional; if present it must at least parse, so the
    // admin doesn't see garbage prefilled into the approval form.
    if !suggested_return_url.is_empty() && url::Url::parse(&suggested_return_url).is_err() {
        return Err(AppError::BadRequest(
            "return_url, if provided, must be a valid URL".into(),
        ));
    }

    let jwk_str = serde_json::to_string(&req.public_jwk)
        .map_err(|e| AppError::BadRequest(format!("public_jwk not JSON: {}", e)))?;
    let jwk = Jwk::from_bytes(jwk_str.as_bytes())
        .map_err(|e| AppError::BadRequest(format!("invalid public_jwk: {}", e)))?;
    if jwk.key_type() != "RSA" {
        return Err(AppError::BadRequest("public_jwk must be RSA".into()));
    }
    let kid = jwk
        .key_id()
        .ok_or_else(|| AppError::BadRequest("public_jwk missing kid".into()))?
        .to_string();

    for p in &req.permissions {
        validate_perm_key(&p.key).map_err(AppError::BadRequest)?;
    }

    let existing: Option<(i64, String, Option<String>)> = sqlx::query_as(
        "SELECT id, status, public_jwk FROM services
         WHERE slug = ? AND deleted_at IS NULL",
    )
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await?;

    let (service_id, effective_status, http_status) = match existing {
        None => {
            let row: (i64,) = sqlx::query_as(
                "INSERT INTO services (slug, name, return_url, status, public_jwk, registered_at)
                 VALUES (?, ?, ?, 'pending', ?, unixepoch())
                 RETURNING id",
            )
            .bind(&slug)
            .bind(&name)
            .bind(&suggested_return_url)
            .bind(&jwk_str)
            .fetch_one(&state.pool)
            .await?;
            (row.0, "pending".to_string(), StatusCode::ACCEPTED)
        }
        Some((id, status, stored_jwk_opt)) => {
            if status == "denied" {
                return Err(AppError::Forbidden);
            }
            let stored_kid = stored_jwk_opt
                .as_deref()
                .and_then(|s| Jwk::from_bytes(s.as_bytes()).ok())
                .and_then(|j| j.key_id().map(|k| k.to_string()));
            if let Some(stored) = stored_kid.as_deref() {
                if stored != kid {
                    return Err(AppError::BadRequest(
                        "public_jwk mismatch — key rotation requires admin re-approval".into(),
                    ));
                }
            }
            // Refresh name + public_jwk + registered_at, but NOT return_url —
            // bastion treats the admin-set return URL as authoritative once
            // the service exists. The service-supplied value is only a
            // suggestion at first-registration time.
            sqlx::query(
                "UPDATE services
                 SET name = ?, public_jwk = ?, registered_at = unixepoch()
                 WHERE id = ?",
            )
            .bind(&name)
            .bind(&jwk_str)
            .bind(id)
            .execute(&state.pool)
            .await?;
            let code = if status == "approved" {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            (id, status, code)
        }
    };

    let stats = sync_permissions(&state.pool, service_id, &req.permissions).await?;

    audit(
        &state.pool,
        None,
        "service.register",
        Some(&format!("service:{}", service_id)),
        Some(json!({
            "slug": slug,
            "kid": kid,
            "thumbprint": jwk_thumbprint(&jwk_str),
            "permission_count": req.permissions.len(),
            "added": stats.added,
            "updated": stats.updated,
            "removed": stats.removed,
        })),
    )
    .await
    .map_err(AppError::Other)?;

    Ok((
        http_status,
        Json(json!({ "status": effective_status, "slug": slug })),
    )
        .into_response())
}

/// GET /api/services/:slug/status — public. Lets a service poll for approval
/// without needing to sign anything yet.
pub async fn status(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AppResult<Response> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT status FROM services WHERE slug = ? AND deleted_at IS NULL",
    )
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await?;
    let status = row.map(|(s,)| s).ok_or(AppError::NotFound)?;
    Ok(Json(json!({ "status": status })).into_response())
}

/// PUT /api/services/:slug/permissions — authenticated by service-signed JWT.
/// Diffs the catalog: new keys inserted, existing keys updated, missing keys
/// soft-deleted via `permissions.removed_at`.
pub async fn put_permissions(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PermissionsBody>,
) -> AppResult<Response> {
    let origin = origin_from(&state, &headers);
    let svc = verify_service_jwt(&state.pool, &headers, &slug, &origin).await?;

    for p in &body.permissions {
        validate_perm_key(&p.key).map_err(AppError::BadRequest)?;
    }
    let stats = sync_permissions(&state.pool, svc.service_id, &body.permissions).await?;

    audit(
        &state.pool,
        None,
        "service.sync_perms",
        Some(&format!("service:{}", svc.service_id)),
        Some(json!({
            "slug": svc.slug,
            "added": stats.added,
            "updated": stats.updated,
            "removed": stats.removed,
        })),
    )
    .await
    .map_err(AppError::Other)?;

    Ok(Json(json!({
        "added": stats.added,
        "updated": stats.updated,
        "removed": stats.removed,
    }))
    .into_response())
}

/// Diff `catalog` against the service's current `permissions` rows. Missing
/// keys are soft-deleted (their `removed_at` is set), reappearing keys have
/// `removed_at` cleared, descriptions are updated in place.
///
/// Permissions flipped from `default_allow=0` to `default_allow=1` (or newly
/// inserted with `default_allow=1`) trigger a one-time backfill: every user
/// currently granted access to this service gets an INSERT into `user_perms`
/// for that permission. Reverse transitions (1 → 0) do nothing — admins'
/// manual revokes survive untouched.
pub async fn sync_permissions(
    pool: &SqlitePool,
    service_id: i64,
    catalog: &[PermissionEntry],
) -> AppResult<SyncStats> {
    let rows: Vec<(i64, String, Option<String>, Option<i64>, bool)> = sqlx::query_as(
        "SELECT id, key, description, removed_at, default_allow
         FROM permissions WHERE service_id = ?",
    )
    .bind(service_id)
    .fetch_all(pool)
    .await?;
    let mut existing: HashMap<String, (i64, Option<String>, Option<i64>, bool)> = rows
        .into_iter()
        .map(|(id, k, d, r, da)| (k, (id, d, r, da)))
        .collect();

    let mut added = 0i64;
    let mut updated = 0i64;
    // Perms that transitioned 0 → 1 (or were freshly inserted as 1). We
    // backfill these against all existing grants below, in one pass.
    let mut backfill_ids: Vec<i64> = Vec::new();

    for p in catalog {
        match existing.remove(&p.key) {
            None => {
                let row: (i64,) = sqlx::query_as(
                    "INSERT INTO permissions (service_id, key, description, default_allow)
                     VALUES (?, ?, ?, ?)
                     RETURNING id",
                )
                .bind(service_id)
                .bind(&p.key)
                .bind(p.description.as_deref())
                .bind(p.default_allow)
                .fetch_one(pool)
                .await?;
                if p.default_allow {
                    backfill_ids.push(row.0);
                }
                added += 1;
            }
            Some((id, prev_desc, prev_removed, prev_default)) => {
                let desc_changed = prev_desc.as_deref() != p.description.as_deref();
                let was_removed = prev_removed.is_some();
                let default_changed = prev_default != p.default_allow;
                if desc_changed || was_removed || default_changed {
                    sqlx::query(
                        "UPDATE permissions
                         SET description = ?, default_allow = ?, removed_at = NULL
                         WHERE id = ?",
                    )
                    .bind(p.description.as_deref())
                    .bind(p.default_allow)
                    .bind(id)
                    .execute(pool)
                    .await?;
                    updated += 1;
                }
                if p.default_allow && !prev_default {
                    backfill_ids.push(id);
                }
            }
        }
    }

    let mut removed = 0i64;
    for (_, (id, _, prev_removed, _)) in existing {
        if prev_removed.is_none() {
            sqlx::query("UPDATE permissions SET removed_at = unixepoch() WHERE id = ?")
                .bind(id)
                .execute(pool)
                .await?;
            removed += 1;
        }
    }

    for perm_id in backfill_ids {
        sqlx::query(
            "INSERT INTO user_perms (user_id, permission_id)
             SELECT g.user_id, ?
             FROM grants g
             WHERE g.service_id = ?
             ON CONFLICT(user_id, permission_id) DO NOTHING",
        )
        .bind(perm_id)
        .bind(service_id)
        .execute(pool)
        .await?;
    }

    Ok(SyncStats {
        added,
        updated,
        removed,
    })
}

/// Insert `user_perms` rows for every `default_allow=1` permission on the
/// given service. Call this right after creating a `grants` row so the new
/// user picks up the service's intended baseline. Idempotent.
pub async fn apply_default_perms(
    pool: &SqlitePool,
    user_id: i64,
    service_id: i64,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO user_perms (user_id, permission_id)
         SELECT ?, p.id FROM permissions p
         WHERE p.service_id = ? AND p.default_allow = 1 AND p.removed_at IS NULL
         ON CONFLICT(user_id, permission_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(service_id)
    .execute(pool)
    .await?;
    Ok(())
}

fn validate_basics(slug: &str, name: &str) -> Result<(String, String), String> {
    let slug = slug.trim().to_string();
    let name = {
        let n = name.trim();
        if n.is_empty() {
            slug.clone()
        } else {
            n.to_string()
        }
    };
    if slug.is_empty() {
        return Err("slug required".into());
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("slug must be lowercase alphanumeric + dashes".into());
    }
    Ok((slug, name))
}

fn validate_perm_key(key: &str) -> Result<(), String> {
    let k = key.trim();
    if k.is_empty() {
        return Err("permission key required".into());
    }
    if !k.chars().all(|c| {
        c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || matches!(c, ':' | '-' | '_' | '.')
    }) {
        return Err(format!(
            "invalid permission key '{}': only lowercase, digits, : - _ .",
            k
        ));
    }
    Ok(())
}

/// Short, stable identifier for a JWK derived from its serialized bytes.
/// Not cryptographic — purely for the admin UI to display + the audit log.
pub fn jwk_thumbprint(jwk_str: &str) -> String {
    let mut h = Sha256::new();
    h.update(jwk_str.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..8])
}

