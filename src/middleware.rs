use anyhow::anyhow;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use josekit::{jwk::Jwk, jws::RS256, jwt};
use sqlx::SqlitePool;
use std::time::SystemTime;
use tower_cookies::Cookies;

use crate::error::AppError;
use crate::models::{ServiceCtx, UserCtx};
use crate::session::{
    clear_session_cookie, expire_host_only_session, read_session_cookie, validate_session_token,
};
use crate::setup::get_setup_state;
use crate::state::AppState;

/// Loads the signed-in user (if any) into request extensions.
pub async fn load_user(
    State(state): State<AppState>,
    cookies: Cookies,
    mut req: Request,
    next: Next,
) -> Response {
    let mut drop_host_only = false;
    if let Some(token) = read_session_cookie(&cookies) {
        match validate_session_token(&state.pool, &token).await {
            Ok(Some((user, _sid))) => {
                let ctx: UserCtx = (&user).into();
                req.extensions_mut().insert(ctx);
            }
            Ok(None) => {
                let domain = crate::settings::cookie_domain(&state.pool).await;
                clear_session_cookie(&cookies, domain.as_deref());
                // A cookie that doesn't validate while a cookie domain is set
                // is very likely a host-only leftover from before the switch,
                // shadowing the real session. Drop it so the next login sticks.
                drop_host_only = domain.is_some();
            }
            Err(e) => {
                tracing::error!(error = ?e, "session validation failed");
            }
        }
    }
    let mut res = next.run(req).await;
    if drop_host_only {
        expire_host_only_session(&mut res);
    }
    res
}

/// Redirects to /setup until first-run setup is complete, except for /setup and the auth flow.
pub async fn setup_gate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let exempt = path.starts_with("/setup")
        || path.starts_with("/auth/")
        || path.starts_with("/static/")
        || path.starts_with("/.well-known/")
        || path.starts_with("/api/")
        || path == "/favicon.svg";
    if !exempt {
        match get_setup_state(&state.pool).await {
            Ok(s) if !s.complete() => return Redirect::to("/setup").into_response(),
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = ?e, "setup state lookup");
                return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
            }
        }
    }
    next.run(req).await
}

pub fn require_admin(user: Option<&UserCtx>) -> Result<&UserCtx, AppError> {
    let u = user.ok_or(AppError::Unauthorized)?;
    if !u.is_admin() {
        return Err(AppError::Forbidden);
    }
    Ok(u)
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get("authorization")?.to_str().ok()?;
    let s = v.trim();
    s.strip_prefix("Bearer ")
        .or_else(|| s.strip_prefix("bearer "))
        .map(|rest| rest.trim().to_string())
}

/// Verify a short-lived JWT presented by an approved service. The slug is
/// supplied by the caller (from the request path) so we can look up the
/// service's public_jwk before parsing the token — same trust model as
/// bastion's own JWKS, just per-service.
///
/// Asserts: signature valid, `iss == slug`, `aud` contains `expected_aud`,
/// and `exp` not in the past. Returns the service context on success.
pub async fn verify_service_jwt(
    pool: &SqlitePool,
    headers: &HeaderMap,
    slug: &str,
    expected_aud: &str,
) -> Result<ServiceCtx, AppError> {
    let token = extract_bearer(headers).ok_or(AppError::Unauthorized)?;

    let row: Option<(i64, Option<String>)> = sqlx::query_as(
        "SELECT id, public_jwk FROM services
         WHERE slug = ? AND status = 'approved' AND deleted_at IS NULL",
    )
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    let (service_id, jwk_str) = row.ok_or(AppError::Forbidden)?;
    let jwk_str = jwk_str.ok_or(AppError::Forbidden)?;

    let jwk = Jwk::from_bytes(jwk_str.as_bytes())
        .map_err(|e| AppError::Other(anyhow!("decode service public_jwk: {}", e)))?;
    let verifier = RS256
        .verifier_from_jwk(&jwk)
        .map_err(|e| AppError::Other(anyhow!("build verifier: {}", e)))?;
    let (payload, _) = jwt::decode_with_verifier(&token, &verifier)
        .map_err(|_| AppError::Unauthorized)?;

    match payload.issuer() {
        Some(iss) if iss == slug => {}
        _ => return Err(AppError::Unauthorized),
    }
    let aud_ok = payload
        .audience()
        .map(|auds| auds.iter().any(|a| *a == expected_aud))
        .unwrap_or(false);
    if !aud_ok {
        return Err(AppError::Unauthorized);
    }
    match payload.expires_at() {
        Some(exp) if exp > SystemTime::now() => {}
        _ => return Err(AppError::Unauthorized),
    }

    Ok(ServiceCtx {
        service_id,
        slug: slug.to_string(),
    })
}
