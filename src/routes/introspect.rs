use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::jwt::verify_service_token;
use crate::state::{origin_from, AppState};

pub async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let token = match extract_bearer(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "active": false, "error": "missing bearer token" })),
            )
                .into_response()
        }
    };

    let origin = origin_from(&state, &headers);
    let payload = match verify_service_token(&state.pool, &origin, &token).await {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "active": false, "error": e.to_string() })),
            )
                .into_response()
        }
    };

    let claims = payload.claims_set();
    let user_id = claims
        .get("bastion_uid")
        .and_then(Value::as_i64);
    let Some(user_id) = user_id else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "active": false, "error": "missing bastion_uid claim" })),
        )
            .into_response();
    };

    let user: Option<(i64, String, Option<String>, Option<String>, String, bool)> = match sqlx::query_as(
        "SELECT id, username, email, avatar, status, is_admin FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = ?e, "introspect user lookup");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    };
    let Some((uid, username, email, avatar, status, is_admin)) = user else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "active": false, "error": "user not found" })),
        )
            .into_response();
    };
    if status != "active" {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "active": false, "error": "user not active" })),
        )
            .into_response();
    }

    let svc = claims.get("svc").and_then(Value::as_str).map(String::from);
    let mut granted = false;
    let mut service_id: Option<i64> = None;
    if let Some(slug) = &svc {
        let s: Option<(i64,)> = sqlx::query_as(
            "SELECT id FROM services WHERE slug = ? AND deleted_at IS NULL",
        )
        .bind(slug)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
        if let Some((sid,)) = s {
            service_id = Some(sid);
            let g: Option<(i64,)> =
                sqlx::query_as("SELECT user_id FROM grants WHERE user_id = ? AND service_id = ?")
                    .bind(uid)
                    .bind(sid)
                    .fetch_optional(&state.pool)
                    .await
                    .ok()
                    .flatten();
            granted = g.is_some();
        }
    }

    let perms: Vec<String> = if let Some(sid) = service_id {
        sqlx::query_as::<_, (String,)>(
            "SELECT p.key FROM user_perms up
             JOIN permissions p ON p.id = up.permission_id
             WHERE up.user_id = ? AND p.service_id = ?",
        )
        .bind(uid)
        .bind(sid)
        .fetch_all(&state.pool)
        .await
        .map(|rows| rows.into_iter().map(|(k,)| k).collect())
        .unwrap_or_default()
    } else {
        vec![]
    };

    let exp = claims.get("exp").and_then(Value::as_i64);
    let sub = claims.get("sub").and_then(Value::as_str);

    Json(json!({
        "active": true,
        "sub": sub,
        "bastion_uid": uid,
        "username": username,
        "email": email,
        "avatar": avatar,
        "is_admin": is_admin,
        "svc": svc,
        "granted": granted,
        "perms": perms,
        "exp": exp,
    }))
    .into_response()
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get("authorization")?.to_str().ok()?;
    let s = v.trim();
    if let Some(rest) = s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")) {
        Some(rest.trim().to_string())
    } else {
        None
    }
}
