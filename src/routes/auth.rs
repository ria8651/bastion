use axum::{
    extract::{ConnectInfo, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use maud::html;
use serde::Deserialize;
use std::net::SocketAddr;
use tower_cookies::Cookies;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::models::UserCtx;
use crate::oauth::{
    build_authorize_url, clear_state_cookie, exchange_code, fetch_user, generate_state,
    read_state_cookie, set_state_cookie, OAuthState,
};
use crate::session::{
    clear_session_cookie, create_session, generate_session_token, invalidate_session,
    read_session_cookie, set_session_cookie,
};
use crate::setup::get_github_oauth_config;
use crate::state::{is_secure, origin_from, AppState};
use crate::templates::layout;

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub service: Option<String>,
    pub claim_admin: Option<String>,
}

pub async fn login_page(
    State(state): State<AppState>,
    Query(q): Query<LoginQuery>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let claim_admin = q.claim_admin.as_deref() == Some("1");

    // service lookup (display only)
    let svc_name = if let Some(slug) = q.service.as_deref() {
        let row: Option<(String,)> = sqlx::query_as("SELECT name FROM services WHERE slug = ?")
            .bind(slug)
            .fetch_optional(&state.pool)
            .await?;
        row.map(|(n,)| n)
    } else {
        None
    };

    let headline = if claim_admin {
        "Claim root admin".to_string()
    } else if let Some(n) = &svc_name {
        format!("Sign in to {}", n)
    } else {
        "Sign in to bastion".to_string()
    };

    let body = html! {
        div.card style="max-width:420px;margin:3rem auto;text-align:center" {
            h1 { (headline) }
            p.muted { "Bastion uses GitHub for authentication." }
            form method="post" action="/auth/login" hx-boost="false" {
                @if let Some(s) = &q.service {
                    input type="hidden" name="service" value=(s);
                }
                @if claim_admin {
                    input type="hidden" name="claim_admin" value="1";
                }
                button.btn.primary type="submit" { "Continue with GitHub" }
            }
        }
    };
    Ok(layout("Sign in", user.as_ref(), body).into_response())
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub service: Option<String>,
    pub claim_admin: Option<String>,
}

pub async fn login_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Form(f): Form<LoginForm>,
) -> AppResult<Response> {
    let cfg = get_github_oauth_config(&state.pool)
        .await?
        .ok_or_else(|| AppError::BadRequest("GitHub OAuth not configured yet".into()))?;

    // Guard claim_admin: only allowed when no admin exists.
    let mut claim_admin = f.claim_admin.as_deref() == Some("1");
    if claim_admin {
        let (c,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_admin = 1")
            .fetch_one(&state.pool)
            .await?;
        if c > 0 {
            claim_admin = false;
        }
    }

    let origin = origin_from(&state, &headers);
    let redirect_uri = format!("{}/auth/callback", origin);
    let s = generate_state();
    set_state_cookie(
        &cookies,
        &OAuthState {
            state: s.clone(),
            service: f.service.clone(),
            claim_admin: if claim_admin { Some(true) } else { None },
        },
        is_secure(&state, &headers),
    );
    let url = build_authorize_url(&cfg.client_id, &redirect_uri, &s);
    Ok(Redirect::to(&url).into_response())
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
}

pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Query(q): Query<CallbackQuery>,
    addr: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let stored = read_state_cookie(&cookies);
    clear_state_cookie(&cookies);

    let (Some(code), Some(state_param), Some(stored)) = (q.code, q.state, stored) else {
        return Err(AppError::BadRequest("Invalid OAuth state".into()));
    };
    if stored.state != state_param {
        return Err(AppError::BadRequest("Invalid OAuth state".into()));
    }

    let cfg = get_github_oauth_config(&state.pool)
        .await?
        .ok_or_else(|| AppError::BadRequest("GitHub OAuth not configured".into()))?;
    let origin = origin_from(&state, &headers);
    let redirect_uri = format!("{}/auth/callback", origin);
    let access_token = exchange_code(&cfg, &redirect_uri, &code)
        .await
        .map_err(AppError::Other)?;
    let gh = fetch_user(&access_token).await.map_err(AppError::Other)?;

    // claim_admin only valid if no admins yet
    let mut claim_admin = stored.claim_admin.unwrap_or(false);
    if claim_admin {
        let (c,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_admin = 1")
            .fetch_one(&state.pool)
            .await?;
        if c > 0 {
            claim_admin = false;
        }
    }

    // Upsert user
    let existing: Option<(i64, bool)> =
        sqlx::query_as("SELECT id, is_admin FROM users WHERE github_id = ?")
            .bind(gh.id)
            .fetch_optional(&state.pool)
            .await?;

    let user_id: i64 = if let Some((id, is_admin)) = existing {
        let promoted = claim_admin && !is_admin;
        if promoted {
            sqlx::query(
                "UPDATE users SET email = COALESCE(?, email), avatar = COALESCE(?, avatar),
                                  last_login_at = unixepoch(), is_admin = 1, status = 'active'
                 WHERE id = ?",
            )
            .bind(&gh.email)
            .bind(&gh.avatar_url)
            .bind(id)
            .execute(&state.pool)
            .await?;
            audit(
                &state.pool,
                Some(id),
                "setup.claim_admin",
                Some(&format!("user:{}", id)),
                Some(serde_json::json!({ "gh_login": gh.login })),
            )
            .await
            .map_err(AppError::Other)?;
        } else {
            sqlx::query(
                "UPDATE users SET email = COALESCE(?, email), avatar = COALESCE(?, avatar),
                                  last_login_at = unixepoch()
                 WHERE id = ?",
            )
            .bind(&gh.email)
            .bind(&gh.avatar_url)
            .bind(id)
            .execute(&state.pool)
            .await?;
        }
        id
    } else {
        let status = if claim_admin { "active" } else { "pending" };
        let is_admin_int: i64 = if claim_admin { 1 } else { 0 };
        let inserted: (i64,) = sqlx::query_as(
            "INSERT INTO users (github_id, username, email, avatar, status, is_admin, last_login_at)
             VALUES (?, ?, ?, ?, ?, ?, unixepoch())
             RETURNING id",
        )
        .bind(gh.id)
        .bind(&gh.login)
        .bind(&gh.email)
        .bind(&gh.avatar_url)
        .bind(status)
        .bind(is_admin_int)
        .fetch_one(&state.pool)
        .await?;
        let id = inserted.0;
        audit(
            &state.pool,
            Some(id),
            if claim_admin { "setup.claim_admin" } else { "user.signup_pending" },
            Some(&format!("user:{}", id)),
            Some(serde_json::json!({ "gh_login": gh.login })),
        )
        .await
        .map_err(AppError::Other)?;
        id
    };

    // Maybe record access request for service redirect
    if let (Some(svc_slug), false) = (stored.service.as_deref(), claim_admin) {
        let svc: Option<(i64,)> = sqlx::query_as("SELECT id FROM services WHERE slug = ?")
            .bind(svc_slug)
            .fetch_optional(&state.pool)
            .await?;
        if let Some((svc_id,)) = svc {
            let granted: Option<(i64,)> = sqlx::query_as(
                "SELECT user_id FROM grants WHERE user_id = ? AND service_id = ?",
            )
            .bind(user_id)
            .bind(svc_id)
            .fetch_optional(&state.pool)
            .await?;
            if granted.is_none() {
                let pending: Option<(i64,)> = sqlx::query_as(
                    "SELECT id FROM access_requests
                     WHERE user_id = ? AND service_id = ? AND resolved_at IS NULL",
                )
                .bind(user_id)
                .bind(svc_id)
                .fetch_optional(&state.pool)
                .await?;
                if pending.is_none() {
                    sqlx::query(
                        "INSERT INTO access_requests (user_id, service_id, note)
                         VALUES (?, ?, ?)",
                    )
                    .bind(user_id)
                    .bind(svc_id)
                    .bind(format!("Requested via login redirect from {}", svc_slug))
                    .execute(&state.pool)
                    .await?;
                }
            }
        }
    }

    // Re-fetch user for status check
    let user_row: (String,) = sqlx::query_as("SELECT status FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;
    if user_row.0 == "denied" {
        return Ok(Redirect::to("/denied").into_response());
    }

    // Create session
    let token = generate_session_token();
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok());
    let ip_string = addr.map(|c| c.0.ip().to_string());
    let exp = create_session(
        &state.pool,
        &token,
        user_id,
        user_agent,
        ip_string.as_deref(),
    )
    .await
    .map_err(AppError::Other)?;
    set_session_cookie(&cookies, &token, is_secure(&state, &headers), exp);

    if claim_admin {
        return Ok(Redirect::to("/setup").into_response());
    }

    if user_row.0 == "pending" {
        let redir = match stored.service.as_deref() {
            Some(s) => format!("/pending?service={}", urlencoding::encode(s)),
            None => "/pending".into(),
        };
        return Ok(Redirect::to(&redir).into_response());
    }

    // Active user — if a service redirect, mint a token
    if let Some(svc_slug) = stored.service.as_deref() {
        let svc: Option<(i64, String, String)> =
            sqlx::query_as("SELECT id, slug, return_url FROM services WHERE slug = ?")
                .bind(svc_slug)
                .fetch_optional(&state.pool)
                .await?;
        if let Some((svc_id, slug, return_url)) = svc {
            let granted: Option<(i64,)> = sqlx::query_as(
                "SELECT user_id FROM grants WHERE user_id = ? AND service_id = ?",
            )
            .bind(user_id)
            .bind(svc_id)
            .fetch_optional(&state.pool)
            .await?;
            if granted.is_some() {
                let u: (String, i64) =
                    sqlx::query_as("SELECT username, github_id FROM users WHERE id = ?")
                        .bind(user_id)
                        .fetch_one(&state.pool)
                        .await?;
                let issued = crate::jwt::issue_service_token(
                    &state.pool,
                    crate::jwt::IssueArgs {
                        issuer: &origin,
                        user_id,
                        provider: "github",
                        provider_user_id: &u.1.to_string(),
                        username: &u.0,
                        service: &slug,
                        perms: vec![],
                    },
                )
                .await
                .map_err(AppError::Other)?;
                let mut dest =
                    url::Url::parse(&return_url).map_err(|e| AppError::Other(e.into()))?;
                dest.query_pairs_mut()
                    .append_pair("bastion_token", &issued.jwt);
                return Ok(Redirect::to(dest.as_str()).into_response());
            } else {
                return Ok(Redirect::to(&format!(
                    "/pending?service={}",
                    urlencoding::encode(&slug)
                ))
                .into_response());
            }
        }
    }

    Ok(Redirect::to("/").into_response())
}

pub async fn logout(
    State(state): State<AppState>,
    cookies: Cookies,
) -> AppResult<Response> {
    if let Some(token) = read_session_cookie(&cookies) {
        invalidate_session(&state.pool, &token)
            .await
            .map_err(AppError::Other)?;
    }
    clear_session_cookie(&cookies);
    Ok(Redirect::to("/").into_response())
}
