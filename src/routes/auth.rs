use axum::{
    extract::{ConnectInfo, Path, Query, State},
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
    read_state_cookie, set_state_cookie, OAuthState, Provider, RemoteUser,
};
use crate::session::{
    clear_session_cookie, create_session, generate_session_token, invalidate_session,
    read_session_cookie, set_session_cookie,
};
use crate::setup::get_oauth_config;
use crate::state::{is_secure, origin_from, AppState};
use crate::templates::{landing_page, provider_icon};

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub service: Option<String>,
    pub claim_admin: Option<String>,
}

pub async fn login_page(
    State(state): State<AppState>,
    Query(q): Query<LoginQuery>,
    _user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let claim_admin = q.claim_admin.as_deref() == Some("1");

    // service lookup (display only)
    let svc_row: Option<(String, String)> = if let Some(slug) = q.service.as_deref() {
        sqlx::query_as("SELECT slug, name FROM services WHERE slug = ? AND deleted_at IS NULL")
            .bind(slug)
            .fetch_optional(&state.pool)
            .await?
    } else {
        None
    };

    // Which providers have configured creds right now?
    let providers: Vec<(String,)> =
        sqlx::query_as("SELECT provider FROM oauth_providers WHERE enabled = 1 ORDER BY provider")
            .fetch_all(&state.pool)
            .await?;
    let configured: Vec<Provider> = providers
        .into_iter()
        .filter_map(|(p,)| Provider::parse(&p))
        .collect();

    let svc_slug = q.service.clone();
    let svc_name = svc_row.as_ref().map(|(_, n)| n.clone());
    let svc_known = svc_row.is_some();
    let svc_display = svc_name
        .clone()
        .or_else(|| svc_slug.clone())
        .unwrap_or_default();

    let headline = if claim_admin {
        "Claim root admin"
    } else {
        "Sign in to continue"
    };
    let subline = if claim_admin {
        "bastion needs a first admin to manage access".to_string()
    } else if svc_known {
        format!("bastion handles auth for {}", svc_display)
    } else if svc_slug.is_some() {
        "bastion handles auth for this app".to_string()
    } else {
        "bastion handles auth for your apps".to_string()
    };

    let buttons_disabled = svc_slug.is_some() && !svc_known;

    let card = html! {
        @if let Some(slug) = &svc_slug {
            @if svc_known {
                div.dest-banner {
                    div.dest-tile { (initials_two(slug)) }
                    div style="min-width:0;flex:1" {
                        div.label { "continuing to" }
                        div.slug { (svc_display) }
                    }
                }
            } @else {
                div.dest-banner.unknown {
                    div.dest-tile { "??" }
                    div style="min-width:0;flex:1" {
                        div.label { "unknown service" }
                        div.slug { (slug) }
                    }
                    span.pill.denied { "unknown" }
                }
            }
        } @else if claim_admin {
            div.dest-banner {
                div.dest-tile { "ba" }
                div style="min-width:0;flex:1" {
                    div.label { "first-run setup" }
                    div.slug { "claim admin" }
                }
            }
        }

        div.landing-headline { (headline) }
        div.landing-subline { (subline) }

        div.provider-stack {
            @if configured.is_empty() {
                div style="font-family:var(--font-mono);font-size:12px;color:var(--fg-mute);text-align:center;padding:12px" {
                    "no identity providers configured"
                }
            } @else {
                @for p in &configured {
                    form method="post" action="/auth/login" hx-boost="false" style="margin:0" {
                        @if let Some(s) = &svc_slug {
                            input type="hidden" name="service" value=(s);
                        }
                        @if claim_admin {
                            input type="hidden" name="claim_admin" value="1";
                        }
                        input type="hidden" name="provider" value=(p.as_str());
                        button.provider-btn type="submit" disabled[buttons_disabled] {
                            (provider_icon(p.as_str()))
                            span { "Continue with " (p.display_name()) }
                        }
                    }
                }
            }
        }

        div.landing-footnote {
            @if svc_slug.is_some() {
                @if svc_known {
                    span.mono { (svc_display) } " will receive your bastion id,"
                    br;
                    " email, and granted permissions."
                } @else {
                    "This service isn't registered with bastion."
                }
            } @else {
                "bastion will share your id, email,"
                br;
                " and granted permissions with each app."
            }
        }
    };
    Ok(landing_page("Sign in", card).into_response())
}

fn initials_two(slug: &str) -> String {
    let s: String = slug
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(2)
        .collect();
    s.to_lowercase()
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub service: Option<String>,
    pub claim_admin: Option<String>,
    pub provider: String,
}

pub async fn login_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Form(f): Form<LoginForm>,
) -> AppResult<Response> {
    let provider = Provider::parse(&f.provider)
        .ok_or_else(|| AppError::BadRequest("unknown provider".into()))?;
    let cfg = get_oauth_config(&state.pool, provider.as_str())
        .await?
        .ok_or_else(|| {
            AppError::BadRequest(format!("{} OAuth not configured yet", provider.display_name()))
        })?;

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
            provider,
            service: f.service.clone(),
            claim_admin: if claim_admin { Some(true) } else { None },
            link_to_user_id: None,
        },
        is_secure(&state, &headers),
    );
    let url = build_authorize_url(provider, &cfg.client_id, &redirect_uri, &s);
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

    let provider = stored.provider;
    let cfg = get_oauth_config(&state.pool, provider.as_str())
        .await?
        .ok_or_else(|| {
            AppError::BadRequest(format!("{} OAuth not configured", provider.display_name()))
        })?;
    let origin = origin_from(&state, &headers);
    let redirect_uri = format!("{}/auth/callback", origin);
    let access_token = exchange_code(provider, &cfg, &redirect_uri, &code)
        .await
        .map_err(AppError::Other)?;
    let remote = fetch_user(provider, &access_token)
        .await
        .map_err(AppError::Other)?;

    // ─── Linking flow: attach this identity to an already-signed-in user. ───
    if let Some(link_uid) = stored.link_to_user_id {
        return link_identity_and_redirect(&state, &cookies, &headers, addr, link_uid, provider, &remote)
            .await;
    }

    // ─── Normal login / signup flow. ───
    let mut claim_admin = stored.claim_admin.unwrap_or(false);
    if claim_admin {
        let (c,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_admin = 1")
            .fetch_one(&state.pool)
            .await?;
        if c > 0 {
            claim_admin = false;
        }
    }

    // Existing identity?
    let existing: Option<(i64, i64, bool)> = sqlx::query_as(
        "SELECT ui.id, u.id, u.is_admin
         FROM user_identities ui
         JOIN users u ON u.id = ui.user_id
         WHERE ui.provider = ? AND ui.provider_id = ?",
    )
    .bind(provider.as_str())
    .bind(&remote.provider_id)
    .fetch_optional(&state.pool)
    .await?;

    let user_id: i64 = if let Some((identity_id, uid, is_admin)) = existing {
        // Existing user — refresh identity + user metadata.
        sqlx::query(
            "UPDATE user_identities
             SET email = COALESCE(?, email),
                 avatar = COALESCE(?, avatar),
                 last_login_at = unixepoch()
             WHERE id = ?",
        )
        .bind(&remote.email)
        .bind(&remote.avatar)
        .bind(identity_id)
        .execute(&state.pool)
        .await?;

        let promoted = claim_admin && !is_admin;
        if promoted {
            sqlx::query(
                "UPDATE users
                 SET email = COALESCE(?, email),
                     avatar = COALESCE(?, avatar),
                     last_login_at = unixepoch(),
                     is_admin = 1,
                     status = 'active'
                 WHERE id = ?",
            )
            .bind(&remote.email)
            .bind(&remote.avatar)
            .bind(uid)
            .execute(&state.pool)
            .await?;
            audit(
                &state.pool,
                Some(uid),
                "setup.claim_admin",
                Some(&format!("user:{}", uid)),
                Some(serde_json::json!({
                    "provider": provider.as_str(),
                    "username": remote.username,
                })),
            )
            .await
            .map_err(AppError::Other)?;
        } else {
            sqlx::query(
                "UPDATE users
                 SET email = COALESCE(?, email),
                     avatar = COALESCE(?, avatar),
                     last_login_at = unixepoch()
                 WHERE id = ?",
            )
            .bind(&remote.email)
            .bind(&remote.avatar)
            .bind(uid)
            .execute(&state.pool)
            .await?;
        }
        uid
    } else {
        // Brand-new user. Freeze the sub anchor to whichever provider signed them up first.
        let status = if claim_admin { "active" } else { "pending" };
        let is_admin_int: i64 = if claim_admin { 1 } else { 0 };
        let username = pick_available_username(&state, &remote.username).await?;
        let inserted: (i64,) = sqlx::query_as(
            "INSERT INTO users (
                github_id, username, email, avatar, status, is_admin, last_login_at,
                sub_anchor_provider, sub_anchor_provider_id
             ) VALUES (?, ?, ?, ?, ?, ?, unixepoch(), ?, ?)
             RETURNING id",
        )
        // github_id is a legacy NOT NULL column; stuff 0 for non-github signups
        // (it's read-only and ignored by new code).
        .bind(legacy_github_id(provider, &remote.provider_id))
        .bind(&username)
        .bind(&remote.email)
        .bind(&remote.avatar)
        .bind(status)
        .bind(is_admin_int)
        .bind(provider.as_str())
        .bind(&remote.provider_id)
        .fetch_one(&state.pool)
        .await?;
        let new_uid = inserted.0;
        sqlx::query(
            "INSERT INTO user_identities (user_id, provider, provider_id, email, avatar, last_login_at)
             VALUES (?, ?, ?, ?, ?, unixepoch())",
        )
        .bind(new_uid)
        .bind(provider.as_str())
        .bind(&remote.provider_id)
        .bind(&remote.email)
        .bind(&remote.avatar)
        .execute(&state.pool)
        .await?;
        audit(
            &state.pool,
            Some(new_uid),
            if claim_admin {
                "setup.claim_admin"
            } else {
                "user.signup_pending"
            },
            Some(&format!("user:{}", new_uid)),
            Some(serde_json::json!({
                "provider": provider.as_str(),
                "username": remote.username,
            })),
        )
        .await
        .map_err(AppError::Other)?;
        new_uid
    };

    // Maybe record access request for service redirect
    if let (Some(svc_slug), false) = (stored.service.as_deref(), claim_admin) {
        let svc: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM services WHERE slug = ? AND deleted_at IS NULL")
                .bind(svc_slug)
                .fetch_optional(&state.pool)
                .await?;
        if let Some((svc_id,)) = svc {
            let granted: Option<(i64,)> =
                sqlx::query_as("SELECT user_id FROM grants WHERE user_id = ? AND service_id = ?")
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
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok());
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

    // Active user — if a service redirect, mint a token from the frozen sub anchor.
    if let Some(svc_slug) = stored.service.as_deref() {
        let svc: Option<(i64, String, String)> = sqlx::query_as(
            "SELECT id, slug, return_url FROM services WHERE slug = ? AND deleted_at IS NULL",
        )
        .bind(svc_slug)
        .fetch_optional(&state.pool)
        .await?;
        if let Some((svc_id, slug, return_url)) = svc {
            let granted: Option<(i64,)> =
                sqlx::query_as("SELECT user_id FROM grants WHERE user_id = ? AND service_id = ?")
                    .bind(user_id)
                    .bind(svc_id)
                    .fetch_optional(&state.pool)
                    .await?;
            if granted.is_some() {
                let u: (String, String, String) = sqlx::query_as(
                    "SELECT username, sub_anchor_provider, sub_anchor_provider_id
                     FROM users WHERE id = ?",
                )
                .bind(user_id)
                .fetch_one(&state.pool)
                .await?;
                let issued = crate::jwt::issue_service_token(
                    &state.pool,
                    crate::jwt::IssueArgs {
                        issuer: &origin,
                        user_id,
                        provider: &u.1,
                        provider_user_id: &u.2,
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

/// Stuff a synthetic value into the legacy `users.github_id` NOT NULL column for
/// non-github signups. The column is unread by new code; we just need to satisfy
/// the schema.
fn legacy_github_id(provider: Provider, provider_id: &str) -> i64 {
    match provider {
        Provider::Github => provider_id.parse::<i64>().unwrap_or(0),
        Provider::Google => 0,
    }
}

async fn pick_available_username(state: &AppState, base: &str) -> AppResult<String> {
    let candidate = if base.is_empty() { "user".to_string() } else { base.to_string() };
    let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM users WHERE username = ?")
        .bind(&candidate)
        .fetch_optional(&state.pool)
        .await?;
    if exists.is_none() {
        return Ok(candidate);
    }
    for n in 2..1000 {
        let try_name = format!("{}-{}", candidate, n);
        let hit: Option<(i64,)> = sqlx::query_as("SELECT id FROM users WHERE username = ?")
            .bind(&try_name)
            .fetch_optional(&state.pool)
            .await?;
        if hit.is_none() {
            return Ok(try_name);
        }
    }
    Err(AppError::Other(anyhow::anyhow!(
        "could not find unique username for '{}'",
        base
    )))
}

async fn link_identity_and_redirect(
    state: &AppState,
    cookies: &Cookies,
    headers: &HeaderMap,
    addr: Option<ConnectInfo<SocketAddr>>,
    link_uid: i64,
    provider: Provider,
    remote: &RemoteUser,
) -> AppResult<Response> {
    // The user must still be signed in as the user they asked to link to.
    let token = read_session_cookie(cookies)
        .ok_or_else(|| AppError::Unauthorized)?;
    let session = crate::session::validate_session_token(&state.pool, &token)
        .await
        .map_err(AppError::Other)?;
    let Some((current_user, _sid)) = session else {
        return Err(AppError::Unauthorized);
    };
    if current_user.id != link_uid {
        return Err(AppError::Forbidden);
    }
    if current_user.status == "denied" {
        return Err(AppError::Forbidden);
    }

    // Is this provider identity already attached to someone?
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM user_identities WHERE provider = ? AND provider_id = ?",
    )
    .bind(provider.as_str())
    .bind(&remote.provider_id)
    .fetch_optional(&state.pool)
    .await?;
    if let Some((other_uid,)) = existing {
        if other_uid == link_uid {
            return Ok(Redirect::to("/account?already=1").into_response());
        }
        return Err(AppError::BadRequest(format!(
            "that {} account is already linked to a different bastion user",
            provider.display_name()
        )));
    }

    sqlx::query(
        "INSERT INTO user_identities (user_id, provider, provider_id, email, avatar, last_login_at)
         VALUES (?, ?, ?, ?, ?, unixepoch())",
    )
    .bind(link_uid)
    .bind(provider.as_str())
    .bind(&remote.provider_id)
    .bind(&remote.email)
    .bind(&remote.avatar)
    .execute(&state.pool)
    .await?;

    audit(
        &state.pool,
        Some(link_uid),
        "user.identity_linked",
        Some(&format!("user:{}", link_uid)),
        Some(serde_json::json!({
            "provider": provider.as_str(),
            "provider_id": remote.provider_id,
        })),
    )
    .await
    .map_err(AppError::Other)?;

    // Silence unused-vars lint.
    let _ = headers;
    let _ = addr;
    Ok(Redirect::to("/account?linked=1").into_response())
}

pub async fn launch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = match user {
        Some(Extension(u)) => u,
        None => {
            return Ok(Redirect::to(&format!(
                "/auth/login?service={}",
                urlencoding::encode(&slug)
            ))
            .into_response());
        }
    };
    if user.status != "active" {
        let path = match user.status.as_str() {
            "denied" => "/denied".to_string(),
            _ => format!("/pending?service={}", urlencoding::encode(&slug)),
        };
        return Ok(Redirect::to(&path).into_response());
    }

    let svc: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT id, slug, return_url FROM services WHERE slug = ? AND deleted_at IS NULL",
    )
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await?;
    let Some((svc_id, svc_slug, return_url)) = svc else {
        return Err(AppError::NotFound);
    };

    let granted: Option<(i64,)> =
        sqlx::query_as("SELECT user_id FROM grants WHERE user_id = ? AND service_id = ?")
            .bind(user.id)
            .bind(svc_id)
            .fetch_optional(&state.pool)
            .await?;
    if granted.is_none() {
        return Ok(Redirect::to(&format!(
            "/pending?service={}",
            urlencoding::encode(&svc_slug)
        ))
        .into_response());
    }

    let origin = origin_from(&state, &headers);
    let issued = crate::jwt::issue_service_token(
        &state.pool,
        crate::jwt::IssueArgs {
            issuer: &origin,
            user_id: user.id,
            provider: &user.sub_anchor_provider,
            provider_user_id: &user.sub_anchor_provider_id,
            username: &user.username,
            service: &svc_slug,
            perms: vec![],
        },
    )
    .await
    .map_err(AppError::Other)?;

    let mut dest = url::Url::parse(&return_url).map_err(|e| AppError::Other(e.into()))?;
    dest.query_pairs_mut()
        .append_pair("bastion_token", &issued.jwt);
    Ok(Redirect::to(dest.as_str()).into_response())
}

pub async fn logout(State(state): State<AppState>, cookies: Cookies) -> AppResult<Response> {
    if let Some(token) = read_session_cookie(&cookies) {
        invalidate_session(&state.pool, &token)
            .await
            .map_err(AppError::Other)?;
    }
    clear_session_cookie(&cookies);
    Ok(Redirect::to("/").into_response())
}
