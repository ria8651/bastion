use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use maud::{html, Markup};
use serde::Deserialize;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::require_admin;
use crate::models::UserCtx;
use crate::setup::{clear_oauth_config, get_setup_state, set_oauth_config};
use crate::state::{origin_from, AppState};
use crate::templates::{
    bottom_strip, host_from_origin, layout, page_chrome, pill, provider_icon,
};

pub async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let setup = get_setup_state(&state.pool).await.map_err(AppError::Other)?;
    let step = setup.step();
    let origin = origin_from(&state, &headers);
    let host = host_from_origin(&origin).to_string();
    let user = user.map(|Extension(u)| u);

    // Step 3 is now optional (services can self-register), but we still
    // show it to give the freshly-claimed admin a chance to approve any
    // pending registrations or pre-register manually before leaving the
    // wizard. Anyone arriving at /setup with admin already claimed lands
    // here too — harmless, and the Finish button gets them out.
    let (approved, pending, pending_perms) = if step == 3 {
        let pending = load_pending(&state.pool).await?;
        let perms = if pending.is_empty() {
            std::collections::HashMap::new()
        } else {
            load_pending_perms(&state.pool).await?
        };
        (load_approved(&state.pool).await?, pending, perms)
    } else {
        (Vec::new(), Vec::new(), std::collections::HashMap::new())
    };

    let title = match step {
        1 => "Connect identity providers",
        2 => "Claim root admin",
        _ => "Connect your services",
    };
    let subtitle = match step {
        1 => "Bastion needs at least one OAuth provider to authenticate users. Configure GitHub, Google, or both.",
        2 => "Sign in with the account that should be the first admin. They'll be able to invite others.",
        _ => "Services can register themselves on first boot — leave this page open and they'll appear below for approval. You can also pre-register manually, or skip this step entirely and add services later from /admin/services.",
    };

    let body = html! {
        (page_chrome(Some("first-run setup"), &host, true))

        div.setup-main {
            div.setup-steps {
                (step_marker(1, "providers", step))
                span.sep {}
                (step_marker(2, "claim admin", step))
                span.sep {}
                (step_marker(3, "connect services", step))
            }

            div.setup-title { (title) }
            div.setup-subtitle { (subtitle) }

            @match step {
                1 => (step1(&origin, setup.has_github, setup.has_google)),
                2 => (step2(user.as_ref())),
                _ => (step3(&approved, &pending, &pending_perms)),
            }
        }
        (bottom_strip(None, true))
    };
    Ok(layout("Setup", body).into_response())
}

/// htmx polling target — returns just the pending-registrations card so
/// step 3 can refresh it every few seconds without disturbing the rest
/// of the page or the manual-add form's focus state.
pub async fn pending_partial(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;
    let pending = load_pending(&state.pool).await?;
    let perms = if pending.is_empty() {
        std::collections::HashMap::new()
    } else {
        load_pending_perms(&state.pool).await?
    };
    Ok(pending_block(&pending, &perms).into_response())
}

fn step_marker(n: u8, label: &str, current: u8) -> Markup {
    let class = if n == current {
        "step active"
    } else if n < current {
        "step done"
    } else {
        "step"
    };
    html! {
        span class=(class) {
            span.num { (n) }
            span.label { (label) }
        }
    }
}

fn provider_row(
    provider_slug: &str,
    display_name: &str,
    configured: bool,
    optional_when_other_present: bool,
) -> Markup {
    html! {
        div class=(if configured { "setup-row configured" } else { "setup-row" }) {
            span.ico style="width:18px;height:18px" { (provider_icon(provider_slug)) }
            div.body {
                div.label { (display_name) }
                div.detail {
                    @if configured {
                        "configured"
                    } @else if optional_when_other_present {
                        "optional · oauth 2.0"
                    } @else {
                        "needs setup · oauth 2.0"
                    }
                }
            }
            @if configured {
                (pill("active", "connected"))
            } @else {
                span.mono style="font-size:11px;color:var(--fg-dim)" { "use form below" }
            }
        }
    }
}

fn provider_form(
    provider_slug: &str,
    display_name: &str,
    origin: &str,
    save_action: &str,
    extra_lines: Option<Markup>,
) -> Markup {
    let cb = format!("{}/auth/callback", origin);
    let homepage_label = format!("{} OAuth credentials", display_name);
    html! {
        div.setup-card {
            h2 { "Configure " (display_name) }
            p { (homepage_label) ":" }
            ul {
                li { "Homepage URL: " code { (origin) } }
                li { "Authorization callback URL: " code { (cb) } }
            }
            @if let Some(extra) = extra_lines { (extra) }
            form method="post" action=(save_action) style="margin-top:14px" {
                label.field { "Client ID"
                    input.input name="clientId" required;
                }
                label.field { "Client Secret"
                    input.input name="clientSecret" type="password" required;
                }
                div style="margin-top:18px" {
                    button.btn.primary type="submit" {
                        "Save " (display_name) " creds"
                    }
                }
            }
            @if !provider_slug.is_empty() {
                // anchor for jump-to behavior on /admin/providers, harmless here
                span hidden { (provider_slug) }
            }
        }
    }
}

fn step1(origin: &str, has_github: bool, has_google: bool) -> Markup {
    let has_any = has_github || has_google;
    let gh_help = html! {
        p style="font-size:13px;color:var(--fg-mute);line-height:1.6" {
            "Create a new OAuth App at "
            a target="_blank" rel="noopener"
              href="https://github.com/settings/applications/new"
              style="color:var(--fg);text-decoration:underline" {
                "github.com/settings/applications/new"
            }
            " (your existing apps live at "
            a target="_blank" rel="noopener"
              href="https://github.com/settings/developers"
              style="color:var(--fg);text-decoration:underline" {
                "github.com/settings/developers"
            }
            ")."
        }
    };
    let g_help = html! {
        p style="font-size:13px;color:var(--fg-mute);line-height:1.6" {
            "Create OAuth 2.0 credentials (Web application type) at "
            a target="_blank" rel="noopener"
              href="https://console.cloud.google.com/apis/credentials/oauthclient"
              style="color:var(--fg);text-decoration:underline" {
                "console.cloud.google.com/apis/credentials/oauthclient"
            }
            " (existing credentials at "
            a target="_blank" rel="noopener"
              href="https://console.cloud.google.com/apis/credentials"
              style="color:var(--fg);text-decoration:underline" {
                "console.cloud.google.com/apis/credentials"
            }
            ")."
        }
    };
    html! {
        div.setup-rows {
            (provider_row("github", "GitHub", has_github, has_any))
            (provider_row("google", "Google", has_google, has_any))
        }

        @if !has_github {
            (provider_form(
                "github",
                "GitHub",
                origin,
                "/setup/save-provider/github",
                Some(gh_help),
            ))
        }
        @if !has_google {
            (provider_form(
                "google",
                "Google",
                origin,
                "/setup/save-provider/google",
                Some(g_help),
            ))
        }

        @if has_any {
            div.setup-foot {
                span.progress {
                    @if has_github && has_google { "2 of 2 connected" }
                    @else { "1 of 2 connected · either is sufficient" }
                }
                div.actions {
                    @if has_github {
                        form method="post" action="/setup/reset-provider/github" style="margin:0" {
                            button.btn.text type="submit" { "← reset github" }
                        }
                    }
                    @if has_google {
                        form method="post" action="/setup/reset-provider/google" style="margin:0" {
                            button.btn.text type="submit" { "← reset google" }
                        }
                    }
                    a.btn.primary href="/setup" { "continue →" }
                }
            }
        }
    }
}

fn step2(user: Option<&UserCtx>) -> Markup {
    html! {
        div.setup-card {
            h2 { "Sign in to claim the first admin account" }
            p {
                "Bastion needs at least one admin who can register services and approve users. "
                "Sign in with the account you want as the first admin."
            }
            @if let Some(u) = user {
                p style="margin-top:12px" {
                    "Currently signed in as "
                    span.mono style="color:var(--fg)" { (u.username) }
                    ". "
                    @if u.is_admin {
                        "You're already an admin."
                    } @else {
                        "If that's right, click below to claim admin."
                    }
                }
            }

            div style="margin-top:18px;display:flex;gap:8px;align-items:center;flex-wrap:wrap" {
                a.btn.primary href="/auth/login?claim_admin=1" { "Sign in & claim admin →" }
            }
        }
    }
}

type ApprovedRow = (i64, String, String);
type PendingRow = (i64, String, String, String, Option<String>, Option<i64>);

async fn load_approved(pool: &sqlx::SqlitePool) -> AppResult<Vec<ApprovedRow>> {
    let rows = sqlx::query_as(
        "SELECT id, slug, return_url FROM services
         WHERE deleted_at IS NULL AND status = 'approved'
         ORDER BY slug",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

async fn load_pending(pool: &sqlx::SqlitePool) -> AppResult<Vec<PendingRow>> {
    let rows = sqlx::query_as(
        "SELECT id, slug, name, return_url, public_jwk, registered_at FROM services
         WHERE deleted_at IS NULL AND status = 'pending'
         ORDER BY registered_at DESC, id DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

async fn load_pending_perms(
    pool: &sqlx::SqlitePool,
) -> AppResult<std::collections::HashMap<i64, Vec<(String, Option<String>)>>> {
    let rows: Vec<(i64, String, Option<String>)> = sqlx::query_as(
        "SELECT service_id, key, description FROM permissions
         WHERE removed_at IS NULL AND service_id IN (
            SELECT id FROM services WHERE status = 'pending' AND deleted_at IS NULL
         )
         ORDER BY service_id, key",
    )
    .fetch_all(pool)
    .await?;
    let mut by_svc: std::collections::HashMap<i64, Vec<(String, Option<String>)>> =
        std::collections::HashMap::new();
    for (sid, key, desc) in rows {
        by_svc.entry(sid).or_default().push((key, desc));
    }
    Ok(by_svc)
}

fn step3(
    approved: &[ApprovedRow],
    pending: &[PendingRow],
    pending_perms: &std::collections::HashMap<i64, Vec<(String, Option<String>)>>,
) -> Markup {
    let has_any = !approved.is_empty();
    html! {
        (pending_block(pending, pending_perms))

        @if !approved.is_empty() {
            div.setup-rows style="margin-top:24px" {
                @for (id, slug, return_url) in approved {
                    div.setup-row.configured {
                        span.ico style="width:18px;height:18px;display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--line);border-radius:6px;background:var(--bg-hover);color:var(--fg-mid);font-family:var(--font-mono);font-size:10px" {
                            (slug.chars().take(2).collect::<String>().to_lowercase())
                        }
                        div.body {
                            div.label { (slug) }
                            div.detail { (return_url) }
                        }
                        form method="post" action="/setup/remove-service" style="margin:0" {
                            input type="hidden" name="id" value=(id);
                            button.btn.danger type="submit" { "remove" }
                        }
                    }
                }
            }
        }

        details.setup-card style="margin-top:24px" {
            summary style="cursor:pointer;font-weight:500" { "Register a service manually" }
            p style="margin-top:10px;font-size:13px;color:var(--fg-mute)" {
                "Use this when a service can't self-register (e.g., a static frontend with no backend to call /api/services/register)."
            }
            form method="post" action="/setup/add-service" style="margin-top:14px" {
                label.field { "Slug (lowercase, dashes ok)"
                    input.input name="slug" required title="lowercase letters, digits, and hyphens";
                }
                label.field { "Display name"
                    input.input name="name";
                }
                label.field { "Return URL"
                    input.input name="returnUrl" type="url" required;
                }
                div style="margin-top:18px" {
                    button.btn.primary type="submit" { "Add service" }
                }
            }
        }

        div.setup-foot {
            span.progress {
                @if has_any {
                    (approved.len()) " service" @if approved.len() != 1 { "s" } " connected"
                } @else {
                    "no services yet · this step is optional"
                }
            }
            div.actions {
                form method="post" action="/setup/finish" style="margin:0" {
                    button.btn.primary type="submit" {
                        @if has_any { "Finish setup →" } @else { "Skip & finish →" }
                    }
                }
            }
        }
    }
}

fn pending_block(
    pending: &[PendingRow],
    pending_perms: &std::collections::HashMap<i64, Vec<(String, Option<String>)>>,
) -> Markup {
    html! {
        div
          #pending-services
          hx-get="/setup/pending"
          hx-trigger="every 4s [!document.activeElement || !document.activeElement.closest('#pending-services')]"
          hx-target="this"
          hx-swap="outerHTML"
        {
            @if pending.is_empty() {
                div.setup-card style="border-style:dashed;background:transparent" {
                    div style="display:flex;align-items:center;gap:10px" {
                        span style="width:8px;height:8px;border-radius:50%;background:var(--fg-mute);display:inline-block" {}
                        span style="font-family:var(--font-mono);font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:var(--fg-mute)" {
                            "waiting for service registrations…"
                        }
                    }
                    p style="margin-top:8px;font-size:13px;color:var(--fg-mute);line-height:1.6" {
                        "Start a service configured to register with bastion and it'll appear here within a few seconds. Services announce themselves by sending "
                        code.mono { "POST /api/services/register" }
                        " on boot."
                    }
                }
            } @else {
                div style="margin:0 0 12px 2px;font-family:var(--font-mono);font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:var(--fg-mute)" {
                    "pending registrations · " (pending.len())
                }
                div.req-grid style="grid-template-columns:1fr" {
                    @for (sid, slug, name, ret, jwk_opt, registered_at) in pending {
                        div.req-card {
                            div.req-head {
                                div.info {
                                    div.uname { (slug) }
                                    div.via {
                                        span { (name) }
                                    }
                                }
                                (pill("pending", "pending"))
                            }
                            div.req-body style="padding-top:8px;padding-bottom:8px" {
                                div.lbl style="margin-bottom:4px" { "suggested return url" }
                                div.mono style="font-size:12px;color:var(--fg-mid);word-break:break-all" {
                                    @if ret.is_empty() {
                                        span style="color:var(--fg-mute);font-style:italic" { "(none — set one below)" }
                                    } @else {
                                        (ret)
                                    }
                                }
                            }
                            div.req-meta {
                                div {
                                    div.lbl { "kid" }
                                    div.val.mono style="font-size:11px" {
                                        (crate::routes::admin::jwk_short(jwk_opt.as_deref()))
                                    }
                                }
                                div {
                                    div.lbl { "fingerprint" }
                                    div.val.mono style="font-size:11px" {
                                        (crate::routes::admin::jwk_thumbprint_short(jwk_opt.as_deref()))
                                    }
                                }
                                div {
                                    div.lbl { "registered" }
                                    div.val { (registered_at.map(|t| crate::routes::admin::rel_time(t)).unwrap_or_else(|| "—".into())) }
                                }
                            }
                            @let perms_here = pending_perms.get(sid);
                            @if let Some(ps) = perms_here {
                                div style="padding:8px 14px 12px;border-top:1px solid var(--border)" {
                                    div.lbl style="margin-bottom:6px" { "declared permissions · " (ps.len()) }
                                    @for (key, desc) in ps {
                                        div.mono style="font-size:12px;padding:3px 0" {
                                            (key)
                                            @if let Some(d) = desc {
                                                span style="color:var(--fg-mute)" { "  — " (d) }
                                            }
                                        }
                                    }
                                }
                            } @else {
                                div style="padding:8px 14px 12px;border-top:1px solid var(--border);color:var(--fg-mute);font-size:12px" {
                                    "no permissions declared"
                                }
                            }
                            div style="padding:12px 14px;border-top:1px solid var(--border);display:grid;gap:8px" {
                                form method="post" action="/setup/approve-service" style="display:grid;gap:8px;margin:0" {
                                    input type="hidden" name="id" value=(sid);
                                    label.field style="margin:0" {
                                        "Return URL (the value users' browsers will be redirected back to)"
                                        input.input.mono name="returnUrl" value=(ret) required type="url" style="font-size:12px";
                                    }
                                    div style="display:flex;gap:8px;align-items:center" {
                                        button.btn.primary type="submit" { "Approve" }
                                        button.btn.danger type="submit"
                                            formaction="/setup/deny-service"
                                            formnovalidate
                                            onclick="return confirm('Deny this registration? The service will be blocked from re-registering with the same slug until you remove it.')"
                                            { "Deny" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SaveProviderForm {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: String,
}

pub async fn save_provider(
    State(state): State<AppState>,
    axum::extract::Path(provider): axum::extract::Path<String>,
    Form(f): Form<SaveProviderForm>,
) -> AppResult<Response> {
    if provider != "github" && provider != "google" {
        return Err(AppError::BadRequest("unknown provider".into()));
    }
    let setup = get_setup_state(&state.pool).await.map_err(AppError::Other)?;
    // Once an admin is claimed and services exist (setup complete), use /admin/providers instead.
    if setup.complete() {
        return Err(AppError::BadRequest(
            "setup already complete; use /admin/providers".into(),
        ));
    }
    let cid = f.client_id.trim();
    let cs = f.client_secret.trim();
    if cid.is_empty() || cs.is_empty() {
        return Err(AppError::BadRequest(
            "Both client id and secret are required".into(),
        ));
    }
    set_oauth_config(&state.pool, &provider, cid, cs)
        .await
        .map_err(AppError::Other)?;
    audit(
        &state.pool,
        None,
        &format!("setup.{}_configured", provider),
        Some(&format!("provider:{}", provider)),
        None,
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/setup").into_response())
}

pub async fn reset_provider(
    State(state): State<AppState>,
    axum::extract::Path(provider): axum::extract::Path<String>,
) -> AppResult<Response> {
    if provider != "github" && provider != "google" {
        return Err(AppError::BadRequest("unknown provider".into()));
    }
    let setup = get_setup_state(&state.pool).await.map_err(AppError::Other)?;
    if setup.has_admin {
        return Err(AppError::BadRequest(
            "can't reset provider creds after an admin has been claimed".into(),
        ));
    }
    clear_oauth_config(&state.pool, &provider)
        .await
        .map_err(AppError::Other)?;
    audit(
        &state.pool,
        None,
        &format!("setup.{}_cleared", provider),
        Some(&format!("provider:{}", provider)),
        None,
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/setup").into_response())
}

#[derive(Debug, Deserialize)]
pub struct ServiceForm {
    pub slug: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "returnUrl")]
    pub return_url: String,
}

fn validate_service(f: &ServiceForm) -> Result<(String, String, String), String> {
    let slug = f.slug.trim().to_string();
    let name = {
        let n = f.name.trim();
        if n.is_empty() {
            slug.clone()
        } else {
            n.to_string()
        }
    };
    let return_url = f.return_url.trim().to_string();
    if slug.is_empty() || return_url.is_empty() {
        return Err("slug and return url required".into());
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("slug must be lowercase alphanumeric + dashes".into());
    }
    if url::Url::parse(&return_url).is_err() {
        return Err("return url must be a valid URL".into());
    }
    Ok((slug, name, return_url))
}

pub async fn add_service(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<ServiceForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
    let (slug, name, return_url) = validate_service(&f).map_err(AppError::BadRequest)?;
    // Manually-added services are admin-approved by definition — drop them
    // straight into 'approved' so they're usable immediately. Self-registered
    // services still land as 'pending' via /api/services/register.
    let inserted: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO services (slug, name, return_url, status, approved_at, approved_by)
         VALUES (?, ?, ?, 'approved', unixepoch(), ?)
         ON CONFLICT(slug) WHERE deleted_at IS NULL DO NOTHING RETURNING id",
    )
    .bind(&slug)
    .bind(&name)
    .bind(&return_url)
    .bind(admin.id)
    .fetch_optional(&state.pool)
    .await?;
    if let Some((svc_id,)) = inserted {
        sqlx::query(
            "INSERT INTO grants (user_id, service_id, granted_by) VALUES (?, ?, ?)
             ON CONFLICT(user_id, service_id) DO NOTHING",
        )
        .bind(admin.id)
        .bind(svc_id)
        .bind(admin.id)
        .execute(&state.pool)
        .await?;
    }
    Ok(Redirect::to("/setup").into_response())
}

#[derive(Debug, Deserialize)]
pub struct IdForm {
    pub id: i64,
}

pub async fn remove_service(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<IdForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;
    sqlx::query("UPDATE services SET deleted_at = unixepoch() WHERE id = ? AND deleted_at IS NULL")
        .bind(f.id)
        .execute(&state.pool)
        .await?;
    Ok(Redirect::to("/setup").into_response())
}

#[derive(Debug, Deserialize)]
pub struct ApproveServiceForm {
    pub id: i64,
    #[serde(rename = "returnUrl")]
    pub return_url: String,
}

pub async fn approve_service(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<ApproveServiceForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT slug, status FROM services WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(f.id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((slug, status)) = row else {
        return Err(AppError::BadRequest("not found".into()));
    };
    if status != "pending" {
        return Err(AppError::BadRequest(format!(
            "service is {}, not pending",
            status
        )));
    }
    let return_url = f.return_url.trim();
    if return_url.is_empty() || url::Url::parse(return_url).is_err() {
        return Err(AppError::BadRequest("return url must be a valid URL".into()));
    }
    sqlx::query(
        "UPDATE services
         SET status = 'approved', approved_at = unixepoch(), approved_by = ?, return_url = ?
         WHERE id = ?",
    )
    .bind(admin.id)
    .bind(return_url)
    .bind(f.id)
    .execute(&state.pool)
    .await?;
    audit(
        &state.pool,
        Some(admin.id),
        "service.approve",
        Some(&format!("service:{}", f.id)),
        Some(serde_json::json!({ "slug": slug, "returnUrl": return_url, "from": "setup" })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/setup").into_response())
}

pub async fn deny_service(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<IdForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT slug, status FROM services WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(f.id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((slug, status)) = row else {
        return Err(AppError::BadRequest("not found".into()));
    };
    if status != "pending" {
        return Err(AppError::BadRequest(format!(
            "service is {}, not pending",
            status
        )));
    }
    sqlx::query("UPDATE services SET status = 'denied' WHERE id = ?")
        .bind(f.id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(admin.id),
        "service.deny",
        Some(&format!("service:{}", f.id)),
        Some(serde_json::json!({ "slug": slug, "from": "setup" })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/setup").into_response())
}

pub async fn finish(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;
    let setup = get_setup_state(&state.pool).await.map_err(AppError::Other)?;
    if !setup.complete() {
        return Err(AppError::BadRequest("setup not complete yet".into()));
    }
    Ok(Redirect::to("/admin/users").into_response())
}
