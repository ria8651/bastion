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
use crate::models::{Service, UserCtx};
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
    if setup.complete() {
        return Ok(Redirect::to("/").into_response());
    }
    let step = setup.step();
    let services: Vec<Service> = if setup.has_provider() {
        sqlx::query_as(
            "SELECT id, slug, name, return_url, created_at FROM services
             WHERE deleted_at IS NULL ORDER BY id",
        )
        .fetch_all(&state.pool)
        .await?
    } else {
        vec![]
    };
    let origin = origin_from(&state, &headers);
    let host = host_from_origin(&origin).to_string();
    let user = user.map(|Extension(u)| u);

    let title = match step {
        1 => "Connect identity providers",
        2 => "Claim root admin",
        _ => "Register your services",
    };
    let subtitle = match step {
        1 => "Bastion needs at least one OAuth provider to authenticate users. Configure GitHub, Google, or both.",
        2 => "Sign in with the account that should be the first admin. They'll be able to invite others.",
        _ => "Each service has a slug, a name, and a return URL. Bastion will redirect authenticated users there with ?bastion_token=<JWT>.",
    };

    let body = html! {
        (page_chrome(Some("first-run setup"), &host, true))

        div.setup-main {
            div.setup-steps {
                (step_marker(1, "providers", step))
                span.sep {}
                (step_marker(2, "claim admin", step))
                span.sep {}
                (step_marker(3, "add service", step))
            }

            div.setup-title { (title) }
            div.setup-subtitle { (subtitle) }

            @match step {
                1 => (step1(&origin, setup.has_github, setup.has_google)),
                2 => (step2(user.as_ref())),
                _ => (step3(&services, setup.has_services)),
            }
        }
        (bottom_strip(None, true))
    };
    Ok(layout("Setup", body).into_response())
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

fn step3(services: &[Service], has_any: bool) -> Markup {
    html! {
        @if !services.is_empty() {
            div.setup-rows style="margin-top:32px" {
                @for s in services {
                    div.setup-row.configured {
                        span.ico style="width:18px;height:18px;display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--line);border-radius:6px;background:var(--bg-hover);color:var(--fg-mid);font-family:var(--font-mono);font-size:10px" {
                            (s.slug.chars().take(2).collect::<String>().to_lowercase())
                        }
                        div.body {
                            div.label { (s.slug) }
                            div.detail { (s.return_url) }
                        }
                        form method="post" action="/setup/remove-service" style="margin:0" {
                            input type="hidden" name="id" value=(s.id);
                            button.btn.danger type="submit" { "remove" }
                        }
                    }
                }
            }
        }

        div.setup-card {
            h2 { "Register a service" }
            p { "Add at least one app. You can register more later from the admin panel." }
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
                    (services.len()) " service" @if services.len() != 1 { "s" } " registered"
                } @else {
                    "no services yet · add at least one"
                }
            }
            div.actions {
                @if has_any {
                    form method="post" action="/setup/finish" style="margin:0" {
                        button.btn.primary type="submit" { "Finish setup →" }
                    }
                } @else {
                    button.btn.primary type="button" disabled { "Finish setup →" }
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
    let (slug, name, return_url) = validate_service(&f).map_err(AppError::BadRequest)?;
    let inserted: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO services (slug, name, return_url) VALUES (?, ?, ?)
         ON CONFLICT(slug) WHERE deleted_at IS NULL DO NOTHING RETURNING id",
    )
    .bind(&slug)
    .bind(&name)
    .bind(&return_url)
    .fetch_optional(&state.pool)
    .await?;
    if let (Some((svc_id,)), Some(Extension(u))) = (inserted, user) {
        sqlx::query(
            "INSERT INTO grants (user_id, service_id, granted_by) VALUES (?, ?, ?)
             ON CONFLICT(user_id, service_id) DO NOTHING",
        )
        .bind(u.id)
        .bind(svc_id)
        .bind(u.id)
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
    Form(f): Form<IdForm>,
) -> AppResult<Response> {
    sqlx::query("UPDATE services SET deleted_at = unixepoch() WHERE id = ? AND deleted_at IS NULL")
        .bind(f.id)
        .execute(&state.pool)
        .await?;
    Ok(Redirect::to("/setup").into_response())
}

pub async fn finish(State(state): State<AppState>) -> AppResult<Response> {
    let setup = get_setup_state(&state.pool).await.map_err(AppError::Other)?;
    if !setup.complete() {
        return Err(AppError::BadRequest("setup not complete yet".into()));
    }
    Ok(Redirect::to("/admin/users").into_response())
}
