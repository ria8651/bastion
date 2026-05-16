use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use maud::{html, Markup};
use serde::Deserialize;

use crate::error::{AppError, AppResult};
use crate::models::{Service, UserCtx};
use crate::setup::{
    clear_github_oauth_config, get_setup_state, set_github_oauth_config,
};
use crate::state::{origin_from, AppState};
use crate::templates::{
    bottom_strip, github_svg, host_from_origin, layout, page_chrome, pill,
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
    let services: Vec<Service> = if setup.has_github {
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
        1 => "Bastion needs an OAuth provider to authenticate users. GitHub is required; more providers can be added later.",
        2 => "Sign in with the GitHub account that should be the first admin. They'll be able to invite others.",
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
                1 => (step1(&origin, setup.has_github)),
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

fn step1(origin: &str, configured: bool) -> Markup {
    let cb = format!("{}/auth/callback", origin);
    html! {
        div.setup-rows {
            div class=(if configured { "setup-row configured" } else { "setup-row" }) {
                span.ico style="width:18px;height:18px" { (github_svg()) }
                div.body {
                    div.label { "GitHub" }
                    div.detail {
                        @if configured { "configured" } @else { "required · oauth 2.0" }
                    }
                }
                @if configured {
                    (pill("active", "connected"))
                } @else {
                    span.mono style="font-size:11px;color:var(--fg-dim)" { "use form below" }
                }
            }
        }

        @if !configured {
            div.setup-card {
                h2 { "Configure GitHub OAuth" }
                p {
                    "Create a new OAuth App at "
                    a target="_blank" href="https://github.com/settings/developers" style="color:var(--fg);text-decoration:underline" {
                        "github.com/settings/developers"
                    }
                    " with these values:"
                }
                ul {
                    li { "Homepage URL: " code { (origin) } }
                    li { "Authorization callback URL: " code { (cb) } }
                }
                form method="post" action="/setup/save-github" style="margin-top:14px" {
                    label.field { "Client ID"
                        input.input name="clientId" required;
                    }
                    label.field { "Client Secret"
                        input.input name="clientSecret" type="password" required;
                    }
                    div style="margin-top:18px" {
                        button.btn.primary type="submit" { "Save and continue →" }
                    }
                }
            }
        } @else {
            div.setup-foot {
                span.progress { "1 of 1 connected · github required" }
                div.actions {
                    form method="post" action="/setup/reset-github" style="margin:0" {
                        button.btn.text type="submit" { "← back" }
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
                "Sign in with the GitHub account you want as the first admin."
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

            div style="margin-top:18px;display:flex;gap:8px;align-items:center" {
                a.btn.primary href="/auth/login?claim_admin=1" { "Sign in & claim admin →" }
                form method="post" action="/setup/reset-github" style="margin:0" {
                    button.btn.text type="submit" { "← back (re-enter GitHub creds)" }
                }
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
pub struct SaveGithubForm {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: String,
}

pub async fn save_github(
    State(state): State<AppState>,
    Form(f): Form<SaveGithubForm>,
) -> AppResult<Response> {
    let setup = get_setup_state(&state.pool).await.map_err(AppError::Other)?;
    if setup.has_github && setup.has_admin {
        return Err(AppError::BadRequest("setup already past this step".into()));
    }
    let cid = f.client_id.trim();
    let cs = f.client_secret.trim();
    if cid.is_empty() || cs.is_empty() {
        return Err(AppError::BadRequest(
            "Both client id and secret are required".into(),
        ));
    }
    set_github_oauth_config(&state.pool, cid, cs)
        .await
        .map_err(AppError::Other)?;
    Ok(Redirect::to("/setup").into_response())
}

pub async fn reset_github(State(state): State<AppState>) -> AppResult<Response> {
    let setup = get_setup_state(&state.pool).await.map_err(AppError::Other)?;
    if setup.has_admin {
        return Err(AppError::BadRequest(
            "can't reset creds after an admin has been claimed".into(),
        ));
    }
    clear_github_oauth_config(&state.pool)
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
    if !slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
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
