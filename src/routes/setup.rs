use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use maud::html;
use serde::Deserialize;

use crate::error::{AppError, AppResult};
use crate::models::{Service, UserCtx};
use crate::setup::{
    clear_github_oauth_config, get_setup_state, set_github_oauth_config,
};
use crate::state::{origin_from, AppState};
use crate::templates::layout;

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
        sqlx::query_as("SELECT id, slug, name, return_url, created_at FROM services ORDER BY id")
            .fetch_all(&state.pool)
            .await?
    } else {
        vec![]
    };
    let origin = origin_from(&state, &headers);
    let user = user.map(|Extension(u)| u);

    let body = html! {
        h1 { "First-run setup" }
        div.progress {
            div class=(progress_class(1, step)) { "1. GitHub OAuth" }
            div class=(progress_class(2, step)) { "2. Claim admin" }
            div class=(progress_class(3, step)) { "3. Services" }
        }
        @match step {
            1 => (step1(&origin)),
            2 => (step2(user.as_ref(), &origin)),
            3 => (step3(&services, setup.has_services)),
            _ => "",
        }
    };
    Ok(layout("Setup", user.as_ref(), body).into_response())
}

fn progress_class(want: u8, current: u8) -> &'static str {
    if want < current {
        "step done"
    } else if want == current {
        "step active"
    } else {
        "step"
    }
}

fn step1(origin: &str) -> maud::Markup {
    let cb = format!("{}/auth/callback", origin);
    let hp = origin;
    html! {
        div.card {
            h2 { "Configure GitHub OAuth" }
            p.muted { "Create a new OAuth App at " a target="_blank" href="https://github.com/settings/developers" { "github.com/settings/developers" } " with these values:" }
            ul {
                li { "Homepage URL: " code { (hp) } }
                li { "Authorization callback URL: " code { (cb) } }
            }
            form method="post" action="/setup/save-github" {
                label for="clientId" { "Client ID" }
                input #clientId name="clientId" required;
                label for="clientSecret" { "Client Secret" }
                input #clientSecret name="clientSecret" type="password" required;
                p style="margin-top:1rem" {
                    button.btn.primary type="submit" { "Save" }
                }
            }
        }
    }
}

fn step2(user: Option<&UserCtx>, _origin: &str) -> maud::Markup {
    html! {
        div.card {
            h2 { "Claim root admin" }
            p { "Sign in with the GitHub account that should be the first admin. " }
            @if let Some(u) = user {
                p.muted { "Currently signed in as " strong { (u.username) } ". If that's right and you're still seeing this, your account hasn't been promoted yet — sign in again with the claim_admin flag below." }
            }
            p {
                a.btn.primary href="/auth/login?claim_admin=1" { "Sign in & claim admin" }
            }
            form method="post" action="/setup/reset-github" style="margin-top:1rem" {
                button.btn type="submit" { "← Back (re-enter GitHub creds)" }
            }
        }
    }
}

fn step3(services: &[Service], has_any: bool) -> maud::Markup {
    html! {
        div.card {
            h2 { "Register services" }
            p.muted { "Each service has a slug, a name, and a return URL. Bastion redirects authenticated users to the return URL with " code { "?bastion_token=<JWT>" } "." }
            @if !services.is_empty() {
                table.admin-table {
                    thead { tr { th{"Slug"} th{"Name"} th{"Return URL"} th{} } }
                    tbody {
                        @for s in services {
                            tr {
                                td { (s.slug) }
                                td { (s.name) }
                                td.muted { (s.return_url) }
                                td {
                                    form method="post" action="/setup/remove-service" style="display:inline" {
                                        input type="hidden" name="id" value=(s.id);
                                        button.btn.danger type="submit" { "Remove" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            form method="post" action="/setup/add-service" style="margin-top:1rem" {
                label for="slug" { "Slug (lowercase, dashes ok)" }
                input #slug name="slug" required pattern="[a-z0-9-]+";
                label for="name" { "Display name" }
                input #name name="name";
                label for="returnUrl" { "Return URL" }
                input #returnUrl name="returnUrl" type="url" required;
                p style="margin-top:1rem" {
                    button.btn.primary type="submit" { "Add service" }
                }
            }
            @if has_any {
                form method="post" action="/setup/finish" style="margin-top:1.5rem" {
                    button.btn.primary type="submit" { "Finish setup" }
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
         ON CONFLICT(slug) DO NOTHING RETURNING id",
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
    sqlx::query("DELETE FROM services WHERE id = ?")
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
    Ok(Redirect::to("/admin").into_response())
}
