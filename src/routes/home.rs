use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
    Extension,
};
use maud::html;
use serde::Deserialize;

use crate::error::AppResult;
use crate::models::UserCtx;
use crate::oauth::Provider;
use crate::state::AppState;
use crate::templates::{
    avatar, bottom_strip, corner_mark, landing_page, layout, provider_icon,
};

pub async fn index(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let Some(Extension(user)) = user else {
        let providers = configured_providers(&state).await?;
        return Ok(landing_unauthed(&providers).into_response());
    };

    match user.status.as_str() {
        "pending" => Ok(pending_for(Some(&user), None).into_response()),
        "denied" => Ok(denied_for().into_response()),
        _ => Ok(dashboard(&state, &user).await?.into_response()),
    }
}

#[derive(Debug, Deserialize)]
pub struct PendingQuery {
    pub service: Option<String>,
}

async fn configured_providers(state: &AppState) -> AppResult<Vec<Provider>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT provider FROM oauth_providers WHERE enabled = 1 ORDER BY provider")
            .fetch_all(&state.pool)
            .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(p,)| Provider::parse(&p))
        .collect())
}

fn landing_unauthed(providers: &[Provider]) -> maud::Markup {
    let card = html! {
        div.landing-headline { "Sign in to continue" }
        div.landing-subline { "bastion handles auth for your apps" }
        div.provider-stack {
            @if providers.is_empty() {
                div style="font-family:var(--font-mono);font-size:12px;color:var(--fg-mute);text-align:center;padding:12px" {
                    "no identity providers configured"
                }
            } @else {
                @for p in providers {
                    form method="post" action="/auth/login" hx-boost="false" style="margin:0" {
                        input type="hidden" name="provider" value=(p.as_str());
                        button.provider-btn type="submit" {
                            (provider_icon(p.as_str()))
                            span { "Continue with " (p.display_name()) }
                        }
                    }
                }
            }
        }
        div.landing-footnote {
            "bastion will share your id, email,"
            br;
            " and granted permissions with each app."
        }
    };
    landing_page("bastion", card)
}

async fn dashboard(state: &AppState, user: &UserCtx) -> AppResult<maud::Markup> {
    let services: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT s.slug, s.name, s.return_url
         FROM services s
         JOIN grants g ON g.service_id = s.id
         WHERE g.user_id = ? AND s.deleted_at IS NULL
         ORDER BY s.slug",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;

    let linked_providers: Vec<(String,)> = sqlx::query_as(
        "SELECT provider FROM user_identities WHERE user_id = ? ORDER BY linked_at",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;
    let providers_text = linked_providers
        .iter()
        .map(|(p,)| p.clone())
        .collect::<Vec<_>>()
        .join(" + ");

    let n = services.len();
    let foot_extra = format!("{} services granted", n);
    let body = html! {
        div.page-chrome {
            (corner_mark(None))
            div.dash-top-right {
                @if user.is_admin {
                    a.admin-pill href="/admin/users" { "admin panel" }
                }
                a.admin-pill href="/account" { "account" }
                div.user-chip {
                    (avatar(user, "sm"))
                    span.name { (user.username) }
                }
                form method="post" action="/auth/logout" hx-boost="false" style="margin:0" {
                    button.signout.mono type="submit" { "sign out" }
                }
            }
        }

        div.dash-main {
            div.dash-header {
                div {
                    div.dash-title { "Your apps" }
                    div.dash-meta {
                        (n) " services · signed in via "
                        @if providers_text.is_empty() { "—" } @else { (providers_text) }
                    }
                }
                div.dash-sort { }
            }

            @if services.is_empty() {
                div.empty-card {
                    div.title { "You don't have access to any services yet." }
                    div.sub { "An admin needs to grant you access. Try logging in via an app you have in mind, or wait for an invite." }
                }
            } @else {
                div.dash-grid {
                    @for (slug, name, _ret) in &services {
                        a.dash-tile href=(format!("/launch/{}", slug)) hx-boost="false" {
                            div.dash-tile-icon { (tile_initials(slug)) }
                            div style="flex:1" {
                                div.slug { (slug) }
                                @if !name.is_empty() && name != slug {
                                    div.desc { (name) }
                                }
                            }
                            div.dash-tile-foot {
                                span { }
                            }
                        }
                    }
                }
            }
        }
        (bottom_strip(Some(&foot_extra), false))
    };
    Ok(layout("Your apps", body))
}

fn tile_initials(slug: &str) -> String {
    slug.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(2)
        .collect::<String>()
        .to_lowercase()
}

pub async fn pending(
    user: Option<Extension<UserCtx>>,
    Query(q): Query<PendingQuery>,
) -> impl IntoResponse {
    let user = user.map(|Extension(u)| u);
    pending_for(user.as_ref(), q.service.as_deref())
}

fn pending_for(user: Option<&UserCtx>, service: Option<&str>) -> maud::Markup {
    let retry_url = service.map(|s| format!("/launch/{}", s));
    let card = html! {
        div.landing-headline { "Waiting for approval" }
        div.landing-subline {
            @match user {
                Some(u) => { "signed in as " (u.username) }
                None => { "not signed in" }
            }
        }
        div.landing-footnote {
            @match user {
                Some(_) => {
                    @if let Some(slug) = service {
                        "Access to " span.mono { (slug) } " is pending an admin's review."
                        br;
                        " Click " strong { "Try again" } " once you've been granted."
                    } @else {
                        "Your account is pending an admin's review."
                        br;
                        " You'll be able to access your apps once it's approved."
                    }
                }
                None => {
                    "Not signed in. "
                    a href="/auth/login" style="color:var(--fg)" { "Sign in" } "."
                }
            }
        }
        @if user.is_some() || retry_url.is_some() {
            div.provider-stack {
                @if let Some(url) = &retry_url {
                    a.btn.primary href=(url) hx-boost="false" style="width:100%;justify-content:center" {
                        "Try again"
                    }
                }
                @if user.is_some() {
                    form method="post" action="/auth/logout" hx-boost="false" style="margin:0" {
                        button.btn type="submit" style="width:100%;justify-content:center" { "Log out" }
                    }
                }
            }
        }
    };
    landing_page("pending", card)
}

pub async fn denied() -> impl IntoResponse {
    denied_for()
}

fn denied_for() -> maud::Markup {
    let card = html! {
        div.landing-headline { "Access denied" }
        div.landing-subline { "bastion has rejected this account" }
        div.landing-footnote {
            "Contact an admin if you think this is wrong."
        }
    };
    landing_page("denied", card)
}
