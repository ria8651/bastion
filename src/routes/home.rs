use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Extension,
};
use maud::html;

use crate::error::AppResult;
use crate::models::UserCtx;
use crate::state::AppState;
use crate::templates::{
    avatar, bottom_strip, corner_mark, github_svg, landing_page, layout,
};

pub async fn index(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let Some(Extension(user)) = user else {
        return Ok(landing_unauthed().into_response());
    };

    match user.status.as_str() {
        "pending" => Ok(pending_for(Some(&user)).into_response()),
        "denied" => Ok(denied_for().into_response()),
        _ => Ok(dashboard(&state, &user).await?.into_response()),
    }
}

fn landing_unauthed() -> maud::Markup {
    let card = html! {
        div.landing-headline { "Sign in to continue" }
        div.landing-subline { "bastion handles auth for your apps" }
        div.provider-stack {
            form method="post" action="/auth/login" hx-boost="false" style="margin:0" {
                button.gh-btn type="submit" {
                    (github_svg())
                    span { "Continue with GitHub" }
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

    let n = services.len();
    let foot_extra = format!("{} services granted", n);
    let body = html! {
        div.page-chrome {
            (corner_mark(None))
            div.dash-top-right {
                @if user.is_admin {
                    a.admin-pill href="/admin/users" { "admin panel" }
                }
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
                    div.dash-meta { (n) " services · signed in via github" }
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

pub async fn pending(user: Option<Extension<UserCtx>>) -> impl IntoResponse {
    let user = user.map(|Extension(u)| u);
    pending_for(user.as_ref())
}

fn pending_for(user: Option<&UserCtx>) -> maud::Markup {
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
                    "Your account is pending an admin's review."
                    br;
                    " You'll be able to access your apps once it's approved."
                }
                None => {
                    "Not signed in. "
                    a href="/auth/login" style="color:var(--fg)" { "Sign in" } "."
                }
            }
        }
        @if user.is_some() {
            div.provider-stack {
                form method="post" action="/auth/logout" hx-boost="false" style="margin:0" {
                    button.btn type="submit" style="width:100%;justify-content:center" { "Log out" }
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
