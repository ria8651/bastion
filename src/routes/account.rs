use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use maud::{html, Markup};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::models::UserCtx;
use crate::oauth::{
    build_authorize_url, generate_state, set_state_cookie, OAuthState, Provider,
};
use crate::setup::get_oauth_config;
use crate::state::{is_secure, origin_from, AppState};
use crate::templates::{
    avatar, bottom_strip, corner_mark, layout, pill, provider_display_name, provider_icon,
};

#[derive(Debug, Deserialize)]
pub struct AccountQuery {
    pub linked: Option<String>,
    pub already: Option<String>,
    pub unlinked: Option<String>,
}

pub async fn page(
    State(state): State<AppState>,
    Query(q): Query<AccountQuery>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let Some(Extension(user)) = user else {
        return Err(AppError::Unauthorized);
    };

    let identities: Vec<(i64, String, String, Option<String>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT id, provider, provider_id, email, linked_at, last_login_at
         FROM user_identities WHERE user_id = ? ORDER BY linked_at",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;

    let configured: Vec<(String,)> =
        sqlx::query_as("SELECT provider FROM oauth_providers WHERE enabled = 1 ORDER BY provider")
            .fetch_all(&state.pool)
            .await?;
    let linked_providers: std::collections::HashSet<String> =
        identities.iter().map(|i| i.1.clone()).collect();
    let linkable: Vec<String> = configured
        .into_iter()
        .map(|(p,)| p)
        .filter(|p| !linked_providers.contains(p) && Provider::parse(p).is_some())
        .collect();

    let body = html! {
        div.page-chrome.narrow {
            (corner_mark(Some("account")))
            div.dash-top-right {
                div.user-chip {
                    (avatar(&user, "sm"))
                    span.name { (user.username) }
                }
                form method="post" action="/auth/logout" hx-boost="false" style="margin:0" {
                    button.signout.mono type="submit" { "sign out" }
                }
            }
        }

        div.setup-main {
            div.setup-title { "Account" }
            div.setup-subtitle {
                "Manage which identity providers can sign you into "
                span.mono { (user.username) } "."
            }

            @if q.linked.is_some() {
                div.empty-card style="border-color:var(--fg-mid)" {
                    div.title { "Linked successfully." }
                    div.sub { "This account can now also sign in with the new provider." }
                }
            }
            @if q.already.is_some() {
                div.empty-card {
                    div.title { "Already linked." }
                    div.sub { "That identity is already attached to this bastion account." }
                }
            }
            @if q.unlinked.is_some() {
                div.empty-card {
                    div.title { "Unlinked." }
                    div.sub { "That identity can no longer sign into this account." }
                }
            }

            h2 style="font-size:14px;margin-top:24px;margin-bottom:12px;font-family:var(--font-mono);color:var(--fg-mute);text-transform:uppercase;letter-spacing:0.06em" { "Linked identities" }
            div.setup-rows {
                @for (iid, prov, pid, email, _linked_at, _last) in &identities {
                    div.setup-row.configured {
                        span.ico style="width:18px;height:18px" { (provider_icon(prov)) }
                        div.body {
                            div.label { (provider_display_name(prov)) }
                            div.detail.mono {
                                (pid)
                                @if let Some(e) = email { " · " (e) }
                            }
                        }
                        @let is_anchor = user.sub_anchor_provider == *prov && user.sub_anchor_provider_id == *pid;
                        @if is_anchor {
                            (pill("admin", "sub anchor"))
                        }
                        @if is_anchor {
                            span.mono style="font-size:11px;color:var(--fg-dim)" { "anchor — can't unlink" }
                        } @else if identities.len() > 1 {
                            form method="post" action="/account/unlink" style="margin:0" {
                                input type="hidden" name="identity_id" value=(iid);
                                button.btn.danger type="submit" { "Unlink" }
                            }
                        } @else {
                            span.mono style="font-size:11px;color:var(--fg-dim)" { "last identity" }
                        }
                    }
                }
            }

            @if !linkable.is_empty() {
                h2 style="font-size:14px;margin-top:32px;margin-bottom:12px;font-family:var(--font-mono);color:var(--fg-mute);text-transform:uppercase;letter-spacing:0.06em" { "Link another provider" }
                div.provider-stack {
                    @for prov in &linkable {
                        form method="post" action="/account/link" hx-boost="false" style="margin:0" {
                            input type="hidden" name="provider" value=(prov);
                            button.provider-btn type="submit" {
                                (provider_icon(prov))
                                span { "Link " (provider_display_name(prov)) }
                            }
                        }
                    }
                }
            }

            (anchor_note(&user))
        }
        (bottom_strip(None, true))
    };

    let _ = state;
    Ok(layout("Account", body).into_response())
}

fn anchor_note(user: &UserCtx) -> Markup {
    html! {
        div style="margin-top:32px;font-size:12px;color:var(--fg-mute);font-family:var(--font-mono);line-height:1.6" {
            "stable sub anchor: " (user.sub_anchor_provider) " / " (user.sub_anchor_provider_id)
            br;
            "your downstream identity is derived from this anchor — linking or unlinking other providers does not change it."
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LinkForm {
    pub provider: String,
}

pub async fn link_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<LinkForm>,
) -> AppResult<Response> {
    let Some(Extension(user)) = user else {
        return Err(AppError::Unauthorized);
    };
    if user.status == "denied" {
        return Err(AppError::Forbidden);
    }
    let provider = Provider::parse(&f.provider)
        .ok_or_else(|| AppError::BadRequest("unknown provider".into()))?;
    let cfg = get_oauth_config(&state.pool, provider.as_str())
        .await?
        .ok_or_else(|| {
            AppError::BadRequest(format!("{} OAuth not configured", provider.display_name()))
        })?;

    // Refuse if already linked to this user.
    let already: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM user_identities WHERE user_id = ? AND provider = ?",
    )
    .bind(user.id)
    .bind(provider.as_str())
    .fetch_optional(&state.pool)
    .await?;
    if already.is_some() {
        return Ok(Redirect::to("/account?already=1").into_response());
    }

    let origin = origin_from(&state, &headers);
    let redirect_uri = format!("{}/auth/callback", origin);
    let s = generate_state();
    set_state_cookie(
        &cookies,
        &OAuthState {
            state: s.clone(),
            provider,
            service: None,
            claim_admin: None,
            link_to_user_id: Some(user.id),
            redirect: None,
        },
        is_secure(&state, &headers),
    );
    let url = build_authorize_url(provider, &cfg.client_id, &redirect_uri, &s);
    Ok(Redirect::to(&url).into_response())
}

#[derive(Debug, Deserialize)]
pub struct UnlinkForm {
    pub identity_id: i64,
}

pub async fn unlink_post(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<UnlinkForm>,
) -> AppResult<Response> {
    let Some(Extension(user)) = user else {
        return Err(AppError::Unauthorized);
    };

    let row: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT user_id, provider, provider_id FROM user_identities WHERE id = ?",
    )
    .bind(f.identity_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((uid, provider, provider_id)) = row else {
        return Err(AppError::NotFound);
    };
    if uid != user.id {
        return Err(AppError::Forbidden);
    }

    // The sub-anchor row defines the downstream JWT `sub`. Deleting it frees
    // the (provider, provider_id) pair so a future signup using that same
    // external account would land on an identical `sub` — i.e., would be
    // treated as this user by downstream services. Refuse.
    if provider == user.sub_anchor_provider && provider_id == user.sub_anchor_provider_id {
        return Err(AppError::BadRequest(
            "can't unlink the sub-anchor identity — your downstream id depends on it".into(),
        ));
    }

    let (remaining,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM user_identities WHERE user_id = ?")
            .bind(user.id)
            .fetch_one(&state.pool)
            .await?;
    if remaining <= 1 {
        return Err(AppError::BadRequest(
            "can't unlink the last identity — you'd be locked out".into(),
        ));
    }

    sqlx::query("DELETE FROM user_identities WHERE id = ?")
        .bind(f.identity_id)
        .execute(&state.pool)
        .await?;

    audit(
        &state.pool,
        Some(user.id),
        "user.identity_unlinked",
        Some(&format!("user:{}", user.id)),
        Some(serde_json::json!({
            "provider": provider,
            "provider_id": provider_id,
        })),
    )
    .await
    .map_err(AppError::Other)?;

    Ok(Redirect::to("/account?unlinked=1").into_response())
}
