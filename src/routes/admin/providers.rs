use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use maud::html;
use serde::Deserialize;

use super::ui::{field, header, section, status_badge, Nav};
use super::{admin, ctx, fmt_time};
use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::models::UserCtx;
use crate::setup::{clear_oauth_config, set_oauth_config};
use crate::state::{origin_from, AppState};
use crate::templates::{provider_display_name, provider_icon};

const PROVIDERS: [&str; 2] = ["github", "google"];

pub async fn providers_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;
    let origin = origin_from(&state, &headers);

    let rows: Vec<(String, String, bool, i64)> =
        sqlx::query_as("SELECT provider, client_id, enabled, updated_at FROM oauth_providers")
            .fetch_all(&state.pool)
            .await?;
    let callback = format!("{}/auth/callback", origin);
    let enabled_n = rows.iter().filter(|r| r.2).count();

    let body = html! {
        (header(None, "Identity providers", Some(html! { (enabled_n) " of " (PROVIDERS.len()) " enabled" }), None))
        p.sec-desc {
            "The OAuth apps people sign in through. Changes apply from the next sign-in. "
            "Register each app with the homepage and callback below."
        }
        @for slug in PROVIDERS {
            @let display = provider_display_name(slug);
            @let configured = rows.iter().find(|(p, ..)| p == slug);
            @let (list_url, create_url) = console_urls(slug);
            (section(display, None, Some(match configured {
                Some((_, _, true, _)) => status_badge("enabled"),
                Some(_) => status_badge("disabled"),
                None => status_badge("not configured"),
            }), html! {
                div.panel {
                    div.inline-actions {
                        span.ico.md { (provider_icon(slug)) }
                        div.grow {
                            a.ext href=(list_url) target="_blank" rel="noopener" { "Your " (display) " OAuth apps ↗" }
                            " · "
                            a.ext href=(create_url) target="_blank" rel="noopener" { "create one ↗" }
                        }
                    }
                    dl.kv {
                        dt { "Homepage URL" } dd { (origin) }
                        dt { "Callback URL" } dd { (callback) }
                        @if let Some((_, _, _, updated)) = configured {
                            dt { "Last changed" } dd { (fmt_time(*updated)) }
                        }
                    }
                    form.form method="post" action=(format!("/admin/providers/save/{}", slug)) {
                        (field("Client ID", None, html! {
                            input.input.mono name="clientId" required autocomplete="off" spellcheck="false"
                                value=(configured.map(|(_, c, ..)| c.as_str()).unwrap_or(""));
                        }))
                        (field("Client secret",
                            configured.is_some().then_some("Stored secrets aren't shown. Enter it again to change anything here."),
                            html! {
                            input.input.mono name="clientSecret" type="password" required autocomplete="new-password";
                        }))
                        div.form-actions {
                            button.btn.primary type="submit" { "Save" }
                            @if configured.is_some() {
                                button.btn.bad type="submit"
                                    formaction=(format!("/admin/providers/clear/{}", slug))
                                    formnovalidate
                                    onclick=(format!(
                                        "return confirm('Remove the {0} credentials? Nobody can sign in with {0} until they are set again.')",
                                        display
                                    ))
                                    { "Remove" }
                            }
                        }
                    }
                }
            }))
        }
    };
    Ok(ctx.page(Nav::Providers, "Identity providers", body).into_response())
}

/// (browse-existing URL, create-new URL) for each provider's OAuth admin console.
fn console_urls(slug: &str) -> (&'static str, &'static str) {
    match slug {
        "github" => (
            "https://github.com/settings/developers",
            "https://github.com/settings/applications/new",
        ),
        "google" => (
            "https://console.cloud.google.com/apis/credentials",
            "https://console.cloud.google.com/apis/credentials/oauthclient",
        ),
        _ => ("", ""),
    }
}

#[derive(Debug, Deserialize)]
pub struct ProviderSaveForm {
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: String,
}

pub async fn providers_save(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<ProviderSaveForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    if !PROVIDERS.contains(&provider.as_str()) {
        return Err(AppError::BadRequest("unknown provider".into()));
    }
    let cid = f.client_id.trim();
    let cs = f.client_secret.trim();
    if cid.is_empty() || cs.is_empty() {
        return Err(AppError::BadRequest("Both client id and secret are required".into()));
    }
    set_oauth_config(&state.pool, &provider, cid, cs)
        .await
        .map_err(AppError::Other)?;
    audit(
        &state.pool,
        Some(admin.id),
        &format!("setup.{}_configured", provider),
        Some(&format!("provider:{}", provider)),
        None,
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/admin/providers").into_response())
}

pub async fn providers_clear(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    if !PROVIDERS.contains(&provider.as_str()) {
        return Err(AppError::BadRequest("unknown provider".into()));
    }

    // Don't let admins wipe out the very last provider.
    let (other_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_providers WHERE enabled = 1 AND provider != ?",
    )
    .bind(&provider)
    .fetch_one(&state.pool)
    .await?;
    if other_count == 0 {
        return Err(AppError::BadRequest(
            "can't clear the last enabled provider — nobody could sign in".into(),
        ));
    }

    clear_oauth_config(&state.pool, &provider)
        .await
        .map_err(AppError::Other)?;
    audit(
        &state.pool,
        Some(admin.id),
        &format!("setup.{}_cleared", provider),
        Some(&format!("provider:{}", provider)),
        None,
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/admin/providers").into_response())
}
