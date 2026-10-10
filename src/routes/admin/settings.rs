//! Instance-wide settings: things that belong to no single service.

use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use maud::html;
use serde::Deserialize;

use super::ui::{badge, field, header, section, Nav, Tone};
use super::{admin, ctx, ProxyHealth};
use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::models::UserCtx;
use crate::state::{origin_from, AppState};
use crate::templates::VERSION_TAG;

pub async fn settings_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;
    let origin = origin_from(&state, &headers);
    let health = ProxyHealth::load(&state).await?;

    let body = html! {
        (header(None, "Settings", None, None))

        (section("Instance", None, None, html! {
            div.panel {
                dl.kv {
                    dt { "Public origin" }
                    dd {
                        (origin) " "
                        @if health.origin_pinned {
                            (badge(Tone::Quiet, "ORIGIN"))
                        } @else {
                            (badge(Tone::Warn, "guessed from request"))
                        }
                    }
                    dt { "JWKS" } dd { (origin) "/.well-known/jwks.json" }
                    dt { "Introspection" } dd { (origin) "/api/introspect" }
                    dt { "Service registration" } dd { (origin) "/api/services/register" }
                    dt { "Version" } dd { (VERSION_TAG) }
                }
            }
        }))

        (section("Session cookie domain", None, None, html! {
            p.sec-desc {
                "Proxy mode serves apps on their own hostnames, so the session cookie has to be "
                "scoped to a parent domain that covers both bastion and those apps — otherwise "
                "it's never sent to them and every request looks signed out. Leave it empty "
                "when nothing is proxied."
            }
            div.notices { (health.notices()) }
            div.panel {
                form.form method="post" action="/admin/settings/cookie-domain" {
                    (field("Domain",
                        Some("Shared with every subdomain, so only use a domain you control end to end."),
                        html! {
                            input.input.mono name="cookieDomain"
                                value=(health.cookie_domain.as_deref().unwrap_or(""))
                                placeholder=".example.com" autocapitalize="off" spellcheck="false";
                        }))
                    div.form-actions { button.btn.primary type="submit" { "Save" } }
                }
            }
        }))
    };
    Ok(ctx.page(Nav::Settings, "Settings", body).into_response())
}

/// Host from `ORIGIN`, or `None` when it isn't pinned.
fn bastion_host(state: &AppState) -> Option<String> {
    crate::host::of_url(state.origin.as_ref()?)
}

#[derive(Debug, Deserialize)]
pub struct CookieDomainForm {
    #[serde(rename = "cookieDomain", default)]
    pub cookie_domain: String,
}

pub async fn cookie_domain_save(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<CookieDomainForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    let domain =
        crate::settings::normalize_cookie_domain(&f.cookie_domain, bastion_host(&state).as_deref())
            .map_err(AppError::BadRequest)?;
    crate::settings::set(&state.pool, crate::settings::COOKIE_DOMAIN, &domain)
        .await
        .map_err(AppError::Other)?;
    audit(
        &state.pool,
        Some(admin.id),
        "settings.cookie_domain",
        None,
        Some(serde_json::json!({ "value": domain })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/admin/settings").into_response())
}
