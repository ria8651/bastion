//! HTTP side of device sign-in (`crate::device`): the two OAuth endpoints a
//! device calls, and `/device`, where a person confirms it on their phone.

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Extension, Form, Json,
};
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::audit::audit;
use crate::device::{self, display_user_code, normalize_user_code, OAuthError, Tokens};
use crate::error::{AppError, AppResult};
use crate::models::UserCtx;
use crate::oauth::Provider;
use crate::state::{origin_from, AppState};
use crate::templates::{landing_page, provider_icon};

// -------------------- Device-facing API --------------------

/// OAuth endpoints are form-encoded (RFC 6749 §4.1.3), so stock clients work.
#[derive(Debug, Deserialize)]
pub struct CodeForm {
    pub client_id: String,
    /// Shown on the confirm page and in device lists: "Living Room Apple TV".
    pub name: Option<String>,
}

pub async fn code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CodeForm>,
) -> Response {
    let started = match device::start(&state.pool, &f.client_id, f.name.as_deref()).await {
        Ok(s) => s,
        Err(e) => return oauth_error(e),
    };
    let origin = origin_from(&state, &headers);
    no_store(Json(json!({
        "device_code": started.device_code,
        "user_code": display_user_code(&started.user_code),
        "verification_uri": format!("{}/device", origin),
        "verification_uri_complete":
            format!("{}{}", origin, device::confirm_path(&started.user_code)),
        "expires_in": device::CODE_TTL_SECONDS,
        "interval": device::POLL_INTERVAL_SECONDS,
    })))
}

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub client_id: String,
    pub device_code: Option<String>,
    pub refresh_token: Option<String>,
}

pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TokenForm>,
) -> Response {
    let issuer = origin_from(&state, &headers);
    let result = match (f.grant_type.as_str(), f.device_code, f.refresh_token) {
        (device::GRANT_DEVICE_CODE, Some(code), _) => {
            device::poll(&state.pool, &issuer, &f.client_id, &code).await
        }
        (device::GRANT_REFRESH, _, Some(token)) => {
            device::refresh(&state.pool, &issuer, &f.client_id, &token).await
        }
        (device::GRANT_DEVICE_CODE | device::GRANT_REFRESH, _, _) => {
            return oauth_error(OAuthError {
                code: "invalid_request",
                description: "missing device_code or refresh_token".into(),
            })
        }
        _ => {
            return oauth_error(OAuthError {
                code: "unsupported_grant_type",
                description: "use device_code or refresh_token".into(),
            })
        }
    };
    match result {
        Ok(Tokens {
            access_token,
            expires_in,
            refresh_token,
        }) => {
            let mut body = json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
            });
            if let Some(r) = refresh_token {
                body["refresh_token"] = r.into();
            }
            no_store(Json(body))
        }
        Err(e) => oauth_error(e),
    }
}

fn oauth_error(e: OAuthError) -> Response {
    let status = match e.code {
        "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
        "invalid_client" => StatusCode::UNAUTHORIZED,
        _ => StatusCode::BAD_REQUEST,
    };
    let body = json!({ "error": e.code, "error_description": e.description });
    let mut res = no_store(Json(body));
    *res.status_mut() = status;
    res
}

/// Token responses must not be cached (RFC 6749 §5.1).
fn no_store(body: impl IntoResponse) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], body).into_response()
}

// -------------------- /device --------------------

#[derive(Debug, Deserialize)]
pub struct DeviceQuery {
    pub code: Option<String>,
}

pub async fn page(
    state: State<AppState>,
    query: Query<DeviceQuery>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    show(state, query, user).await.map(no_framing)
}

async fn show(
    State(state): State<AppState>,
    Query(q): Query<DeviceQuery>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let typed = q.code.as_deref().map(str::trim).filter(|c| !c.is_empty());
    let code = typed.and_then(normalize_user_code);

    // Signed out: sign in first, carrying the code through. Nothing about the
    // code is looked up yet — that would be an unthrottled oracle for codes.
    let Some(Extension(user)) = user else {
        return Ok(sign_in(&state, code.as_deref()).await?.into_response());
    };
    if let Some(r) = not_active(&user) {
        return Ok(r);
    }
    if device::too_many_misses(user.id) {
        return Ok(enter_code(Some(TOO_MANY), None).into_response());
    }
    let Some(code) = code else {
        let error =
            typed.map(|_| "That isn't a code bastion gives out. Check it against your screen.");
        return Ok(enter_code(error, typed).into_response());
    };
    let Some(p) = device::pending(&state.pool, &code).await? else {
        let error = if device::record_miss(user.id) {
            TOO_MANY
        } else {
            NO_MATCH
        };
        return Ok(enter_code(Some(error), typed).into_response());
    };

    if !crate::grants::is_granted(&state.pool, user.id, p.service_id).await? {
        let note = format!("Requested via device sign-in to {}", p.slug);
        crate::grants::request_access(&state.pool, user.id, p.service_id, &note).await?;
        return Ok(no_access(&p).into_response());
    }
    Ok(confirm(&p, &user).into_response())
}

#[derive(Debug, Deserialize)]
pub struct DecideForm {
    pub code: String,
}

pub async fn approve(
    state: State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
    form: Form<DecideForm>,
) -> AppResult<Response> {
    decide(state, headers, user, form, true)
        .await
        .map(no_framing)
}

pub async fn deny(
    state: State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
    form: Form<DecideForm>,
) -> AppResult<Response> {
    decide(state, headers, user, form, false)
        .await
        .map(no_framing)
}

async fn decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<DecideForm>,
    approve: bool,
) -> AppResult<Response> {
    if !same_origin(&state, &headers) {
        return Err(AppError::Forbidden);
    }
    let Some(Extension(user)) = user else {
        return Err(AppError::Unauthorized);
    };
    if let Some(r) = not_active(&user) {
        return Ok(r);
    }
    let code = normalize_user_code(&f.code)
        .ok_or_else(|| AppError::BadRequest("not a device code".into()))?;
    // Everything the confirm page checked, checked again: it was rendered
    // from a GET that may be minutes old. That includes the wrong-code limit:
    // a form posted straight here would otherwise be an unlimited way to
    // guess codes, or to deny other people's.
    if device::too_many_misses(user.id) {
        return Ok(enter_code(Some(TOO_MANY), None).into_response());
    }
    let Some(p) = device::pending(&state.pool, &code).await? else {
        device::record_miss(user.id);
        return Ok(outcome(
            "Code expired",
            "It was already used, or timed out. Start again on your device.",
        )
        .into_response());
    };
    if approve && !crate::grants::is_granted(&state.pool, user.id, p.service_id).await? {
        return Ok(no_access(&p).into_response());
    }
    if !device::decide(&state.pool, &code, user.id, approve).await? {
        return Ok(outcome(
            "Code expired",
            "It was already used, or timed out. Start again on your device.",
        )
        .into_response());
    }
    audit(
        &state.pool,
        Some(user.id),
        if approve {
            "device.approve"
        } else {
            "device.deny"
        },
        Some(&format!("service:{}", p.service_id)),
        Some(json!({ "service": p.slug, "name": p.device_name })),
    )
    .await
    .map_err(AppError::Other)?;

    Ok(if approve {
        outcome(
            "Device signed in",
            &format!(
                "{} will finish signing in to {} in a moment. You can close this page.",
                p.device_name, p.service_name
            ),
        )
    } else {
        outcome("Cancelled", "The device wasn't signed in.")
    }
    .into_response())
}

/// Approving mints a 90-day credential, so the post has to come from
/// bastion's own confirm page. `SameSite=Lax` doesn't ensure that: every host
/// bastion fronts is the same site, so a page on any of them could post here
/// with the visitor's cookie. Browsers send `Sec-Fetch-Site` (over https) or
/// at least `Origin` on a POST; a request with neither isn't from a browser,
/// and so carries no cookie but its sender's own.
fn same_origin(state: &AppState, headers: &HeaderMap) -> bool {
    let get = |k| headers.get(k).and_then(|v| v.to_str().ok());
    if let Some(site) = get("sec-fetch-site") {
        return site == "same-origin";
    }
    match get("origin") {
        Some(o) => {
            let own = crate::host::of_url(&origin_from(state, headers));
            crate::host::of_url(o).is_some_and(|h| Some(h) == own)
        }
        None => true,
    }
}

/// The confirm page is one click from pairing a device, so no other site may
/// frame it and steer that click.
fn no_framing(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    res
}

const NO_MATCH: &str =
    "No device is waiting with that code. Codes last 10 minutes — check the one on your screen.";
const TOO_MANY: &str = "Too many wrong codes. Wait a few minutes, then try again.";

fn not_active(user: &UserCtx) -> Option<Response> {
    match user.status.as_str() {
        "active" => None,
        "denied" => Some(Redirect::to("/denied").into_response()),
        _ => Some(Redirect::to("/pending").into_response()),
    }
}

async fn sign_in(state: &AppState, code: Option<&str>) -> AppResult<Markup> {
    let providers: Vec<(String,)> =
        sqlx::query_as("SELECT provider FROM oauth_providers WHERE enabled = 1 ORDER BY provider")
            .fetch_all(&state.pool)
            .await?;
    let providers: Vec<Provider> = providers
        .into_iter()
        .filter_map(|(p,)| Provider::parse(&p))
        .collect();
    Ok(landing_page(
        "Sign in a device",
        html! {
            div.landing-headline { "Sign in a device" }
            div.landing-subline { "sign in to bastion first, then confirm the device" }
            div.provider-stack {
                @for p in &providers {
                    form method="post" action="/auth/login" hx-boost="false" style="margin:0" {
                        @if let Some(c) = code {
                            input type="hidden" name="device" value=(c);
                        }
                        input type="hidden" name="provider" value=(p.as_str());
                        button.provider-btn type="submit" {
                            (provider_icon(p.as_str()))
                            span { "Continue with " (p.display_name()) }
                        }
                    }
                }
            }
        },
    ))
}

fn enter_code(error: Option<&str>, typed: Option<&str>) -> Markup {
    landing_page(
        "Sign in a device",
        html! {
            div.landing-headline { "Sign in a device" }
            div.landing-subline { "enter the code shown on your device" }
            form.provider-stack method="get" action="/device" {
                input.input.mono.code-input name="code" value=[typed]
                    placeholder="BCDF-GHJK" autocomplete="off" autocapitalize="characters"
                    spellcheck="false" autofocus required;
                button.btn.primary.wide type="submit" { "Continue" }
            }
            @if let Some(e) = error {
                div.landing-footnote { (e) }
            }
        },
    )
}

fn banner(p: &device::Pending) -> Markup {
    html! {
        div.dest-banner {
            div.dest-tile { (crate::templates::initials(&p.slug)) }
            div style="min-width:0;flex:1" {
                div.label { "signing in to" }
                div.slug { (p.service_name) }
            }
        }
    }
}

fn confirm(p: &device::Pending, user: &UserCtx) -> Markup {
    let code = display_user_code(&p.user_code);
    landing_page(
        "Confirm device",
        html! {
            (banner(p))
            div.landing-headline { "Sign in this device?" }
            div.landing-subline {
                "a device calling itself “" (p.device_name) "” wants to sign in to "
                (p.service_name) " as " (user.username)
            }
            div.device-code.mono { (code) }
            div.landing-footnote {
                "Only continue if this code is on a screen in front of you."
                br;
                "If someone sent it to you, deny it."
            }
            div.provider-stack {
                form method="post" action="/device/approve" style="margin:0" {
                    input type="hidden" name="code" value=(code);
                    button.btn.primary.wide type="submit" { "Sign in" }
                }
                form method="post" action="/device/deny" style="margin:0" {
                    input type="hidden" name="code" value=(code);
                    button.btn.wide type="submit" { "Deny" }
                }
            }
        },
    )
}

fn no_access(p: &device::Pending) -> Markup {
    landing_page(
        "No access",
        html! {
            (banner(p))
            div.landing-headline { "No access yet" }
            div.landing-subline { "you don't have access to " (p.service_name) }
            div.landing-footnote {
                "An admin has been asked. Once they've granted it, enter the code again "
                "— or start over on the device if it has expired."
            }
        },
    )
}

fn outcome(headline: &str, detail: &str) -> Markup {
    landing_page(
        headline,
        html! {
            div.landing-headline { (headline) }
            div.landing-footnote { (detail) }
        },
    )
}

// -------------------- Revoking --------------------

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub id: i64,
}

/// A user unpairing one of their own devices, from `/account`.
pub async fn revoke_own(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<RevokeForm>,
) -> AppResult<Response> {
    let Some(Extension(user)) = user else {
        return Err(AppError::Unauthorized);
    };
    device::revoke(
        &state.pool,
        f.id,
        Some(user.id),
        Some(user.id),
        "device.revoke",
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/account").into_response())
}
