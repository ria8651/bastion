use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use maud::{html, Markup};
use serde::Deserialize;

use super::ui::{
    back, badge, empty, field, header, section, status_badge, tile, user_avatar, Nav, Post, Tone,
};
use super::{admin, ctx, fmt_time, rel_time, ProxyHealth};
use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::models::UserCtx;
use crate::state::AppState;

// -------------------- List --------------------

pub async fn services_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(i64, String, String, String, String, Option<String>, Option<String>, Option<i64>, i64, i64, String)> =
        sqlx::query_as(
            "SELECT s.id, s.slug, s.name, s.status, s.mode, s.proxy_host, s.upstream_url,
                    s.registered_at,
                    (SELECT COUNT(*) FROM grants g WHERE g.service_id = s.id),
                    (SELECT COUNT(*) FROM permissions p
                      WHERE p.service_id = s.id AND p.removed_at IS NULL),
                    s.return_url
             FROM services s
             WHERE s.deleted_at IS NULL
             ORDER BY s.slug",
        )
        .fetch_all(&state.pool)
        .await?;
    let of = |st: &'static str| rows.iter().filter(move |r| r.3 == st);
    let approved: Vec<_> = of("approved").collect();
    let pending: Vec<_> = of("pending").collect();
    let denied: Vec<_> = of("denied").collect();

    let body = html! {
        (header(None, "Services",
            Some(html! {
                (approved.len()) " active"
                @if !pending.is_empty() { " · " (pending.len()) " awaiting review" }
            }),
            Some(html! { a.btn.primary href="/admin/services/new" { "New service" } }),
        ))

        @if !pending.is_empty() {
            (section("Awaiting review", Some(pending.len()), None, html! {
                p.sec-desc { "These services registered themselves via the API. Nobody can sign in to them until you approve." }
                div.list {
                    @for (id, slug, name, _, _, _, _, registered, ..) in &pending {
                        a.row href=(format!("/admin/services/{}", id)) {
                            span.lead { (tile(slug, "")) }
                            div.row-body {
                                div.main {
                                    div.t { (slug) }
                                    div.s { (name) " · registered " (registered.map(rel_time).unwrap_or_else(|| "—".into())) }
                                }
                                div.meta { (badge(Tone::Warn, "review")) }
                            }
                            span.chev { "›" }
                        }
                    }
                }
            }))
        }

        (section("Services", None, None, html! {
            @if approved.is_empty() {
                (empty("No services yet.",
                    "Services register themselves by POSTing to /api/services/register, or add one by hand."))
            } @else {
                div.list {
                    @for (id, slug, name, _, mode, phost, upstream, _, users, perms, return_url) in &approved {
                        a.row href=(format!("/admin/services/{}", id)) {
                            span.lead { (tile(slug, "")) }
                            div.row-body {
                                div.main {
                                    div.t {
                                        (slug)
                                        @if name != slug { span.mute { " · " (name) } }
                                    }
                                    div.s {
                                        @if mode == "proxy" {
                                            (phost.as_deref().unwrap_or("—")) " → " (upstream.as_deref().unwrap_or("no upstream"))
                                        } @else {
                                            (return_url)
                                        }
                                    }
                                }
                                div.meta {
                                    (badge(Tone::Quiet, mode))
                                    span { (users) " " (if *users == 1 { "user" } else { "users" }) }
                                    @if *perms > 0 { span { (perms) " perms" } }
                                }
                            }
                            span.chev { "›" }
                        }
                    }
                }
            }
        }))

        @if !denied.is_empty() {
            (section("Denied registrations", Some(denied.len()), None, html! {
                p.sec-desc { "A denied service can't register again under the same slug until you remove it." }
                div.list {
                    @for (id, slug, name, ..) in &denied {
                        a.row href=(format!("/admin/services/{}", id)) {
                            span.lead { (tile(slug, "")) }
                            div.row-body {
                                div.main { div.t { (slug) } div.s { (name) } }
                                div.meta { (status_badge("denied")) }
                            }
                            span.chev { "›" }
                        }
                    }
                }
            }))
        }
    };
    Ok(ctx.page(Nav::Services, "Services", body).into_response())
}

// -------------------- Shared form --------------------

#[derive(Default)]
struct FormValues<'a> {
    id: Option<i64>,
    slug: &'a str,
    name: &'a str,
    mode: &'a str,
    return_url: &'a str,
    proxy_host: &'a str,
    upstream_url: &'a str,
    public_paths: &'a str,
}

/// One form for create and edit. Fields for the other mode are hidden by CSS
/// keyed on `data-mode`, which the radios update; without JS everything shows
/// and the server ignores what the mode doesn't use.
fn service_form(action: &str, submit: &str, v: &FormValues) -> Markup {
    let mode = if v.mode == "proxy" { "proxy" } else { "redirect" };
    html! {
        form.form method="post" action=(action) data-mode=(mode) {
            @if let Some(id) = v.id { input type="hidden" name="id" value=(id); }
            div.grid-2 {
                (field("Slug", Some("Lowercase letters, digits and dashes. Becomes the JWT audience."),
                    html! { input.input.mono name="slug" value=(v.slug) required
                        pattern="[a-z0-9-]+" autocapitalize="off" autocomplete="off" spellcheck="false"; }))
                (field("Name", Some("Shown to users. Defaults to the slug."),
                    html! { input.input name="name" value=(v.name); }))
            }
            div.fld {
                span.l { "Mode" }
                div.choice role="radiogroup" {
                    label {
                        input type="radio" name="mode" value="redirect" checked[mode == "redirect"]
                            onchange="this.form.dataset.mode=this.value";
                        div {
                            div.t { "Redirect" }
                            div.d { "The app sends users to bastion and verifies the JWT it gets back." }
                        }
                    }
                    label {
                        input type="radio" name="mode" value="proxy" checked[mode == "proxy"]
                            onchange="this.form.dataset.mode=this.value";
                        div {
                            div.t { "Proxy" }
                            div.d { "bastion serves the app's hostname and forwards with identity headers. The app needs no changes." }
                        }
                    }
                }
            }
            div data-for="redirect" {
                (field("Return URL", Some("Where users land after sign-in, with ?bastion_token= appended."),
                    html! { input.input.mono name="returnUrl" value=(v.return_url) type="url"
                        placeholder="https://app.example.com/auth/bastion" autocapitalize="off"; }))
            }
            div.grid-2 data-for="proxy" {
                (field("Public hostname", Some("Point its DNS and TLS at bastion."),
                    html! { input.input.mono name="proxyHost" value=(v.proxy_host)
                        placeholder="app.example.com" autocapitalize="off" spellcheck="false"; }))
                (field("Upstream", Some("Where the app actually listens. Plain http."),
                    html! { input.input.mono name="upstreamUrl" value=(v.upstream_url)
                        placeholder="http://127.0.0.1:8080" autocapitalize="off" spellcheck="false"; }))
            }
            div data-for="proxy" {
                (field("Public paths", Some("One glob per line. Forwarded without a session — health checks, webhooks."),
                    html! { textarea.input name="publicPaths" rows="3"
                        placeholder="/health\n/api/webhooks/*" { (v.public_paths) } }))
            }
            div.form-actions {
                button.btn.primary type="submit" { (submit) }
            }
        }
    }
}

// -------------------- New --------------------

pub async fn service_new_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;
    let body = html! {
        (back("/admin/services", "Services"))
        (header(None, "New service", None, None))
        p.sec-desc {
            "Most services register themselves by POSTing to "
            span.code { "/api/services/register" }
            " on boot and appear for review. Add one here when it can't — including any proxied app, "
            "since only an admin can set an upstream."
        }
        div.panel {
            (service_form("/admin/services/add", "Create service", &FormValues { mode: "redirect", ..Default::default() }))
        }
    };
    Ok(ctx.page(Nav::Services, "New service", body).into_response())
}

// -------------------- Detail --------------------

pub async fn service_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;

    #[allow(clippy::type_complexity)]
    let row: Option<(String, String, String, String, String, Option<String>, Option<String>, Option<String>, Option<String>, Option<i64>, i64)> =
        sqlx::query_as(
            "SELECT slug, name, return_url, status, mode, proxy_host, upstream_url, public_paths,
                    public_jwk, registered_at, created_at
             FROM services WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    let Some((slug, name, return_url, status, mode, phost, upstream, ppaths, jwk, registered, created)) = row
    else {
        return Err(AppError::NotFound);
    };

    let perms: Vec<(String, Option<String>, Option<i64>, bool)> = sqlx::query_as(
        "SELECT key, description, removed_at, default_allow FROM permissions
         WHERE service_id = ? ORDER BY removed_at IS NOT NULL, key",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let active_perms = perms.iter().filter(|p| p.2.is_none()).count();
    let id_s = id.to_string();
    let is_proxy = mode == "proxy";

    let perms_list = html! {
        @if perms.is_empty() {
            (empty("No permissions declared.", ""))
        } @else {
            div.list {
                @for (key, desc, removed, default_allow) in &perms {
                    div.row {
                        div.row-body {
                            div.main {
                                div.t.mono.strike[removed.is_some()] { (key) }
                                @if let Some(d) = desc { div.s { (d) } }
                            }
                            div.meta {
                                @if let Some(at) = removed {
                                    (badge(Tone::Quiet, &format!("removed {}", rel_time(*at))))
                                } @else if *default_allow {
                                    (badge(Tone::Quiet, "default on"))
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    let remove = |label: &str, msg: &str| {
        html! {
            (Post::new("/admin/services/remove", label).class("btn bad")
                .fields(&[("id", &id_s)]).confirm(msg).render())
        }
    };

    let body = match status.as_str() {
        "pending" => html! {
            (back("/admin/services", "Services"))
            (header(Some(tile(&slug, "lg")), &slug, Some(html! { (status_badge("pending")) span { (name) } }), None))
            (section("Registration", None, None, html! {
                div.panel {
                    dl.kv {
                        dt { "Slug" } dd { (slug) }
                        dt { "Name" } dd { (name) }
                        dt { "Registered" } dd { (registered.map(fmt_time).unwrap_or_else(|| "—".into())) }
                        dt { "Key id" } dd { (jwk_short(jwk.as_deref())) }
                        dt { "Key fingerprint" } dd { (jwk_thumbprint_short(jwk.as_deref())) }
                    }
                }
            }))
            (section("Declared permissions", Some(active_perms), None, perms_list))
            (section("Decision", None, None, html! {
                div.panel {
                    form.form method="post" action="/admin/services/approve-registration" {
                        input type="hidden" name="id" value=(id);
                        (field("Return URL", Some("Suggested by the service. Users' browsers are sent here after sign-in — check it's really theirs."),
                            html! { input.input.mono name="returnUrl" value=(return_url) required type="url"; }))
                        div.form-actions {
                            button.btn.primary type="submit" { "Approve" }
                            button.btn.bad type="submit" formaction="/admin/services/deny-registration" formnovalidate
                                onclick="return confirm('Deny this registration? The service can\\'t register again under this slug until you remove it.')"
                                { "Deny" }
                        }
                    }
                }
            }))
        },
        "denied" => html! {
            (back("/admin/services", "Services"))
            (header(Some(tile(&slug, "lg")), &slug, Some(html! { (status_badge("denied")) span { (name) } }), None))
            p.sec-desc { "This registration was denied. Remove it to let the service register again under the same slug." }
            (remove("Remove", "Remove this denied registration?"))
        },
        _ => {
            let users: Vec<(i64, String, Option<String>, String, i64)> = sqlx::query_as(
                "SELECT u.id, u.username, u.avatar, u.status, g.granted_at
                 FROM grants g JOIN users u ON u.id = g.user_id
                 WHERE g.service_id = ? ORDER BY u.username",
            )
            .bind(id)
            .fetch_all(&state.pool)
            .await?;
            let health = ProxyHealth::load(&state).await?;
            let target = if is_proxy { phost.clone().unwrap_or_default() } else { return_url.clone() };
            html! {
                (back("/admin/services", "Services"))
                (header(
                    Some(tile(&slug, "lg")),
                    &slug,
                    Some(html! {
                        (badge(Tone::Quiet, &mode))
                        @if name != slug { span { (name) } }
                        span { "created " (fmt_time(created)) }
                    }),
                    Some(html! {
                        a.btn href=(format!("/launch/{}", slug)) hx-boost="false" target="_blank" rel="noopener"
                            title=(target) { "Open ↗" }
                    }),
                ))
                @if is_proxy { div.notices { (health.notices()) } }

                (section("Configuration", None, None, html! {
                    div.panel {
                        (service_form("/admin/services/update", "Save changes", &FormValues {
                            id: Some(id),
                            slug: &slug,
                            name: &name,
                            mode: &mode,
                            return_url: &return_url,
                            proxy_host: phost.as_deref().unwrap_or(""),
                            upstream_url: upstream.as_deref().unwrap_or(""),
                            public_paths: ppaths.as_deref().unwrap_or(""),
                        }))
                    }
                }))

                (section("People with access", Some(users.len()), None, html! {
                    @if users.is_empty() {
                        (empty("Nobody has access yet.", "Grant it from a user's page, or approve their access request."))
                    } @else {
                        div.list {
                            @for (uid, uname, avatar, ustatus, granted_at) in &users {
                                a.row href=(format!("/admin/users/{}", uid)) {
                                    span.lead { (user_avatar(avatar.as_deref(), uname, "")) }
                                    div.row-body {
                                        div.main { div.t { (uname) } }
                                        div.meta {
                                            @if ustatus != "active" { (status_badge(ustatus)) }
                                            span { "granted " (rel_time(*granted_at)) }
                                        }
                                    }
                                    span.chev { "›" }
                                }
                            }
                        }
                    }
                }))

                // A proxied app can't register a catalog and is sent none, so an
                // empty section there would only suggest something it can't use.
                @if !(is_proxy && perms.is_empty()) {
                    (section("Permissions", Some(active_perms), None, html! {
                        p.sec-desc {
                            @if is_proxy {
                                "Proxy mode doesn't send permissions — the grant is the whole decision. "
                            }
                            "The catalog belongs to the service, which declares it when it registers. Toggle them per user on each user's page."
                        }
                        (perms_list)
                    }))
                }

                (section("Danger zone", None, None, html! {
                    div.panel.danger {
                        div.inline-actions {
                            div.grow {
                                div { "Remove this service" }
                                div.hint { "Everyone loses access immediately. Its slug becomes free to register again." }
                            }
                            (remove("Remove service", "Remove this service? Everyone with access loses it immediately."))
                        }
                    }
                }))
            }
        }
    };
    Ok(ctx.page(Nav::Services, &slug, body).into_response())
}

pub fn jwk_short(jwk_str: Option<&str>) -> String {
    let Some(s) = jwk_str else { return "—".into() };
    serde_json::from_str::<serde_json::Value>(s)
        .ok()
        .and_then(|v| v.get("kid").and_then(|k| k.as_str()).map(String::from))
        .unwrap_or_else(|| "—".into())
}

pub fn jwk_thumbprint_short(jwk_str: Option<&str>) -> String {
    let Some(s) = jwk_str else { return "—".into() };
    crate::routes::registration::jwk_thumbprint(s)
}

// -------------------- Mutations --------------------

/// Create and edit share a form; `id` is present only on edit.
#[derive(Debug, Deserialize)]
pub struct ServiceForm {
    #[serde(default)]
    pub id: Option<i64>,
    pub slug: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "returnUrl", default)]
    pub return_url: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(rename = "proxyHost", default)]
    pub proxy_host: Option<String>,
    #[serde(rename = "upstreamUrl", default)]
    pub upstream_url: Option<String>,
    #[serde(rename = "publicPaths", default)]
    pub public_paths: Option<String>,
}

#[derive(Debug)]
pub struct ServiceFields {
    pub slug: String,
    pub name: String,
    pub return_url: String,
    pub mode: String,
    pub proxy_host: Option<String>,
    pub upstream_url: Option<String>,
}

impl ServiceForm {
    fn validate(&self) -> Result<ServiceFields, String> {
        validate(
            &self.slug,
            &self.name,
            &self.return_url,
            self.mode.as_deref(),
            self.proxy_host.as_deref(),
            self.upstream_url.as_deref(),
        )
    }

    /// Public paths only mean something in proxy mode; drop them otherwise so
    /// a service flipped back to redirect doesn't carry stale ones.
    fn public_paths(&self, mode: &str) -> Option<&str> {
        self.public_paths
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && mode == "proxy")
    }
}

fn validate(
    slug: &str,
    name: &str,
    return_url: &str,
    mode: Option<&str>,
    proxy_host: Option<&str>,
    upstream_url: Option<&str>,
) -> Result<ServiceFields, String> {
    let slug = slug.trim().to_string();
    let name = {
        let n = name.trim();
        if n.is_empty() { slug.clone() } else { n.to_string() }
    };
    if slug.is_empty() {
        return Err("slug required".into());
    }
    if !slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err("slug must be lowercase alphanumeric + dashes".into());
    }

    let mode = match mode.map(str::trim).unwrap_or("redirect") {
        "" | "redirect" => "redirect",
        "proxy" => "proxy",
        _ => return Err("mode must be redirect or proxy".into()),
    }
    .to_string();

    let mut return_url = return_url.trim().to_string();
    let mut upstream = None;
    let proxy_host = if mode == "proxy" {
        let host = crate::host::validate(proxy_host.unwrap_or(""), "public hostname")?;

        // Admin-only, and never settable by a self-registering service: an
        // attacker-chosen upstream would turn bastion into an open proxy onto
        // whatever the box can reach.
        let u = upstream_url.unwrap_or("").trim().to_string();
        if u.is_empty() {
            return Err("upstream URL required for proxy mode".into());
        }
        // http only, matching the proxy client. TLS terminates at the gateway
        // in front of bastion, and the upstream is the app itself — normally on
        // loopback. Accepting https here would mean every request to that
        // service 502s with nothing to explain why.
        match url::Url::parse(&u) {
            Ok(parsed) if parsed.scheme() == "http" => {}
            Ok(parsed) if parsed.scheme() == "https" => {
                return Err(
                    "upstream URL must be http — bastion talks to upstreams in plaintext, \
                     and TLS belongs at the gateway in front of bastion"
                        .into(),
                )
            }
            Ok(_) => return Err("upstream URL must be http".into()),
            Err(_) => return Err("upstream URL must be a valid URL".into()),
        }
        // Compare hosts, not string suffixes: `ends_with` called
        // http://myapp.example.com a loop against app.example.com, and missed
        // the real one at https://app.example.com:443/ because the port breaks
        // the suffix test.
        if crate::host::of_url(&u).as_deref() == Some(host.as_str()) {
            return Err("upstream URL points back at the public hostname — that is a loop".into());
        }
        upstream = Some(u);
        // A proxied app is reached at its own hostname, so that *is* the place
        // to land after login. Keeping return_url populated also means
        // /launch/<slug> and the pending page's "try again" keep working
        // unchanged for both modes.
        if return_url.is_empty() {
            return_url = format!("https://{}/", host);
        }
        Some(host)
    } else {
        None
    };

    if return_url.is_empty() {
        return Err("return url required for redirect mode".into());
    }
    if url::Url::parse(&return_url).is_err() {
        return Err("return url must be a valid URL".into());
    }
    Ok(ServiceFields { slug, name, return_url, mode, proxy_host, upstream_url: upstream })
}

pub async fn add_service(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<ServiceForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    let v = f.validate().map_err(AppError::BadRequest)?;
    let inserted: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO services (slug, name, return_url, mode, proxy_host, upstream_url, public_paths)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(slug) WHERE deleted_at IS NULL DO NOTHING RETURNING id",
    )
    .bind(&v.slug)
    .bind(&v.name)
    .bind(&v.return_url)
    .bind(&v.mode)
    .bind(&v.proxy_host)
    .bind(&v.upstream_url)
    .bind(f.public_paths(&v.mode))
    .fetch_optional(&state.pool)
    .await?;
    let Some((sid,)) = inserted else {
        return Err(AppError::BadRequest("slug already exists".into()));
    };
    sqlx::query(
        "INSERT INTO grants (user_id, service_id, granted_by) VALUES (?, ?, ?)
         ON CONFLICT(user_id, service_id) DO NOTHING",
    )
    .bind(admin.id)
    .bind(sid)
    .bind(admin.id)
    .execute(&state.pool)
    .await?;
    crate::routes::registration::apply_default_perms(&state.pool, admin.id, sid).await?;
    audit(
        &state.pool,
        Some(admin.id),
        "service.add",
        Some(&format!("service:{}", sid)),
        Some(serde_json::json!({ "slug": v.slug })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to(&format!("/admin/services/{}", sid)).into_response())
}

pub async fn update_service(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<ServiceForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    let id = f.id.ok_or_else(|| AppError::BadRequest("missing service id".into()))?;
    let v = f.validate().map_err(AppError::BadRequest)?;
    sqlx::query(
        "UPDATE services
         SET slug = ?, name = ?, return_url = ?, mode = ?,
             proxy_host = ?, upstream_url = ?, public_paths = ?
         WHERE id = ?",
    )
    .bind(&v.slug)
    .bind(&v.name)
    .bind(&v.return_url)
    .bind(&v.mode)
    .bind(&v.proxy_host)
    .bind(&v.upstream_url)
    .bind(f.public_paths(&v.mode))
    .bind(id)
    .execute(&state.pool)
    .await?;
    audit(
        &state.pool,
        Some(admin.id),
        "service.update",
        Some(&format!("service:{}", id)),
        Some(serde_json::json!({ "slug": v.slug })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to(&format!("/admin/services/{}", id)).into_response())
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
    let admin = admin(user)?;
    sqlx::query("UPDATE services SET deleted_at = unixepoch() WHERE id = ? AND deleted_at IS NULL")
        .bind(f.id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(admin.id),
        "service.remove",
        Some(&format!("service:{}", f.id)),
        None,
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/admin/services").into_response())
}

#[derive(Debug, Deserialize)]
pub struct ApproveRegistrationForm {
    pub id: i64,
    #[serde(rename = "returnUrl")]
    pub return_url: String,
}

pub async fn approve_registration(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<ApproveRegistrationForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT slug, status FROM services WHERE id = ? AND deleted_at IS NULL")
            .bind(f.id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((slug, status)) = row else {
        return Err(AppError::BadRequest("not found".into()));
    };
    if status != "pending" {
        return Err(AppError::BadRequest(format!("service is {}, not pending", status)));
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
        Some(serde_json::json!({ "slug": slug, "returnUrl": return_url })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to(&format!("/admin/services/{}", f.id)).into_response())
}

pub async fn deny_registration(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<IdForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT slug, status FROM services WHERE id = ? AND deleted_at IS NULL")
            .bind(f.id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((slug, status)) = row else {
        return Err(AppError::BadRequest("not found".into()));
    };
    if status != "pending" {
        return Err(AppError::BadRequest(format!("service is {}, not pending", status)));
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
        Some(serde_json::json!({ "slug": slug })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/admin/services").into_response())
}

#[cfg(test)]
mod tests {
    use super::validate;

    fn proxy(host: &str, upstream: &str) -> Result<super::ServiceFields, String> {
        validate("demo", "Demo", "", Some("proxy"), Some(host), Some(upstream))
    }

    #[test]
    fn upstream_loop_check_compares_hosts_not_suffixes() {
        // The suffix test this replaced got both directions wrong.
        // False positive: a different host that merely ends with the same text.
        assert!(proxy("app.example.com", "http://myapp.example.com").is_ok());
        // False negative: the real loop, missed because the port broke the
        // suffix match.
        assert!(proxy("app.example.com", "https://app.example.com:443/").is_err());

        assert!(proxy("app.example.com", "http://app.example.com").is_err());
        assert!(proxy("app.example.com", "http://app.example.com./x").is_err());
        assert!(proxy("app.example.com", "http://APP.example.com").is_err());
        assert!(proxy("app.example.com", "http://127.0.0.1:8080").is_ok());
    }

    #[test]
    fn proxy_mode_requires_a_usable_upstream() {
        assert!(proxy("app.example.com", "").is_err());
        assert!(proxy("app.example.com", "ftp://host/x").is_err());
        assert!(proxy("app.example.com", "not a url").is_err());
        assert!(validate("demo", "", "", Some("proxy"), Some(""), Some("http://x:1")).is_err());

        // The proxy client is plaintext-only, so an https upstream would save
        // cleanly and then 502 on every request. Refuse it here, where the
        // message can say why, rather than there, where nothing can.
        let err = proxy("app.example.com", "https://127.0.0.1:8080").unwrap_err();
        assert!(err.contains("must be http"), "{}", err);
        assert!(err.contains("gateway"), "{}", err);
    }

    #[test]
    fn proxy_fields_are_cleared_in_redirect_mode() {
        // Otherwise a service flipped back to redirect keeps a live proxy_host,
        // and its unique index keeps that hostname claimed.
        let v = validate(
            "demo",
            "Demo",
            "https://demo.example.com/cb",
            Some("redirect"),
            Some("app.example.com"),
            Some("http://127.0.0.1:8080"),
        )
        .unwrap();
        assert_eq!(v.mode, "redirect");
        assert!(v.proxy_host.is_none());
        assert!(v.upstream_url.is_none());
        assert_eq!(v.return_url, "https://demo.example.com/cb");
    }

    #[test]
    fn proxy_mode_defaults_return_url_to_the_public_host() {
        // /launch/<slug> and the pending page's "try again" both go through
        // return_url, so it has to be populated in either mode.
        let v = proxy("app.example.com", "http://127.0.0.1:8080").unwrap();
        assert_eq!(v.return_url, "https://app.example.com/");
        assert_eq!(v.proxy_host.as_deref(), Some("app.example.com"));
    }
}
