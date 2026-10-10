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
    let rows: Vec<(i64, String, String, String, Option<i64>, i64, i64, String, Option<String>)> =
        sqlx::query_as(
            "SELECT s.id, s.slug, s.name, s.status, s.registered_at,
                    (SELECT COUNT(*) FROM grants g WHERE g.service_id = s.id),
                    (SELECT COUNT(*) FROM permissions p
                      WHERE p.service_id = s.id AND p.removed_at IS NULL),
                    s.return_url,
                    (SELECT group_concat(h.host, ', ') FROM route_hosts h
                       JOIN routes r ON r.id = h.route_id WHERE r.service_id = s.id)
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
                    @for (id, slug, name, _, registered, ..) in &pending {
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
                    @for (id, slug, name, _, _, users, perms, return_url, gated_hosts) in &approved {
                        a.row href=(format!("/admin/services/{}", id)) {
                            span.lead { (tile(slug, "")) }
                            div.row-body {
                                div.main {
                                    div.t {
                                        (slug)
                                        @if name != slug { span.mute { " · " (name) } }
                                    }
                                    div.s {
                                        @if let Some(h) = gated_hosts {
                                            (h)
                                        } @else if !return_url.is_empty() {
                                            (return_url)
                                        } @else {
                                            "no way in yet"
                                        }
                                    }
                                }
                                div.meta {
                                    @if gated_hosts.is_some() { (badge(Tone::Quiet, "gated")) }
                                    @if !return_url.is_empty() { (badge(Tone::Quiet, "token")) }
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
    return_url: &'a str,
}

fn service_form(action: &str, submit: &str, v: &FormValues) -> Markup {
    html! {
        form.form method="post" action=(action) {
            @if let Some(id) = v.id { input type="hidden" name="id" value=(id); }
            div.grid-2 {
                (field("Slug", Some("Lowercase letters, digits and dashes. Becomes the JWT audience."),
                    html! { input.input.mono name="slug" value=(v.slug) required
                        pattern="[a-z0-9-]+" autocapitalize="off" autocomplete="off" spellcheck="false"; }))
                (field("Name", Some("Shown to users. Defaults to the slug."),
                    html! { input.input name="name" value=(v.name); }))
            }
            (field("Return URL",
                Some("Only for an app that verifies bastion's token itself: users land here after sign-in, with ?bastion_token= appended. Leave empty for an app gated by a route."),
                html! { input.input.mono name="returnUrl" value=(v.return_url) type="url"
                    placeholder="https://app.example.com/auth/bastion" autocapitalize="off"; }))
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
            "A service is who may get in. Apps that verify bastion's token register themselves by POSTing to "
            span.code { "/api/services/register" }
            " and appear for review. For an app that knows nothing about bastion, create a service here, "
            "then gate a route with it."
        }
        div.panel {
            (service_form("/admin/services/add", "Create service", &FormValues::default()))
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
    let row: Option<(String, String, String, String, Option<String>, Option<i64>, i64)> =
        sqlx::query_as(
            "SELECT slug, name, return_url, status, public_jwk, registered_at, created_at
             FROM services WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    let Some((slug, name, return_url, status, jwk, registered, created)) = row
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
    let uses_token = !return_url.is_empty();

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
            let routes: Vec<(i64, String, String, bool, String)> = sqlx::query_as(
                "SELECT r.id, r.name, r.upstream_url, r.enabled,
                        COALESCE((SELECT group_concat(host, ', ') FROM
                                   (SELECT host FROM route_hosts WHERE route_id = r.id ORDER BY host)), '')
                 FROM routes r WHERE r.service_id = ? ORDER BY r.name",
            )
            .bind(id)
            .fetch_all(&state.pool)
            .await?;
            let health = ProxyHealth::load(&state).await?;
            let can_open = uses_token || routes.iter().any(|r| r.3);
            html! {
                (back("/admin/services", "Services"))
                (header(
                    Some(tile(&slug, "lg")),
                    &slug,
                    Some(html! {
                        @if !routes.is_empty() { (badge(Tone::Quiet, "gated")) }
                        @if uses_token { (badge(Tone::Quiet, "token")) }
                        @if name != slug { span { (name) } }
                        span { "created " (fmt_time(created)) }
                    }),
                    can_open.then(|| html! {
                        a.btn href=(format!("/launch/{}", slug)) hx-boost="false" target="_blank" rel="noopener" { "Open ↗" }
                    }),
                ))
                @if !routes.is_empty() { div.notices { (health.notices()) } }

                (section("Configuration", None, None, html! {
                    div.panel {
                        (service_form("/admin/services/update", "Save changes", &FormValues {
                            id: Some(id),
                            slug: &slug,
                            name: &name,
                            return_url: &return_url,
                        }))
                    }
                }))

                (section("Reached via", Some(routes.len()),
                    Some(html! { a.btn.sm href=(format!("/admin/routes/new?service={}", id)) { "Add a route" } }),
                    html! {
                    p.sec-desc {
                        "Routes gated by this service: only people with access get through, and the app "
                        "receives their identity as headers."
                    }
                    @if routes.is_empty() {
                        (empty("No routes are gated by this service.",
                            if uses_token { "It's reached through its return URL instead." } else { "Add one to put an app behind it." }))
                    } @else {
                        div.list {
                            @for (rid, rname, upstream, enabled, hosts) in &routes {
                                a.row href=(format!("/admin/routes/{}", rid)) {
                                    span.lead { (tile(rname, "")) }
                                    div.row-body {
                                        div.main { div.t { (rname) } div.s { (hosts) " → " (upstream) } }
                                        div.meta { @if !enabled { (status_badge("disabled")) } }
                                    }
                                    span.chev { "›" }
                                }
                            }
                        }
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

                // Permissions travel in the JWT only. An app reached solely
                // through a gated route can't register a catalog and is sent
                // none, so an empty section there would suggest something it
                // can't use.
                @if uses_token || !perms.is_empty() {
                    (section("Permissions", Some(active_perms), None, html! {
                        p.sec-desc {
                            @if !uses_token {
                                "Gated routes don't send permissions — the grant is the whole decision. "
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
                            (remove("Remove service", if routes.is_empty() {
                                "Remove this service? Everyone with access loses it immediately."
                            } else {
                                "Remove this service? Everyone with access loses it immediately, and the routes it gates close until they're given another service."
                            }))
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
}

#[derive(Debug)]
pub struct ServiceFields {
    pub slug: String,
    pub name: String,
    pub return_url: String,
}

fn validate(slug: &str, name: &str, return_url: &str) -> Result<ServiceFields, String> {
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
    // Optional: empty means the service is only reached through gated routes.
    let return_url = return_url.trim().to_string();
    if !return_url.is_empty() && url::Url::parse(&return_url).is_err() {
        return Err("return url must be a valid URL".into());
    }
    Ok(ServiceFields { slug, name, return_url })
}

pub async fn add_service(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<ServiceForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    let v = validate(&f.slug, &f.name, &f.return_url).map_err(AppError::BadRequest)?;
    let inserted: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO services (slug, name, return_url)
         VALUES (?, ?, ?)
         ON CONFLICT(slug) WHERE deleted_at IS NULL DO NOTHING RETURNING id",
    )
    .bind(&v.slug)
    .bind(&v.name)
    .bind(&v.return_url)
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
    let v = validate(&f.slug, &f.name, &f.return_url).map_err(AppError::BadRequest)?;
    sqlx::query("UPDATE services SET slug = ?, name = ?, return_url = ? WHERE id = ?")
    .bind(&v.slug)
    .bind(&v.name)
    .bind(&v.return_url)
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

    #[test]
    fn return_url_is_optional_but_must_parse() {
        // A service gated only by routes has nowhere to send a token.
        let v = validate("demo", "", "").unwrap();
        assert_eq!(v.return_url, "");
        assert_eq!(v.name, "demo");
        assert!(validate("demo", "", "https://demo.example.com/cb").is_ok());
        assert!(validate("demo", "", "not a url").is_err());
        assert!(validate("Demo", "", "").is_err());
        assert!(validate("", "", "").is_err());
    }
}
