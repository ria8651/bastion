//! Routes: every hostname bastion forwards. A route can be open, or gated by
//! a service — only people granted it get through, with identity headers.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use maud::{html, Markup};
use serde::Deserialize;

use super::ui::{back, badge, empty, field, header, notice, section, status_badge, switch, tile, Nav, Post, Tone};
use super::{admin, ctx, fmt_time, ProxyHealth};
use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::models::UserCtx;
use crate::state::AppState;

/// The gate on a route, as the admin pages show it.
enum Access {
    Open,
    Gated(String),
    /// Gated by a service that has since been removed or isn't approved: the
    /// route is closed until someone picks again.
    Broken,
}

impl Access {
    fn of(service_id: Option<i64>, slug: Option<String>) -> Access {
        match (service_id, slug) {
            (None, _) => Access::Open,
            (Some(_), Some(slug)) => Access::Gated(slug),
            (Some(_), None) => Access::Broken,
        }
    }

    fn badge(&self) -> Markup {
        match self {
            Access::Open => badge(Tone::Quiet, "open"),
            Access::Gated(slug) => badge(Tone::Strong, &format!("gated · {}", slug)),
            Access::Broken => badge(Tone::Bad, "gate removed"),
        }
    }
}

/// Approved services, for the "Access" picker.
async fn gate_choices(state: &AppState) -> AppResult<Vec<(i64, String, String)>> {
    Ok(sqlx::query_as(
        "SELECT id, slug, name FROM services
         WHERE deleted_at IS NULL AND status = 'approved' ORDER BY slug",
    )
    .fetch_all(&state.pool)
    .await?)
}

// -------------------- List --------------------

pub async fn routes_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;

    #[allow(clippy::type_complexity)]
    let routes: Vec<(i64, String, String, bool, bool, String, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT r.id, r.name, r.upstream_url, r.tls_skip_verify, r.enabled,
                COALESCE((SELECT group_concat(host, ', ') FROM
                           (SELECT host FROM route_hosts WHERE route_id = r.id ORDER BY host)), ''),
                r.service_id,
                (SELECT s.slug FROM services s WHERE s.id = r.service_id
                   AND s.deleted_at IS NULL AND s.status = 'approved')
         FROM routes r
         ORDER BY r.name",
    )
    .fetch_all(&state.pool)
    .await?;
    let gated = routes.iter().filter(|r| r.6.is_some()).count();
    let health = ProxyHealth::load(&state).await?;

    let body = html! {
        (header(None, "Routes",
            Some(html! { (routes.len() - gated) " open · " (gated) " gated" }),
            Some(html! { a.btn.primary href="/admin/routes/new" { "New route" } }),
        ))

        div.notices {
            (health.notices())
            @if state.origin.is_none() && !routes.is_empty() {
                (notice(Tone::Warn, html! {
                    strong { "ORIGIN isn't set." }
                    " bastion can't tell its own hostname from a routed one, so a wildcard route "
                    "covering it would take over this admin UI. Pin it in the environment."
                }))
            }
        }

        (section("Routes", None, None, html! {
            p.sec-desc {
                "Every hostname bastion forwards. An open route goes straight to its upstream; a gated one "
                "first checks the visitor is signed in and granted its service, then adds identity headers. "
                "bastion's own session cookie is stripped either way."
            }
            @if routes.is_empty() {
                (empty("No routes yet.", "Add one for each hostname bastion should forward."))
            } @else {
                div.list {
                    @for (id, name, upstream, skip_verify, enabled, hosts, sid, slug) in &routes {
                        a.row href=(format!("/admin/routes/{}", id)) {
                            span.lead { (tile(name, "")) }
                            div.row-body {
                                div.main {
                                    div.t { (name) }
                                    div.s { (hosts) " → " (upstream) }
                                }
                                div.meta {
                                    (Access::of(*sid, slug.clone()).badge())
                                    @if !enabled { (status_badge("disabled")) }
                                    @if *skip_verify { (badge(Tone::Warn, "unverified tls")) }
                                }
                            }
                            span.chev { "›" }
                        }
                    }
                }
            }
        }))
    };
    Ok(ctx.page(Nav::Routes, "Routes", body).into_response())
}

// -------------------- Shared form --------------------

#[derive(Default)]
struct FormValues<'a> {
    id: Option<i64>,
    name: &'a str,
    hosts: &'a str,
    upstream: &'a str,
    skip_verify: bool,
    service_id: Option<i64>,
    public_paths: &'a str,
}

/// `choices` is the approved services; a route still pointing at one that has
/// gone is offered it too, marked, so saving some other edit can't silently
/// flip the route open by falling back to the first option.
fn route_form(action: &str, submit: &str, v: &FormValues, choices: &[(i64, String, String)]) -> Markup {
    let current_missing = v.service_id.filter(|id| !choices.iter().any(|c| c.0 == *id));
    html! {
        form.form method="post" action=(action) data-gated=(if v.service_id.is_some() { "1" } else { "" }) {
            @if let Some(id) = v.id { input type="hidden" name="id" value=(id); }
            (field("Hostnames",
                Some("One per line. *.example.com covers every name under it. Point their DNS at bastion; the certificate has to cover them too."),
                html! { textarea.input name="hosts" rows="3" required autocapitalize="off" spellcheck="false"
                    placeholder="media.example.com\n*.apps.example.com" { (v.hosts) } }))
            div.grid-2 {
                (field("Upstream", Some("Where the app itself listens. http or https."),
                    html! { input.input.mono name="upstreamUrl" value=(v.upstream) required
                        placeholder="http://192.168.1.8:8096" autocapitalize="off" spellcheck="false"; }))
                (field("Name", Some("For this list and the logs. Defaults to the first hostname."),
                    html! { input.input name="name" value=(v.name); }))
            }
            (field("Access",
                Some("Gated: only people granted the service get through, and the app receives X-Bastion-User and friends. Needs a session cookie domain."),
                html! {
                    select.input name="serviceId" onchange="this.form.dataset.gated=this.value?'1':''" {
                        option value="" selected[v.service_id.is_none()] { "Open — anyone can reach it" }
                        @if let Some(id) = current_missing {
                            option value=(id) selected { "Gated by a removed service — pick again" }
                        }
                        @for (id, slug, name) in choices {
                            option value=(id) selected[v.service_id == Some(*id)] {
                                "Gated by " (slug) @if name != slug { " (" (name) ")" }
                            }
                        }
                    }
                }))
            div data-for="gated" {
                (field("Public paths", Some("One glob per line. Forwarded without the gate — health checks, webhooks."),
                    html! { textarea.input name="publicPaths" rows="3"
                        placeholder="/health\n/api/webhooks/*" { (v.public_paths) } }))
            }
            label.check {
                input type="checkbox" name="skipVerify" value="1" checked[v.skip_verify];
                span {
                    "Accept any certificate from the upstream"
                    span.h { "For an https upstream with a self-signed certificate. The hop is still encrypted, just not to anyone in particular." }
                }
            }
            div.form-actions {
                button.btn.primary type="submit" { (submit) }
            }
        }
    }
}

// -------------------- New --------------------

#[derive(Debug, Deserialize)]
pub struct NewRouteQuery {
    /// Pre-select a gate, from a service's "Add a route" link.
    pub service: Option<i64>,
}

pub async fn route_new_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<NewRouteQuery>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;
    let choices = gate_choices(&state).await?;
    let service_id = q.service.filter(|id| choices.iter().any(|c| c.0 == *id));
    let body = html! {
        (back("/admin/routes", "Routes"))
        (header(None, "New route", None, None))
        div.panel {
            (route_form("/admin/routes/add", "Create route",
                &FormValues { service_id, ..Default::default() }, &choices))
        }
    };
    Ok(ctx.page(Nav::Routes, "New route", body).into_response())
}

// -------------------- Detail --------------------

pub async fn route_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;
    #[allow(clippy::type_complexity)]
    let row: Option<(String, String, bool, bool, i64, Option<i64>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT r.name, r.upstream_url, r.tls_skip_verify, r.enabled, r.created_at,
                r.service_id, r.public_paths,
                (SELECT s.slug FROM services s WHERE s.id = r.service_id
                   AND s.deleted_at IS NULL AND s.status = 'approved')
         FROM routes r WHERE r.id = ?",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((name, upstream, skip_verify, enabled, created, service_id, public_paths, slug)) = row else {
        return Err(AppError::NotFound);
    };
    let hosts: Vec<(String,)> = sqlx::query_as("SELECT host FROM route_hosts WHERE route_id = ? ORDER BY host")
        .bind(id)
        .fetch_all(&state.pool)
        .await?;
    let hosts: Vec<String> = hosts.into_iter().map(|(h,)| h).collect();
    let choices = gate_choices(&state).await?;
    let access = Access::of(service_id, slug);
    let health = ProxyHealth::load(&state).await?;
    let id_s = id.to_string();

    let body = html! {
        (back("/admin/routes", "Routes"))
        (header(
            Some(tile(&name, "lg")),
            &name,
            Some(html! {
                (status_badge(if enabled { "enabled" } else { "disabled" }))
                (access.badge())
                span { "created " (fmt_time(created)) }
            }),
            Some(html! {
                (switch("/admin/routes/toggle", &[("id", &id_s)], enabled,
                    if enabled { "Disable route" } else { "Enable route" }))
            }),
        ))
        div.notices {
            @if matches!(access, Access::Gated(_)) { (health.notices()) }
            @if matches!(access, Access::Broken) {
                (notice(Tone::Bad, html! {
                    strong { "Closed." }
                    " The service gating this route has been removed, so every request gets a 503 "
                    "rather than going through ungated. Pick another service, or make it open."
                }))
            }
        }
        @if !enabled {
            p.sec-desc { "Disabled: its hostnames get a 404 until it's switched back on." }
        }

        (section("Configuration", None, None, html! {
            div.panel {
                (route_form("/admin/routes/update", "Save changes", &FormValues {
                    id: Some(id),
                    name: &name,
                    hosts: &hosts.join("\n"),
                    upstream: &upstream,
                    skip_verify,
                    service_id,
                    public_paths: public_paths.as_deref().unwrap_or(""),
                }, &choices))
            }
        }))

        (section("Danger zone", None, None, html! {
            div.panel.danger {
                div.inline-actions {
                    div.grow {
                        div { "Remove this route" }
                        div.hint { "Its hostnames stop being forwarded immediately." }
                    }
                    (Post::new("/admin/routes/remove", "Remove route").class("btn bad")
                        .fields(&[("id", &id_s)]).confirm("Remove this route?").render())
                }
            }
        }))
    };
    Ok(ctx.page(Nav::Routes, &name, body).into_response())
}

// -------------------- Mutations --------------------

#[derive(Debug, Deserialize)]
pub struct RouteForm {
    #[serde(default)]
    pub id: Option<i64>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub hosts: String,
    #[serde(rename = "upstreamUrl", default)]
    pub upstream_url: String,
    #[serde(rename = "skipVerify", default)]
    pub skip_verify: Option<String>,
    #[serde(rename = "serviceId", default)]
    pub service_id: String,
    #[serde(rename = "publicPaths", default)]
    pub public_paths: String,
}

struct RouteFields {
    name: String,
    hosts: Vec<String>,
    upstream: String,
    skip_verify: bool,
    service_id: Option<i64>,
    public_paths: Option<String>,
}

fn validate(f: &RouteForm, own_ports: &[u16]) -> Result<RouteFields, String> {
    let hosts = crate::edge::parse_hosts(&f.hosts)?;
    let upstream = crate::edge::validate_upstream(&f.upstream_url, &hosts, own_ports)?;
    let name = match f.name.trim() {
        "" => hosts[0].clone(),
        n => n.to_string(),
    };
    let service_id = match f.service_id.trim() {
        "" => None,
        s => Some(s.parse::<i64>().map_err(|_| "unknown service".to_string())?),
    };
    // Public paths are holes in a gate; on an open route there's no gate to
    // have holes in, and keeping stale ones would quietly reopen them the day
    // the route is gated again.
    let public_paths = service_id
        .and(Some(f.public_paths.trim()))
        .filter(|p| !p.is_empty())
        .map(str::to_string);
    Ok(RouteFields { name, hosts, upstream, skip_verify: f.skip_verify.is_some(), service_id, public_paths })
}

/// A gate has to be a live, approved service.
async fn refuse_dead_gate(state: &AppState, service_id: Option<i64>) -> AppResult<Option<String>> {
    let Some(id) = service_id else {
        return Ok(None);
    };
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT slug FROM services WHERE id = ? AND deleted_at IS NULL AND status = 'approved'",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    match row {
        Some((slug,)) => Ok(Some(slug)),
        None => Err(AppError::BadRequest(
            "that service no longer exists — pick another, or make the route open".into(),
        )),
    }
}

/// A gated hostname has to be under the session cookie domain, or the cookie
/// never reaches it and sign-in loops. With no domain set at all the gate
/// explains that itself, so there's nothing to check against yet.
async fn refuse_uncovered_hosts(state: &AppState, hosts: &[String], service_id: Option<i64>) -> AppResult<()> {
    if service_id.is_none() {
        return Ok(());
    }
    let Some(domain) = crate::settings::cookie_domain(&state.pool).await else {
        return Ok(());
    };
    let parent = domain.trim_start_matches('.');
    for h in hosts {
        let name = h.strip_prefix("*.").unwrap_or(h);
        if !crate::host::covers(parent, name) {
            return Err(AppError::BadRequest(format!(
                "{} isn't under the session cookie domain ({}), so sign-in can't reach it. \
                 Gate only hostnames under that domain, or leave this route open.",
                h, domain
            )));
        }
    }
    Ok(())
}

/// Refuse a name another route already holds, or bastion's own.
async fn refuse_claimed_hosts(state: &AppState, hosts: &[String], id: Option<i64>) -> AppResult<()> {
    let own = state.origin.as_deref().and_then(crate::host::of_url);
    for h in hosts {
        if own.as_deref() == Some(h.as_str()) {
            return Err(AppError::BadRequest(format!("{} is bastion's own hostname", h)));
        }
        if let Some(owner) = crate::edge::host_owner(&state.pool, h, id).await? {
            return Err(AppError::BadRequest(format!("{} is already served by route {}", h, owner)));
        }
    }
    Ok(())
}

async fn save_hosts(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: i64,
    hosts: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM route_hosts WHERE route_id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    for h in hosts {
        sqlx::query("INSERT INTO route_hosts (host, route_id) VALUES (?, ?)")
            .bind(h)
            .bind(id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

pub async fn add_route(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<RouteForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    let v = validate(&f, &state.ports).map_err(AppError::BadRequest)?;
    let gate = refuse_dead_gate(&state, v.service_id).await?;
    refuse_uncovered_hosts(&state, &v.hosts, v.service_id).await?;
    refuse_claimed_hosts(&state, &v.hosts, None).await?;

    let mut tx = state.pool.begin().await?;
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO routes (name, upstream_url, tls_skip_verify, service_id, public_paths)
         VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(&v.name)
    .bind(&v.upstream)
    .bind(v.skip_verify)
    .bind(v.service_id)
    .bind(&v.public_paths)
    .fetch_one(&mut *tx)
    .await?;
    save_hosts(&mut tx, id, &v.hosts).await?;
    tx.commit().await?;

    audit(
        &state.pool,
        Some(admin.id),
        "route.add",
        Some(&format!("route:{}", id)),
        Some(serde_json::json!({ "name": v.name, "hosts": v.hosts, "upstream": v.upstream, "gate": gate })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to(&format!("/admin/routes/{}", id)).into_response())
}

pub async fn update_route(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<RouteForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    let id = f.id.ok_or_else(|| AppError::BadRequest("missing route id".into()))?;
    let v = validate(&f, &state.ports).map_err(AppError::BadRequest)?;
    let gate = refuse_dead_gate(&state, v.service_id).await?;
    refuse_uncovered_hosts(&state, &v.hosts, v.service_id).await?;
    refuse_claimed_hosts(&state, &v.hosts, Some(id)).await?;

    let mut tx = state.pool.begin().await?;
    let updated = sqlx::query(
        "UPDATE routes SET name = ?, upstream_url = ?, tls_skip_verify = ?, service_id = ?, public_paths = ?
         WHERE id = ?",
    )
        .bind(&v.name)
        .bind(&v.upstream)
        .bind(v.skip_verify)
        .bind(v.service_id)
        .bind(&v.public_paths)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    save_hosts(&mut tx, id, &v.hosts).await?;
    tx.commit().await?;

    audit(
        &state.pool,
        Some(admin.id),
        "route.update",
        Some(&format!("route:{}", id)),
        Some(serde_json::json!({ "name": v.name, "hosts": v.hosts, "upstream": v.upstream, "gate": gate })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to(&format!("/admin/routes/{}", id)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct RouteIdForm {
    pub id: i64,
}

pub async fn toggle_route(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<RouteIdForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    let row: Option<(bool,)> = sqlx::query_as("UPDATE routes SET enabled = NOT enabled WHERE id = ? RETURNING enabled")
        .bind(f.id)
        .fetch_optional(&state.pool)
        .await?;
    let Some((enabled,)) = row else {
        return Err(AppError::NotFound);
    };
    audit(
        &state.pool,
        Some(admin.id),
        if enabled { "route.enable" } else { "route.disable" },
        Some(&format!("route:{}", f.id)),
        None,
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to(&format!("/admin/routes/{}", f.id)).into_response())
}

pub async fn remove_route(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<RouteIdForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    let row: Option<(String,)> = sqlx::query_as("DELETE FROM routes WHERE id = ? RETURNING name")
        .bind(f.id)
        .fetch_optional(&state.pool)
        .await?;
    if let Some((name,)) = row {
        audit(
            &state.pool,
            Some(admin.id),
            "route.remove",
            Some(&format!("route:{}", f.id)),
            Some(serde_json::json!({ "name": name })),
        )
        .await
        .map_err(AppError::Other)?;
    }
    Ok(Redirect::to("/admin/routes").into_response())
}
