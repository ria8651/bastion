use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use maud::html;
use serde::Deserialize;

use super::ui::{
    back, badge, empty, header, provider_icons, section, status_badge, switch, tile, user_avatar,
    Nav, Post, Tone,
};
use super::{admin, back_to, ctx, fmt_time, rel_time};
use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::models::UserCtx;
use crate::state::AppState;
use crate::templates::{provider_display_name, provider_icon};

// -------------------- List --------------------

pub async fn users_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(i64, Option<String>, String, Option<String>, String, bool, Option<i64>, i64, Option<String>)> =
        sqlx::query_as(
            "SELECT u.id, u.avatar, u.username, u.email, u.status, u.is_admin, u.last_login_at,
                    (SELECT COUNT(*) FROM grants g
                       JOIN services s ON s.id = g.service_id AND s.deleted_at IS NULL
                      WHERE g.user_id = u.id) AS svc_count,
                    (SELECT GROUP_CONCAT(DISTINCT ui.provider)
                       FROM user_identities ui WHERE ui.user_id = u.id) AS providers
             FROM users u
             ORDER BY u.status = 'pending' DESC, u.last_login_at IS NULL, u.last_login_at DESC",
        )
        .fetch_all(&state.pool)
        .await?;

    let pending = rows.iter().filter(|r| r.4 == "pending").count();
    let body = html! {
        (header(None, "Users", Some(html! {
            (rows.len()) " total"
            @if pending > 0 { " · " (pending) " pending" }
        }), None))
        @if rows.is_empty() {
            (empty("No users yet.", "People appear here after their first sign-in."))
        } @else {
            div.list {
                @for (id, avatar, username, email, status, is_admin, last, svc_count, providers) in &rows {
                    a.row href=(format!("/admin/users/{}", id)) {
                        span.lead { (user_avatar(avatar.as_deref(), username, "lg")) }
                        div.row-body {
                            div.main {
                                div.t { (username) }
                                div.s { (email.as_deref().unwrap_or("no email")) }
                            }
                            div.meta {
                                (provider_icons(providers.as_deref().unwrap_or("")))
                                @if *is_admin { (badge(Tone::Strong, "admin")) }
                                @if status != "active" { (status_badge(status)) }
                                span { (svc_count) " " (if *svc_count == 1 { "service" } else { "services" }) }
                                span title="last sign-in" { (last.map(rel_time).unwrap_or_else(|| "never".into())) }
                            }
                        }
                        span.chev { "›" }
                    }
                }
            }
        }
    };
    Ok(ctx.page(Nav::Users, "Users", body).into_response())
}

// -------------------- Detail --------------------

struct Perm {
    id: i64,
    key: String,
    description: Option<String>,
    held: bool,
    default_allow: bool,
}

pub async fn user_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;

    #[allow(clippy::type_complexity)]
    let u: Option<(String, Option<String>, Option<String>, String, bool, i64, Option<i64>, String, String)> =
        sqlx::query_as(
            "SELECT username, email, avatar, status, is_admin, created_at, last_login_at,
                    sub_anchor_provider, sub_anchor_provider_id
             FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    let Some((uname, email, avatar_url, status, is_admin, created, last, anchor_p, anchor_id)) = u
    else {
        return Err(AppError::NotFound);
    };
    let is_self = ctx.viewer.id == id;

    let identities: Vec<(String, String, Option<String>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT provider, provider_id, email, linked_at, last_login_at
         FROM user_identities WHERE user_id = ? ORDER BY linked_at",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;

    let services: Vec<(i64, String, String, String, bool)> = sqlx::query_as(
        "SELECT s.id, s.slug, s.name, s.mode,
                EXISTS(SELECT 1 FROM grants g WHERE g.user_id = ? AND g.service_id = s.id)
         FROM services s
         WHERE s.deleted_at IS NULL AND s.status = 'approved'
         ORDER BY s.slug",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;

    let perm_rows: Vec<(i64, i64, String, Option<String>, bool, bool)> = sqlx::query_as(
        "SELECT p.service_id, p.id, p.key, p.description,
                EXISTS(SELECT 1 FROM user_perms up
                       WHERE up.user_id = ? AND up.permission_id = p.id),
                p.default_allow
         FROM permissions p
         JOIN services s ON s.id = p.service_id
         WHERE p.removed_at IS NULL AND s.deleted_at IS NULL AND s.status = 'approved'
         ORDER BY p.service_id, p.key",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let mut perms: HashMap<i64, Vec<Perm>> = HashMap::new();
    for (sid, pid, key, description, held, default_allow) in perm_rows {
        perms.entry(sid).or_default().push(Perm { id: pid, key, description, held, default_allow });
    }

    let requests: Vec<(Option<String>, Option<String>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT s.slug, r.decision, r.requested_at, r.resolved_at
         FROM access_requests r LEFT JOIN services s ON s.id = r.service_id
         WHERE r.user_id = ? ORDER BY r.requested_at DESC",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;

    let (active_sessions,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions
         WHERE user_id = ? AND revoked_at IS NULL AND expires_at > unixepoch()",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    let id_s = id.to_string();
    let here = format!("/admin/users/{}", id);
    let granted_n = services.iter().filter(|s| s.4).count();
    let grant_action = format!("/admin/users/{}/toggle-grant", id);
    let perm_action = format!("/admin/users/{}/toggle-perm", id);
    let revoke_action = format!("/admin/users/{}/revoke-sessions", id);

    let body = html! {
        (back("/admin/users", "Users"))
        (header(
            Some(user_avatar(avatar_url.as_deref(), &uname, "xl")),
            &uname,
            Some(html! {
                (status_badge(&status))
                @if is_admin { (badge(Tone::Strong, "admin")) }
                span { (email.as_deref().unwrap_or("no email")) }
            }),
            None,
        ))

        (section("Account", None, None, html! {
            div.list {
                div.row {
                    div.row-body {
                        div.main {
                            div.t { "Status" }
                            div.s {
                                @match status.as_str() {
                                    "active" => "can sign in and use granted services",
                                    "pending" => "signed in, waiting for approval",
                                    _ => "blocked from signing in",
                                }
                            }
                        }
                    }
                    @if !is_self {
                        div.end {
                            @if status != "denied" {
                                (Post::new("/admin/users/set-status", if status == "pending" { "Deny" } else { "Block" })
                                    .class("btn sm bad")
                                    .fields(&[("id", &id_s), ("status", "denied"), ("next", &here)])
                                    .confirm("Block this user? They will be unable to sign in.")
                                    .render())
                            }
                            @if status != "active" {
                                (Post::new("/admin/users/set-status", if status == "pending" { "Approve" } else { "Unblock" })
                                    .class("btn sm primary")
                                    .fields(&[("id", &id_s), ("status", "active"), ("next", &here)])
                                    .render())
                            }
                        }
                    }
                }
                div.row {
                    div.row-body {
                        div.main {
                            div.t { "Role" }
                            div.s { @if is_admin { "admin — full access to this panel" } @else { "user" } }
                        }
                    }
                    @if !is_self {
                        div.end {
                            @if is_admin {
                                (Post::new("/admin/users/set-admin", "Remove admin")
                                    .fields(&[("id", &id_s), ("is_admin", "0"), ("next", &here)])
                                    .render())
                            } @else {
                                (Post::new("/admin/users/set-admin", "Make admin")
                                    .fields(&[("id", &id_s), ("is_admin", "1"), ("next", &here)])
                                    .confirm("Make this user an admin? They will be able to change everything here.")
                                    .render())
                            }
                        }
                    }
                }
                div.row {
                    div.row-body {
                        div.main {
                            div.t { "Sessions" }
                            div.s { (active_sessions) " active" }
                        }
                    }
                    @if active_sessions > 0 {
                        div.end {
                            (Post::new(&revoke_action, "Sign out everywhere")
                                .class("btn sm bad")
                                .confirm(if is_self {
                                    "Revoke all your sessions? That includes this one — you'll be signed out."
                                } else {
                                    "Revoke all of this user's sessions? They'll have to sign in again."
                                })
                                .render())
                        }
                    }
                }
            }
        }))

        (section("Service access", None, Some(html! { (granted_n) " of " (services.len()) " granted" }), html! {
            @if services.is_empty() {
                (empty("No services yet.", ""))
            } @else {
                div.list {
                    @for (sid, slug, name, mode, granted) in &services {
                        @let sid_s = sid.to_string();
                        @let ps = perms.get(sid).map(Vec::as_slice).unwrap_or(&[]);
                        @let held = ps.iter().filter(|p| p.held).count();
                        div.row {
                            a.lead href=(format!("/admin/services/{}", sid)) { (tile(slug, "")) }
                            div.row-body {
                                div.main {
                                    div.t { a href=(format!("/admin/services/{}", sid)) { (slug) } }
                                    div.s {
                                        (name)
                                        @if mode == "proxy" { " · proxy" }
                                    }
                                }
                                div.meta {
                                    @if *granted && !ps.is_empty() {
                                        span { (held) "/" (ps.len()) " permissions" }
                                    }
                                    @if *granted { (status_badge("granted")) }
                                }
                            }
                            div.end {
                                @if *granted {
                                    (Post::new(&grant_action, "Revoke").class("btn sm bad")
                                        .fields(&[("service_id", &sid_s), ("grant", "0")])
                                        .stay().render())
                                } @else {
                                    (Post::new(&grant_action, "Grant").class("btn sm")
                                        .fields(&[("service_id", &sid_s), ("grant", "1")])
                                        .stay().render())
                                }
                            }
                        }
                        @if *granted && !ps.is_empty() {
                            div.sub-list {
                                @for p in ps {
                                    @let pid = p.id.to_string();
                                    div.sub-row {
                                        (switch(&perm_action,
                                            &[("permission_id", &pid), ("grant", if p.held { "0" } else { "1" })],
                                            p.held, &p.key))
                                        div {
                                            span.k { (p.key) }
                                            @if p.default_allow { " " (badge(Tone::Quiet, "default")) }
                                            @if let Some(d) = &p.description { div.d { (d) } }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }))

        (section("Linked identities", Some(identities.len()), None, html! {
            div.list {
                @for (prov, pid, iemail, linked, ilast) in &identities {
                    div.row {
                        span.lead { span.ico.md { (provider_icon(prov)) } }
                        div.row-body {
                            div.main {
                                div.t {
                                    (provider_display_name(prov))
                                }
                                div.s { (iemail.as_deref().unwrap_or("no email")) " · id " (pid) }
                            }
                            div.meta {
                                @if *prov == anchor_p && *pid == anchor_id {
                                    span title="The JWT `sub` is derived from this identity and never changes" {
                                        (badge(Tone::Quiet, "sub anchor"))
                                    }
                                }
                                span title=(format!("linked {}", fmt_time(*linked))) {
                                    (ilast.map(rel_time).unwrap_or_else(|| "never used".into()))
                                }
                            }
                        }
                    }
                }
            }
        }))

        @if !requests.is_empty() {
            (section("Access requests", Some(requests.len()), None, html! {
                div.list {
                    @for (slug, decision, at, resolved) in &requests {
                        div.row {
                            div.row-body {
                                div.main {
                                    div.t { (slug.as_deref().unwrap_or("account")) }
                                    div.s { "requested " (fmt_time(*at)) }
                                }
                                div.meta {
                                    @match (resolved.is_some(), decision.as_deref()) {
                                        (true, Some("approved")) => (status_badge("granted")),
                                        (true, Some("denied")) => (status_badge("denied")),
                                        (true, _) => (badge(Tone::Quiet, "resolved")),
                                        _ => (status_badge("pending")),
                                    }
                                }
                            }
                        }
                    }
                }
            }))
        }

        (section("Details", None, None, html! {
            div.panel {
                dl.kv {
                    dt { "User id" } dd { (id) }
                    dt { "Sub anchor" } dd { (anchor_p) "/" (anchor_id) }
                    dt { "Joined" } dd { (fmt_time(created)) }
                    dt { "Last sign-in" } dd { (last.map(fmt_time).unwrap_or_else(|| "never".into())) }
                }
            }
        }))
    };
    Ok(ctx.page(Nav::Users, &uname, body).into_response())
}

// -------------------- Mutations --------------------

#[derive(Debug, Deserialize)]
pub struct SetStatusForm {
    pub id: i64,
    pub status: String,
    pub next: Option<String>,
}

pub async fn set_status(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<SetStatusForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    if !matches!(f.status.as_str(), "active" | "pending" | "denied") {
        return Err(AppError::BadRequest("bad status".into()));
    }
    if f.id == admin.id && f.status != "active" {
        return Err(AppError::BadRequest("can't change your own status".into()));
    }
    sqlx::query("UPDATE users SET status = ? WHERE id = ?")
        .bind(&f.status)
        .bind(f.id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(admin.id),
        "user.status",
        Some(&format!("user:{}", f.id)),
        Some(serde_json::json!({ "status": f.status })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(back_to(f.next.as_deref(), &format!("/admin/users/{}", f.id)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct SetAdminForm {
    pub id: i64,
    pub is_admin: i32,
    pub next: Option<String>,
}

pub async fn set_admin(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<SetAdminForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    if f.id == admin.id && f.is_admin == 0 {
        return Err(AppError::BadRequest("can't demote yourself".into()));
    }
    let want = if f.is_admin == 0 { 0i64 } else { 1i64 };
    sqlx::query("UPDATE users SET is_admin = ? WHERE id = ?")
        .bind(want)
        .bind(f.id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(admin.id),
        "user.admin",
        Some(&format!("user:{}", f.id)),
        Some(serde_json::json!({ "is_admin": want == 1 })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(back_to(f.next.as_deref(), &format!("/admin/users/{}", f.id)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct ToggleGrantForm {
    pub service_id: i64,
    pub grant: i32,
}

#[derive(Debug, Deserialize)]
pub struct TogglePermForm {
    pub permission_id: i64,
    pub grant: i32,
}

pub async fn toggle_grant(
    State(state): State<AppState>,
    Path(uid): Path<i64>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<ToggleGrantForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    if f.grant == 1 {
        sqlx::query(
            "INSERT INTO grants (user_id, service_id, granted_by) VALUES (?, ?, ?)
             ON CONFLICT(user_id, service_id) DO NOTHING",
        )
        .bind(uid)
        .bind(f.service_id)
        .bind(admin.id)
        .execute(&state.pool)
        .await?;
        crate::routes::registration::apply_default_perms(&state.pool, uid, f.service_id).await?;
        sqlx::query(
            "UPDATE access_requests SET resolved_at = unixepoch(), resolved_by = ?, decision = 'approved'
             WHERE user_id = ? AND service_id = ? AND resolved_at IS NULL",
        )
        .bind(admin.id)
        .bind(uid)
        .bind(f.service_id)
        .execute(&state.pool)
        .await?;
        audit(
            &state.pool,
            Some(admin.id),
            "grant.add",
            Some(&format!("user:{}", uid)),
            Some(serde_json::json!({ "serviceId": f.service_id })),
        )
        .await
        .map_err(AppError::Other)?;
    } else {
        sqlx::query("DELETE FROM grants WHERE user_id = ? AND service_id = ?")
            .bind(uid)
            .bind(f.service_id)
            .execute(&state.pool)
            .await?;
        audit(
            &state.pool,
            Some(admin.id),
            "grant.remove",
            Some(&format!("user:{}", uid)),
            Some(serde_json::json!({ "serviceId": f.service_id })),
        )
        .await
        .map_err(AppError::Other)?;
    }
    Ok(Redirect::to(&format!("/admin/users/{}", uid)).into_response())
}

pub async fn toggle_perm(
    State(state): State<AppState>,
    Path(uid): Path<i64>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<TogglePermForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;

    let row: Option<(i64, String, Option<i64>)> =
        sqlx::query_as("SELECT service_id, key, removed_at FROM permissions WHERE id = ?")
            .bind(f.permission_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((service_id, key, removed)) = row else {
        return Err(AppError::BadRequest("permission not found".into()));
    };
    if removed.is_some() {
        return Err(AppError::BadRequest(
            "permission was removed by the service and can't be granted".into(),
        ));
    }

    if f.grant == 1 {
        sqlx::query(
            "INSERT INTO user_perms (user_id, permission_id) VALUES (?, ?)
             ON CONFLICT(user_id, permission_id) DO NOTHING",
        )
        .bind(uid)
        .bind(f.permission_id)
        .execute(&state.pool)
        .await?;
    } else {
        sqlx::query("DELETE FROM user_perms WHERE user_id = ? AND permission_id = ?")
            .bind(uid)
            .bind(f.permission_id)
            .execute(&state.pool)
            .await?;
    }
    audit(
        &state.pool,
        Some(admin.id),
        if f.grant == 1 { "perm.grant" } else { "perm.revoke" },
        Some(&format!("user:{}", uid)),
        Some(serde_json::json!({
            "serviceId": service_id,
            "permissionId": f.permission_id,
            "key": key,
        })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to(&format!("/admin/users/{}", uid)).into_response())
}

pub async fn revoke_sessions(
    State(state): State<AppState>,
    Path(uid): Path<i64>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let admin = admin(user)?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(uid)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(admin.id),
        "session.revoke_all",
        Some(&format!("user:{}", uid)),
        None,
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to(&format!("/admin/users/{}", uid)).into_response())
}
