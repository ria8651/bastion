use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use chrono::{TimeZone, Utc};
use maud::{html, Markup};
use serde::Deserialize;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::require_admin;
use crate::models::UserCtx;
use crate::state::{origin_from, AppState};
use crate::templates::{
    admin_header, admin_shell, github_svg, host_from_origin, pill, status_pill, AdminCounts,
    AdminTab,
};

fn fmt_time(unix: i64) -> String {
    Utc.timestamp_opt(unix, 0)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

fn rel_time(unix: i64) -> String {
    let now = Utc::now().timestamp();
    let d = now - unix;
    if d < 60 {
        format!("{}s ago", d.max(0))
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86400 {
        format!("{}h ago", d / 3600)
    } else if d < 86400 * 14 {
        format!("{}d ago", d / 86400)
    } else if d < 86400 * 60 {
        format!("{}w ago", d / (86400 * 7))
    } else {
        format!("{}mo ago", d / (86400 * 30))
    }
}

async fn load_counts(state: &AppState) -> AppResult<AdminCounts> {
    let (users,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pool)
        .await?;
    let (requests,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM access_requests WHERE resolved_at IS NULL")
            .fetch_one(&state.pool)
            .await?;
    let (services,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM services WHERE deleted_at IS NULL")
            .fetch_one(&state.pool)
            .await?;
    Ok(AdminCounts {
        users: Some(users),
        requests: if requests > 0 { Some(requests) } else { None },
        services: Some(services),
    })
}

pub async fn index_redirect() -> Redirect {
    Redirect::to("/admin/users")
}

// -------------------- Users --------------------

pub async fn users_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;
    let user = user.unwrap();
    let host = host_from_origin(&origin_from(&state, &headers)).to_string();
    let counts = load_counts(&state).await?;

    let rows: Vec<(i64, Option<String>, String, Option<String>, String, bool, Option<i64>, i64)> =
        sqlx::query_as(
            "SELECT u.id, u.avatar, u.username, u.email, u.status, u.is_admin, u.last_login_at,
                    (SELECT COUNT(*) FROM grants g WHERE g.user_id = u.id) AS svc_count
             FROM users u ORDER BY u.created_at DESC",
        )
        .fetch_all(&state.pool)
        .await?;

    let total = rows.len();
    let meta = format!("{} total · 1 provider", total);
    let action = html! {
        span.btn.text style="cursor:default" title="not implemented yet" { "+ invite" }
    };

    let body = html! {
        (admin_header("Users", Some(&meta), Some(action)))
        p.admin-desc {
            "Linked accounts. Each user is bound to the identity provider they first signed in with."
        }
        div.filter-row {
            input.input.mono style="width:280px" placeholder="filter user…";
            span.sort { "sort: last seen" }
        }
        div.table-wrap {
            table {
                thead {
                    tr {
                        th { "Account" }
                        th { "Provider" }
                        th { "Status" }
                        th { "Role" }
                        th { "Services" }
                        th { "Last seen" }
                        th {}
                    }
                }
                tbody {
                    @for (id, avatar_url, username, email, status, is_admin, last, svc_count) in &rows {
                        tr {
                            td {
                                a href=(format!("/admin/users/{}", id)) style="display:flex;align-items:center;gap:12px;color:var(--fg)" {
                                    span.avatar {
                                        @if let Some(a) = avatar_url {
                                            img src=(a) alt="" referrerpolicy="no-referrer";
                                        } @else {
                                            (username.chars().take(2).collect::<String>().to_lowercase())
                                        }
                                    }
                                    div {
                                        div { (username) }
                                        div.mono style="font-size:11px;color:var(--fg-mute)" {
                                            (email.as_deref().unwrap_or("—"))
                                        }
                                    }
                                }
                            }
                            td {
                                span style="display:inline-flex;align-items:center;gap:8px;color:var(--fg-mid)" {
                                    span style="width:14px;height:14px;display:inline-flex" { (github_svg()) }
                                    span.mono style="font-size:12px" { "github" }
                                }
                            }
                            td { (status_pill(status)) }
                            td {
                                @if *is_admin {
                                    (pill("admin", "admin"))
                                } @else {
                                    span style="font-size:13px;color:var(--fg-mid)" { "user" }
                                }
                            }
                            td.mono style="font-size:13px;color:var(--fg-mid)" { (svc_count) }
                            td.mono style="font-size:12px;color:var(--fg-mute)" {
                                (last.map(rel_time).unwrap_or_else(|| "—".into()))
                            }
                            td style="text-align:right" {
                                div.row-actions style="justify-content:flex-end" {
                                    @if status != "active" {
                                        form method="post" action="/admin/users/set-status" style="margin:0" {
                                            input type="hidden" name="id" value=(id);
                                            input type="hidden" name="status" value="active";
                                            button.btn.primary type="submit" style="padding:4px 10px;font-size:12px" { "Approve" }
                                        }
                                    }
                                    @if status != "denied" {
                                        form method="post" action="/admin/users/set-status" style="margin:0" {
                                            input type="hidden" name="id" value=(id);
                                            input type="hidden" name="status" value="denied";
                                            button.btn.danger type="submit" style="padding:4px 10px;font-size:12px" { "Deny" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    Ok(admin_shell(AdminTab::Users, &user, &host, counts, body).into_response())
}

#[derive(Debug, Deserialize)]
pub struct SetStatusForm {
    pub id: i64,
    pub status: String,
}

pub async fn set_status(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<SetStatusForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
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
    Ok(Redirect::to("/admin/users").into_response())
}

#[derive(Debug, Deserialize)]
pub struct SetAdminForm {
    pub id: i64,
    pub is_admin: i32,
}

pub async fn set_admin(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<SetAdminForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
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
    Ok(Redirect::to("/admin/users").into_response())
}

// -------------------- User detail --------------------

pub async fn user_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;
    let viewer = user.unwrap();
    let host = host_from_origin(&origin_from(&state, &headers)).to_string();
    let counts = load_counts(&state).await?;

    let u: Option<(i64, i64, String, Option<String>, Option<String>, String, bool, i64, Option<i64>)> =
        sqlx::query_as(
            "SELECT id, github_id, username, email, avatar, status, is_admin, created_at, last_login_at
             FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    let Some((uid, gh, uname, email, avatar_url, status, is_admin, _created, last)) = u else {
        return Err(AppError::NotFound);
    };

    let services: Vec<(i64, String, String, bool)> = sqlx::query_as(
        "SELECT s.id, s.slug, s.name,
                EXISTS(SELECT 1 FROM grants g WHERE g.user_id = ? AND g.service_id = s.id) as granted
         FROM services s WHERE s.deleted_at IS NULL ORDER BY s.slug",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;

    let requests: Vec<(i64, Option<String>, Option<String>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT r.id, s.slug, r.decision, r.requested_at, r.resolved_at
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

    let meta = format!(
        "github_id={} · {}",
        gh,
        email.as_deref().unwrap_or("no email")
    );

    let body = html! {
        (admin_header(&uname, Some(&meta), None))
        p.admin-desc {
            (status_pill(&status)) " "
            @if is_admin { (pill("admin", "admin")) " " }
            "last login " (last.map(fmt_time).unwrap_or_else(|| "never".into()))
            @if let Some(a) = &avatar_url {
                " · "
                img src=(a) style="width:24px;height:24px;border-radius:50%;vertical-align:middle";
            }
        }

        h2 style="font-size:14px;margin-top:24px;margin-bottom:12px;font-family:var(--font-mono);color:var(--fg-mute);text-transform:uppercase;letter-spacing:0.06em" { "Service grants" }
        div.table-wrap {
            table {
                thead { tr { th { "Service" } th { "Granted" } th {} } }
                tbody {
                    @for (sid, slug, name, granted) in &services {
                        tr {
                            td {
                                div.mono style="font-weight:500" { (slug) }
                                div.mono style="font-size:11px;color:var(--fg-mute)" { (name) }
                            }
                            td {
                                @if *granted { (pill("active", "yes")) } @else { span.pill { "no" } }
                            }
                            td style="text-align:right" {
                                form method="post" action=(format!("/admin/users/{}/toggle-grant", uid)) style="margin:0" {
                                    input type="hidden" name="service_id" value=(sid);
                                    input type="hidden" name="grant" value=(if *granted { "0" } else { "1" });
                                    button.btn type="submit" {
                                        @if *granted { "Revoke" } @else { "Grant" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        h2 style="font-size:14px;margin-top:32px;margin-bottom:12px;font-family:var(--font-mono);color:var(--fg-mute);text-transform:uppercase;letter-spacing:0.06em" { "Access requests" }
        @if requests.is_empty() {
            p.muted style="font-size:13px" { "None." }
        } @else {
            div.table-wrap {
                table {
                    thead { tr { th { "Service" } th { "Requested" } th { "Status" } } }
                    tbody {
                        @for (_rid, slug, decision, ra, resolved) in &requests {
                            tr {
                                td.mono style="font-size:13px" { (slug.as_deref().unwrap_or("—")) }
                                td.mono style="font-size:12px;color:var(--fg-mute)" { (fmt_time(*ra)) }
                                td {
                                    @if resolved.is_some() {
                                        @match decision.as_deref() {
                                            Some("approved") => (pill("active", "approved")),
                                            Some("denied")   => (pill("denied", "denied")),
                                            _ => span.pill { "—" },
                                        }
                                    } @else {
                                        (pill("pending", "pending"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        h2 style="font-size:14px;margin-top:32px;margin-bottom:12px;font-family:var(--font-mono);color:var(--fg-mute);text-transform:uppercase;letter-spacing:0.06em" { "Role & sessions" }
        div.row-actions {
            @if viewer.id != uid {
                form method="post" action="/admin/users/set-admin" style="margin:0" {
                    input type="hidden" name="id" value=(uid);
                    input type="hidden" name="is_admin" value=(if is_admin { "0" } else { "1" });
                    button.btn type="submit" {
                        @if is_admin { "Demote from admin" } @else { "Promote to admin" }
                    }
                }
            }
            form method="post" action=(format!("/admin/users/{}/revoke-sessions", uid)) style="margin:0" {
                button.btn.danger type="submit" { "Revoke all sessions" "(" (active_sessions) ")" }
            }
        }
    };
    Ok(admin_shell(AdminTab::Users, &viewer, &host, counts, body).into_response())
}

#[derive(Debug, Deserialize)]
pub struct IdForm {
    pub id: i64,
}

#[derive(Debug, Deserialize)]
pub struct ToggleGrantForm {
    pub service_id: i64,
    pub grant: i32,
}

pub async fn toggle_grant(
    State(state): State<AppState>,
    Path(uid): Path<i64>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<ToggleGrantForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
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

pub async fn revoke_sessions(
    State(state): State<AppState>,
    Path(uid): Path<i64>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
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

// -------------------- Requests --------------------

#[derive(Debug, Deserialize)]
pub struct RequestsQuery {
    pub filter: Option<String>,
}

pub async fn requests_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
    axum::extract::Query(q): axum::extract::Query<RequestsQuery>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;
    let viewer = user.unwrap();
    let host = host_from_origin(&origin_from(&state, &headers)).to_string();
    let counts = load_counts(&state).await?;

    let filter = q.filter.as_deref().unwrap_or("pending");
    let where_clause = match filter {
        "granted" => "r.resolved_at IS NOT NULL AND r.decision = 'approved'",
        "denied" => "r.resolved_at IS NOT NULL AND r.decision = 'denied'",
        "all" => "1=1",
        _ => "r.resolved_at IS NULL",
    };
    let sql = format!(
        "SELECT r.id, u.id, u.username, u.avatar, s.slug, r.requested_at, r.resolved_at, r.decision, u.created_at
         FROM access_requests r
         JOIN users u ON u.id = r.user_id
         LEFT JOIN services s ON s.id = r.service_id
         WHERE {}
         ORDER BY r.requested_at DESC LIMIT 80",
        where_clause
    );
    let rows: Vec<(i64, i64, String, Option<String>, Option<String>, i64, Option<i64>, Option<String>, i64)> =
        sqlx::query_as(&sql).fetch_all(&state.pool).await?;

    let (pending_n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM access_requests WHERE resolved_at IS NULL",
    )
    .fetch_one(&state.pool)
    .await?;
    let (granted_n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM access_requests WHERE decision = 'approved'",
    )
    .fetch_one(&state.pool)
    .await?;
    let (denied_n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM access_requests WHERE decision = 'denied'",
    )
    .fetch_one(&state.pool)
    .await?;
    let total_n = pending_n + granted_n + denied_n;

    let (this_week_resolved,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM access_requests
         WHERE resolved_at IS NOT NULL AND resolved_at > unixepoch() - 7*86400",
    )
    .fetch_one(&state.pool)
    .await?;
    let meta = format!("{} pending · {} resolved this week", pending_n, this_week_resolved);

    let body = html! {
        (admin_header("Access requests", Some(&meta), None))
        p.admin-desc {
            "Users wanting into a registered service. Approve to mint a grant; deny to mark the request rejected."
        }

        div.filter-row {
            div.seg {
                (seg_item("pending", pending_n, filter == "pending"))
                (seg_item("granted", granted_n, filter == "granted"))
                (seg_item("denied", denied_n, filter == "denied"))
                (seg_item("all", total_n, filter == "all"))
            }
            span.sort { "sort: newest first" }
        }

        @if rows.is_empty() {
            div.empty-card {
                div.title { "Nothing here." }
                div.sub { "no access requests match this filter" }
            }
        } @else {
            div.req-grid {
                @for (rid, _uid, uname, uavatar, slug, ra, resolved, decision, created) in &rows {
                    div.req-card {
                        div.req-head {
                            span.avatar.lg {
                                @if let Some(a) = uavatar {
                                    img src=(a) alt="" referrerpolicy="no-referrer";
                                } @else {
                                    (uname.chars().take(2).collect::<String>().to_lowercase())
                                }
                            }
                            div.info {
                                div.uname { (uname) }
                                div.via {
                                    span style="display:inline-flex;width:11px;height:11px" { (github_svg()) }
                                    span { "via github" }
                                }
                            }
                            @match (resolved.is_some(), decision.as_deref()) {
                                (true, Some("approved")) => (pill("active", "granted")),
                                (true, Some("denied")) => (pill("denied", "denied")),
                                _ => (pill("pending", "pending")),
                            }
                        }
                        div.req-body {
                            "wants access to "
                            span.target { (slug.as_deref().unwrap_or("—")) }
                        }
                        div.req-meta {
                            div {
                                div.lbl { "account age" }
                                div.val { (rel_time(*created).replace(" ago", "")) }
                            }
                            div {
                                div.lbl { "requested" }
                                div.val { (rel_time(*ra)) }
                            }
                        }
                        @if resolved.is_none() {
                            div.req-actions {
                                form method="post" action="/admin/requests/approve" {
                                    input type="hidden" name="id" value=(rid);
                                    button.btn.primary type="submit" { "Approve" }
                                }
                                form method="post" action="/admin/requests/deny" {
                                    input type="hidden" name="id" value=(rid);
                                    button.btn.danger type="submit" { "Deny" }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    Ok(admin_shell(AdminTab::Requests, &viewer, &host, counts, body).into_response())
}

fn seg_item(label: &str, n: i64, active: bool) -> Markup {
    let class = if active { "seg-item active" } else { "seg-item" };
    let href = format!("/admin/requests?filter={}", label);
    html! {
        a class=(class) href=(href) {
            span { (label) }
            span.n { (n) }
        }
    }
}

pub async fn approve_request(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<IdForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();

    let req: Option<(i64, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT user_id, service_id, resolved_at FROM access_requests WHERE id = ?",
    )
    .bind(f.id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((uid, svc_id, resolved)) = req else {
        return Err(AppError::BadRequest("not found".into()));
    };
    if resolved.is_some() {
        return Err(AppError::BadRequest("already resolved".into()));
    }
    sqlx::query("UPDATE users SET status = 'active' WHERE id = ?")
        .bind(uid)
        .execute(&state.pool)
        .await?;
    if let Some(sid) = svc_id {
        sqlx::query(
            "INSERT INTO grants (user_id, service_id, granted_by) VALUES (?, ?, ?)
             ON CONFLICT(user_id, service_id) DO NOTHING",
        )
        .bind(uid)
        .bind(sid)
        .bind(admin.id)
        .execute(&state.pool)
        .await?;
    }
    sqlx::query(
        "UPDATE access_requests SET resolved_at = unixepoch(), resolved_by = ?, decision = 'approved'
         WHERE id = ?",
    )
    .bind(admin.id)
    .bind(f.id)
    .execute(&state.pool)
    .await?;
    audit(
        &state.pool,
        Some(admin.id),
        "request.approve",
        Some(&format!("request:{}", f.id)),
        Some(serde_json::json!({ "userId": uid, "serviceId": svc_id })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/admin/requests").into_response())
}

pub async fn deny_request(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<IdForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();

    let req: Option<(i64, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT user_id, service_id, resolved_at FROM access_requests WHERE id = ?",
    )
    .bind(f.id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((uid, svc_id, resolved)) = req else {
        return Err(AppError::BadRequest("not found".into()));
    };
    if resolved.is_some() {
        return Err(AppError::BadRequest("already resolved".into()));
    }
    sqlx::query(
        "UPDATE access_requests SET resolved_at = unixepoch(), resolved_by = ?, decision = 'denied'
         WHERE id = ?",
    )
    .bind(admin.id)
    .bind(f.id)
    .execute(&state.pool)
    .await?;
    audit(
        &state.pool,
        Some(admin.id),
        "request.deny",
        Some(&format!("request:{}", f.id)),
        Some(serde_json::json!({ "userId": uid, "serviceId": svc_id })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/admin/requests").into_response())
}

// -------------------- Services --------------------

pub async fn services_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;
    let viewer = user.unwrap();
    let host = host_from_origin(&origin_from(&state, &headers)).to_string();
    let counts = load_counts(&state).await?;

    let rows: Vec<(i64, String, String, String, i64)> = sqlx::query_as(
        "SELECT s.id, s.slug, s.name, s.return_url,
                (SELECT COUNT(*) FROM grants g WHERE g.service_id = s.id) AS user_count
         FROM services s WHERE s.deleted_at IS NULL ORDER BY s.slug",
    )
    .fetch_all(&state.pool)
    .await?;

    let (total_grants,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM grants")
        .fetch_one(&state.pool)
        .await?;
    let meta = format!("{} registered · {} grants", rows.len(), total_grants);
    let action = html! {
        a.btn href="#add-service" { "+ register service" }
    };

    let body = html! {
        (admin_header("Services", Some(&meta), Some(action)))
        p.admin-desc {
            "Apps that consume bastion-issued JWTs. Each service has a registered return URL and an explicit grant list."
        }

        div.filter-row {
            input.input.mono style="width:240px" placeholder="filter service…";
            span.sort { "sort: alphabetical" }
        }

        div.table-wrap {
            table {
                thead {
                    tr {
                        th { "Service" }
                        th { "Return URL" }
                        th { "Grants" }
                        th { "Perms" }
                        th {}
                    }
                }
                tbody {
                    @for (id, slug, name, ret, n) in &rows {
                        tr {
                            td {
                                div.mono style="font-size:13px;font-weight:500" { (slug) }
                                div.mono style="font-size:11px;color:var(--fg-mute)" { "aud:" (slug) " · " (name) }
                            }
                            td.mono style="font-size:12px;color:var(--fg-mid);max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" {
                                (ret)
                            }
                            td.mono style="font-size:13px;color:var(--fg)" { (n) }
                            td.mono style="font-size:13px;color:var(--fg-dim)" { "0" }
                            td style="text-align:right" {
                                button.btn.text type="button"
                                    onclick={
                                        "var r=this.closest('tr').nextElementSibling;"
                                        "r.style.display = (r.style.display === 'table-row' ? 'none' : 'table-row');"
                                    } { "edit" }
                            }
                        }
                        tr style="display:none;background:var(--bg-elev)" {
                            td colspan="5" {
                                form method="post" action="/admin/services/update" style="display:grid;gap:10px;max-width:520px" {
                                    input type="hidden" name="id" value=(id);
                                    label.field { "Slug" input.input name="slug" value=(slug) required; }
                                    label.field { "Name" input.input name="name" value=(name); }
                                    label.field { "Return URL" input.input name="returnUrl" value=(ret) required type="url"; }
                                    div.row-actions style="margin-top:6px" {
                                        button.btn.primary type="submit" { "Save" }
                                        button.btn.danger type="submit"
                                            formaction="/admin/services/remove"
                                            formnovalidate
                                            onclick="return confirm('Remove this service? Existing grants will also be removed.')"
                                            { "Remove" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        h2 id="add-service" style="font-size:14px;margin-top:32px;margin-bottom:12px;font-family:var(--font-mono);color:var(--fg-mute);text-transform:uppercase;letter-spacing:0.06em" { "Register a new service" }
        div.table-wrap style="padding:20px;background:var(--bg-elev)" {
            form method="post" action="/admin/services/add" style="display:grid;gap:10px;max-width:520px" {
                label.field { "Slug (lowercase, dashes ok)" input.input name="slug" required title="lowercase letters, digits, and hyphens"; }
                label.field { "Name" input.input name="name"; }
                label.field { "Return URL" input.input name="returnUrl" required type="url"; }
                div style="margin-top:6px" { button.btn.primary type="submit" { "Add service" } }
            }
        }
    };
    Ok(admin_shell(AdminTab::Services, &viewer, &host, counts, body).into_response())
}

#[derive(Debug, Deserialize)]
pub struct ServiceForm {
    pub slug: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "returnUrl")]
    pub return_url: String,
}

#[derive(Debug, Deserialize)]
pub struct ServiceUpdateForm {
    pub id: i64,
    pub slug: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "returnUrl")]
    pub return_url: String,
}

fn validate(slug: &str, name: &str, return_url: &str) -> Result<(String, String, String), String> {
    let slug = slug.trim().to_string();
    let name = {
        let n = name.trim();
        if n.is_empty() { slug.clone() } else { n.to_string() }
    };
    let return_url = return_url.trim().to_string();
    if slug.is_empty() || return_url.is_empty() {
        return Err("slug and return url required".into());
    }
    if !slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err("slug must be lowercase alphanumeric + dashes".into());
    }
    if url::Url::parse(&return_url).is_err() {
        return Err("return url must be a valid URL".into());
    }
    Ok((slug, name, return_url))
}

pub async fn add_service(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<ServiceForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
    let (slug, name, return_url) =
        validate(&f.slug, &f.name, &f.return_url).map_err(AppError::BadRequest)?;
    let inserted: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO services (slug, name, return_url) VALUES (?, ?, ?)
         ON CONFLICT(slug) WHERE deleted_at IS NULL DO NOTHING RETURNING id",
    )
    .bind(&slug)
    .bind(&name)
    .bind(&return_url)
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
    audit(
        &state.pool,
        Some(admin.id),
        "service.add",
        Some(&format!("service:{}", sid)),
        Some(serde_json::json!({ "slug": slug })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/admin/services").into_response())
}

pub async fn update_service(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<ServiceUpdateForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
    let (slug, name, return_url) =
        validate(&f.slug, &f.name, &f.return_url).map_err(AppError::BadRequest)?;
    sqlx::query("UPDATE services SET slug = ?, name = ?, return_url = ? WHERE id = ?")
        .bind(&slug)
        .bind(&name)
        .bind(&return_url)
        .bind(f.id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(admin.id),
        "service.update",
        Some(&format!("service:{}", f.id)),
        Some(serde_json::json!({ "slug": slug })),
    )
    .await
    .map_err(AppError::Other)?;
    Ok(Redirect::to("/admin/services").into_response())
}

pub async fn remove_service(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<IdForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
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

// -------------------- Audit log --------------------

pub async fn audit_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;
    let viewer = user.unwrap();
    let host = host_from_origin(&origin_from(&state, &headers)).to_string();
    let counts = load_counts(&state).await?;

    let rows: Vec<(i64, String, Option<String>, Option<String>, Option<String>)> =
        sqlx::query_as(
            "SELECT a.at, a.action, u.username,
                    CASE
                      WHEN a.target LIKE 'user:%'
                        THEN (SELECT u2.username FROM users u2
                              WHERE u2.id = CAST(SUBSTR(a.target, 6) AS INTEGER))
                      WHEN a.target LIKE 'service:%'
                        THEN (SELECT s.slug FROM services s
                              WHERE s.id = CAST(SUBSTR(a.target, 9) AS INTEGER))
                      WHEN a.target LIKE 'request:%'
                        THEN 'request #' || SUBSTR(a.target, 9)
                      ELSE a.target
                    END AS target_label,
                    a.meta
             FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id
             ORDER BY a.at DESC LIMIT 200",
        )
        .fetch_all(&state.pool)
        .await?;

    let (total_events,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&state.pool)
        .await?;
    let meta = format!("append-only · {} events", total_events);

    let body = html! {
        (admin_header("Audit log", Some(&meta), None))
        p.admin-desc {
            "Every admin action and authentication event. Filter by actor, event type, or service."
        }

        div.filter-row {
            input.input.mono style="width:240px" placeholder="event filter (e.g. grant.*)…";
            select.input.mono style="width:140px" { option { "all actors" } }
            select.input.mono style="width:140px" { option { "last 7 days" } }
            span style="margin-left:auto" {
                button.btn type="button" disabled { "export csv ↓" }
            }
        }

        div.audit-grid {
            div.head {
                span { "Timestamp" }
                span { "Event" }
                span { "Actor" }
                span { "Detail" }
                span style="text-align:right" { "Result" }
            }
            @for (at, action, actor, target, _meta) in &rows {
                @let result_kind = result_tone(action);
                div.row {
                    span.ts { (fmt_time(*at)) }
                    span.ev { (action) }
                    span.actor { (actor.as_deref().unwrap_or("system")) }
                    span.det { (target.as_deref().unwrap_or("")) }
                    span class=(format!("result {}", result_kind)) { (result_kind) }
                }
            }
        }
    };
    Ok(admin_shell(AdminTab::Audit, &viewer, &host, counts, body).into_response())
}

fn result_tone(action: &str) -> &'static str {
    if action.ends_with(".deny")
        || action.ends_with(".revoke")
        || action.ends_with(".revoke_all")
        || action.ends_with(".remove")
        || action.ends_with(".reject")
    {
        "warn"
    } else if action.ends_with(".add")
        || action.ends_with(".approve")
        || action.ends_with(".create")
        || action.ends_with(".update")
        || action.starts_with("setup.")
        || action.starts_with("service.")
        || action.starts_with("grant.")
    {
        "success"
    } else {
        "info"
    }
}
