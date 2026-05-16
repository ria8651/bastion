use axum::{
    extract::{Path, State},
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
use crate::state::AppState;
use crate::templates::{admin_layout, status_pill, AdminTab};

fn fmt_time(unix: i64) -> String {
    Utc.timestamp_opt(unix, 0)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

// -------------------- Overview --------------------

pub async fn overview(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;

    let (total_users,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pool)
        .await?;
    let (pending_users,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE status = 'pending'")
            .fetch_one(&state.pool)
            .await?;
    let (pending_reqs,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM access_requests WHERE resolved_at IS NULL")
            .fetch_one(&state.pool)
            .await?;
    let (svc_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM services")
        .fetch_one(&state.pool)
        .await?;

    let entries: Vec<(i64, Option<String>, String, Option<String>, Option<String>, i64)> =
        sqlx::query_as(
            "SELECT a.id, u.username, a.action, a.target, a.meta, a.at
             FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id
             ORDER BY a.at DESC LIMIT 20",
        )
        .fetch_all(&state.pool)
        .await?;

    let body = html! {
        h1 { "Overview" }
        div.stat-grid {
            a.stat href="/admin/users" {
                span.n { (total_users) } br;
                span.lbl { "users" }
            }
            a.stat href="/admin/users" {
                span.n { (pending_users) } br;
                span.lbl { "pending users" }
            }
            a.stat href="/admin/requests" {
                span.n { (pending_reqs) } br;
                span.lbl { "pending requests" }
            }
            a.stat href="/admin/services" {
                span.n { (svc_count) } br;
                span.lbl { "services" }
            }
        }
        h2 { "Recent activity" }
        @if entries.is_empty() {
            p.muted { "No audit entries yet." }
        } @else {
            table.admin-table {
                thead { tr { th{"When"} th{"Actor"} th{"Action"} th{"Target"} th{"Meta"} } }
                tbody {
                    @for (_, actor, action, target, meta, at) in &entries {
                        tr {
                            td.muted { (fmt_time(*at)) }
                            td { (actor.as_deref().unwrap_or("—")) }
                            td { code { (action) } }
                            td.muted { (target.as_deref().unwrap_or("")) }
                            td.muted { (meta.as_deref().unwrap_or("")) }
                        }
                    }
                }
            }
        }
    };
    Ok(admin_layout("Overview", AdminTab::Overview, user.as_ref(), body).into_response())
}

// -------------------- Requests --------------------

pub async fn requests_page(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;

    let pending: Vec<(i64, String, Option<String>, Option<String>, i64)> = sqlx::query_as(
        "SELECT r.id, u.username, s.slug, r.note, r.requested_at
         FROM access_requests r
         JOIN users u ON u.id = r.user_id
         LEFT JOIN services s ON s.id = r.service_id
         WHERE r.resolved_at IS NULL
         ORDER BY r.requested_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    let resolved: Vec<(i64, String, Option<String>, Option<String>, Option<i64>)> =
        sqlx::query_as(
            "SELECT r.id, u.username, s.slug, r.decision, r.resolved_at
             FROM access_requests r
             JOIN users u ON u.id = r.user_id
             LEFT JOIN services s ON s.id = r.service_id
             WHERE r.resolved_at IS NOT NULL
             ORDER BY r.resolved_at DESC LIMIT 25",
        )
        .fetch_all(&state.pool)
        .await?;

    let body = html! {
        h1 { "Requests" }
        h2 { "Pending" }
        @if pending.is_empty() {
            p.muted { "No pending requests." }
        } @else {
            table.admin-table {
                thead { tr { th{"User"} th{"Service"} th{"When"} th{"Note"} th{} } }
                tbody {
                    @for (id, uname, slug, note, at) in &pending {
                        tr {
                            td { (uname) }
                            td { (slug.as_deref().unwrap_or("—")) }
                            td.muted { (fmt_time(*at)) }
                            td.muted { (note.as_deref().unwrap_or("")) }
                            td.row-actions {
                                form method="post" action="/admin/requests/approve" {
                                    input type="hidden" name="id" value=(id);
                                    button.btn.primary type="submit" { "Approve" }
                                }
                                form method="post" action="/admin/requests/deny" {
                                    input type="hidden" name="id" value=(id);
                                    button.btn.danger type="submit" { "Deny" }
                                }
                            }
                        }
                    }
                }
            }
        }
        h2 style="margin-top:2rem" { "Recently resolved" }
        @if resolved.is_empty() {
            p.muted { "Nothing yet." }
        } @else {
            table.admin-table {
                thead { tr { th{"User"} th{"Service"} th{"Decision"} th{"When"} } }
                tbody {
                    @for (_id, uname, slug, decision, at) in &resolved {
                        tr {
                            td { (uname) }
                            td { (slug.as_deref().unwrap_or("—")) }
                            td {
                                @match decision.as_deref() {
                                    Some("approved") => span.pill.good { "approved" },
                                    Some("denied")   => span.pill.bad  { "denied" },
                                    _ => span.pill { "—" },
                                }
                            }
                            td.muted { (at.map(|t| fmt_time(t)).unwrap_or_default()) }
                        }
                    }
                }
            }
        }
    };
    Ok(admin_layout("Requests", AdminTab::Requests, user.as_ref(), body).into_response())
}

#[derive(Debug, Deserialize)]
pub struct IdForm {
    pub id: i64,
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

// -------------------- Users --------------------

pub async fn users_page(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;

    let rows: Vec<(i64, Option<String>, String, Option<String>, String, bool, Option<i64>)> =
        sqlx::query_as(
            "SELECT id, avatar, username, email, status, is_admin, last_login_at
             FROM users ORDER BY created_at DESC",
        )
        .fetch_all(&state.pool)
        .await?;

    let body = html! {
        h1 { "Users" }
        table.admin-table {
            thead {
                tr {
                    th {} th { "Username" } th { "Email" } th { "Status" }
                    th { "Admin" } th { "Last login" } th {}
                }
            }
            tbody {
                @for (id, avatar, username, email, status, is_admin, last) in &rows {
                    tr {
                        td {
                            @if let Some(a) = avatar {
                                img.avatar src=(a) alt="" referrerpolicy="no-referrer";
                            }
                        }
                        td { a href=(format!("/admin/users/{}", id)) { (username) } }
                        td.muted { (email.as_deref().unwrap_or("—")) }
                        td { (status_pill(status)) }
                        td {
                            @if *is_admin { span.pill.good { "admin" } } @else { span.pill { "—" } }
                        }
                        td.muted { (last.map(|t| fmt_time(t)).unwrap_or_else(|| "never".into())) }
                        td.row-actions {
                            @if status != "active" {
                                form method="post" action="/admin/users/set-status" {
                                    input type="hidden" name="id" value=(id);
                                    input type="hidden" name="status" value="active";
                                    button.btn.primary type="submit" { "Approve" }
                                }
                            }
                            @if status != "denied" {
                                form method="post" action="/admin/users/set-status" {
                                    input type="hidden" name="id" value=(id);
                                    input type="hidden" name="status" value="denied";
                                    button.btn.danger type="submit" { "Deny" }
                                }
                            }
                            form method="post" action="/admin/users/set-admin" {
                                input type="hidden" name="id" value=(id);
                                input type="hidden" name="is_admin" value=(if *is_admin { "0" } else { "1" });
                                button.btn type="submit" {
                                    @if *is_admin { "Demote" } @else { "Promote" }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    Ok(admin_layout("Users", AdminTab::Users, user.as_ref(), body).into_response())
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
    Path(id): Path<i64>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;

    let u: Option<(i64, i64, String, Option<String>, Option<String>, String, bool, i64, Option<i64>)> =
        sqlx::query_as(
            "SELECT id, github_id, username, email, avatar, status, is_admin, created_at, last_login_at
             FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    let Some((uid, gh, uname, email, avatar, status, is_admin, _created, last)) = u else {
        return Err(AppError::NotFound);
    };

    let services: Vec<(i64, String, String, bool)> = sqlx::query_as(
        "SELECT s.id, s.slug, s.name,
                EXISTS(SELECT 1 FROM grants g WHERE g.user_id = ? AND g.service_id = s.id) as granted
         FROM services s ORDER BY s.slug",
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

    let body = html! {
        h1 {
            @if let Some(a) = &avatar {
                img.avatar src=(a) alt="" style="width:36px;height:36px;vertical-align:middle";
            }
            " " (uname)
        }
        p.muted {
            (status_pill(&status)) " "
            @if is_admin { span.pill.good { "admin" } } " "
            "github_id=" (gh) " · "
            (email.as_deref().unwrap_or("no email")) " · "
            "last login " (last.map(|t| fmt_time(t)).unwrap_or_else(|| "never".into()))
        }

        h2 { "Service grants" }
        table.admin-table {
            thead { tr { th{"Service"} th{"Granted"} th{} } }
            tbody {
                @for (sid, slug, name, granted) in &services {
                    tr {
                        td { strong { (slug) } " " span.muted { (name) } }
                        td {
                            @if *granted { span.pill.good { "yes" } } @else { span.pill { "no" } }
                        }
                        td {
                            form method="post" action=(format!("/admin/users/{}/toggle-grant", uid)) {
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

        h2 style="margin-top:2rem" { "Access requests" }
        @if requests.is_empty() {
            p.muted { "None." }
        } @else {
            table.admin-table {
                thead { tr { th{"Service"} th{"Requested"} th{"Status"} } }
                tbody {
                    @for (_rid, slug, decision, ra, resolved) in &requests {
                        tr {
                            td { (slug.as_deref().unwrap_or("—")) }
                            td.muted { (fmt_time(*ra)) }
                            td {
                                @if resolved.is_some() {
                                    @match decision.as_deref() {
                                        Some("approved") => span.pill.good { "approved" },
                                        Some("denied")   => span.pill.bad  { "denied" },
                                        _ => span.pill { "—" },
                                    }
                                } @else {
                                    span.pill.warn { "pending" }
                                }
                            }
                        }
                    }
                }
            }
        }

        h2 style="margin-top:2rem" { "Sessions" }
        p.muted { (active_sessions) " active session(s)." }
        form method="post" action=(format!("/admin/users/{}/revoke-sessions", uid)) {
            button.btn.danger type="submit" { "Revoke all sessions" }
        }
    };
    Ok(admin_layout(&uname, AdminTab::Users, user.as_ref(), body).into_response())
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

// -------------------- Services --------------------

pub async fn services_page(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;

    let rows: Vec<(i64, String, String, String, i64)> = sqlx::query_as(
        "SELECT s.id, s.slug, s.name, s.return_url,
                (SELECT COUNT(*) FROM grants g WHERE g.service_id = s.id) AS user_count
         FROM services s ORDER BY s.slug",
    )
    .fetch_all(&state.pool)
    .await?;

    let body = html! {
        h1 { "Services" }
        table.admin-table {
            thead { tr { th{"Slug"} th{"Name"} th{"Return URL"} th{"Users"} th{} } }
            tbody {
                @for (id, slug, name, ret, n) in &rows {
                    tr {
                        td { strong { (slug) } }
                        td { (name) }
                        td.muted { code { (ret) } }
                        td { (n) }
                        td.row-actions {
                            (edit_button(*id))
                            form method="post" action="/admin/services/remove"
                                onsubmit="return confirm('Remove this service? Existing grants will also be removed.')" {
                                input type="hidden" name="id" value=(id);
                                button.btn.danger type="submit" { "Remove" }
                            }
                        }
                    }
                    (edit_row(*id, slug, name, ret))
                }
            }
        }
        h2 style="margin-top:2rem" { "Add service" }
        (add_form())
    };
    Ok(admin_layout("Services", AdminTab::Services, user.as_ref(), body).into_response())
}

fn edit_button(_id: i64) -> Markup {
    html! {
        // Toggle the corresponding hidden row via a tiny inline handler.
        // Keeps htmx simple — no extra endpoints for an in-place edit panel.
        button.btn type="button"
            onclick={
                "var r=this.closest('tr').nextElementSibling;"
                "r.style.display = (r.style.display === 'table-row' ? 'none' : 'table-row');"
            } { "Edit" }
    }
}

fn edit_row(id: i64, slug: &str, name: &str, ret: &str) -> Markup {
    html! {
        tr style="display:none;background:#0c0e12" {
            td colspan="5" {
                form method="post" action="/admin/services/update" style="display:grid;gap:.5rem;max-width:520px" {
                    input type="hidden" name="id" value=(id);
                    label { "Slug"        input name="slug"      value=(slug)  required; }
                    label { "Name"        input name="name"      value=(name); }
                    label { "Return URL"  input name="returnUrl" value=(ret)   required type="url"; }
                    div.row-actions { button.btn.primary type="submit" { "Save" } }
                }
            }
        }
    }
}

fn add_form() -> Markup {
    html! {
        form method="post" action="/admin/services/add" style="display:grid;gap:.5rem;max-width:520px" {
            label { "Slug"        input name="slug"      required pattern="[a-z0-9-]+"; }
            label { "Name"        input name="name"; }
            label { "Return URL"  input name="returnUrl" required type="url"; }
            div.row-actions { button.btn.primary type="submit" { "Add" } }
        }
    }
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
         ON CONFLICT(slug) DO NOTHING RETURNING id",
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
    sqlx::query("DELETE FROM services WHERE id = ?")
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
