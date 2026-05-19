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
use crate::setup::{clear_oauth_config, set_oauth_config};
use crate::state::{origin_from, AppState};
use crate::templates::{
    admin_header, admin_shell, host_from_origin, pill, provider_display_name, provider_icon,
    status_pill, AdminCounts, AdminTab,
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

    let rows: Vec<(
        i64,
        Option<String>,
        String,
        Option<String>,
        String,
        bool,
        Option<i64>,
        i64,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT u.id, u.avatar, u.username, u.email, u.status, u.is_admin, u.last_login_at,
                (SELECT COUNT(*) FROM grants g WHERE g.user_id = u.id) AS svc_count,
                (SELECT GROUP_CONCAT(DISTINCT ui.provider)
                   FROM user_identities ui WHERE ui.user_id = u.id) AS providers
         FROM users u ORDER BY u.created_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    let total = rows.len();
    let (provider_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM oauth_providers WHERE enabled = 1")
            .fetch_one(&state.pool)
            .await?;
    let meta = format!(
        "{} total · {} provider{}",
        total,
        provider_count,
        if provider_count == 1 { "" } else { "s" }
    );

    let body = html! {
        (admin_header("Users", Some(&meta), None))
        p.admin-desc {
            "Linked accounts. Each user can sign in via one or more identity providers."
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
                    @for (id, avatar_url, username, email, status, is_admin, last, svc_count, providers) in &rows {
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
                                span style="display:inline-flex;align-items:center;gap:6px;color:var(--fg-mid)" {
                                    @for p in providers.as_deref().unwrap_or("").split(',').filter(|p| !p.is_empty()) {
                                        span title=(p) style="width:14px;height:14px;display:inline-flex" {
                                            (provider_icon(p))
                                        }
                                    }
                                    @if providers.as_deref().unwrap_or("").is_empty() {
                                        span.mono style="font-size:12px;color:var(--fg-dim)" { "—" }
                                    }
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

#[derive(Debug, Deserialize)]
pub struct UserDetailQuery {
    pub expand: Option<i64>,
}

pub async fn user_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    axum::extract::Query(q): axum::extract::Query<UserDetailQuery>,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;
    let viewer = user.unwrap();
    let host = host_from_origin(&origin_from(&state, &headers)).to_string();
    let expand_service: Option<i64> = q.expand;
    let counts = load_counts(&state).await?;

    let u: Option<(
        i64,
        String,
        Option<String>,
        Option<String>,
        String,
        bool,
        i64,
        Option<i64>,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT id, username, email, avatar, status, is_admin, created_at, last_login_at,
                sub_anchor_provider, sub_anchor_provider_id
         FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((
        uid,
        uname,
        email,
        avatar_url,
        status,
        is_admin,
        _created,
        last,
        sub_anchor_provider,
        sub_anchor_provider_id,
    )) = u
    else {
        return Err(AppError::NotFound);
    };

    let identities: Vec<(i64, String, String, Option<String>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT id, provider, provider_id, email, linked_at, last_login_at
         FROM user_identities WHERE user_id = ? ORDER BY linked_at",
    )
    .bind(uid)
    .fetch_all(&state.pool)
    .await?;

    let services: Vec<(i64, String, String, bool)> = sqlx::query_as(
        "SELECT s.id, s.slug, s.name,
                EXISTS(SELECT 1 FROM grants g WHERE g.user_id = ? AND g.service_id = s.id) as granted
         FROM services s
         WHERE s.deleted_at IS NULL AND s.status = 'approved'
         ORDER BY s.slug",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;

    // Active perms per service, plus whether this user currently holds each.
    let perm_rows: Vec<(i64, i64, String, Option<String>, bool, bool)> = sqlx::query_as(
        "SELECT p.service_id, p.id, p.key, p.description,
                EXISTS(SELECT 1 FROM user_perms up
                       WHERE up.user_id = ? AND up.permission_id = p.id) as has_it,
                p.default_allow
         FROM permissions p
         JOIN services s ON s.id = p.service_id
         WHERE p.removed_at IS NULL
           AND s.deleted_at IS NULL
           AND s.status = 'approved'
         ORDER BY p.service_id, p.key",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let mut service_perms: std::collections::HashMap<
        i64,
        Vec<(i64, String, Option<String>, bool, bool)>,
    > = std::collections::HashMap::new();
    for (sid, pid, key, desc, has_it, default_allow) in perm_rows {
        service_perms
            .entry(sid)
            .or_default()
            .push((pid, key, desc, has_it, default_allow));
    }

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
        "sub anchor: {}/{} · {}",
        sub_anchor_provider,
        sub_anchor_provider_id,
        email.as_deref().unwrap_or("no email")
    );

    let body = html! {
        div.admin-header {
            div.titlewrap.user-titlewrap {
                @if let Some(a) = &avatar_url {
                    img.user-avatar-lg src=(a) alt="";
                }
                h1 { (uname) }
                span.meta { (meta) }
            }
        }
        div.admin-desc.user-meta-row {
            (status_pill(&status))
            @if is_admin { (pill("admin", "admin")) }
            span.last-login { "last login " (last.map(fmt_time).unwrap_or_else(|| "never".into())) }
        }

        h2 style="font-size:14px;margin-top:24px;margin-bottom:12px;font-family:var(--font-mono);color:var(--fg-mute);text-transform:uppercase;letter-spacing:0.06em" { "Linked identities" }
        div.table-wrap {
            table {
                thead { tr { th { "Provider" } th { "Provider id" } th { "Email" } th { "Linked" } th { "Last seen" } } }
                tbody {
                    @for (_iid, prov, pid, iemail, linked, ilast) in &identities {
                        tr {
                            td {
                                span style="display:inline-flex;align-items:center;gap:8px;color:var(--fg-mid)" {
                                    span style="width:14px;height:14px;display:inline-flex" { (provider_icon(prov)) }
                                    span.mono style="font-size:12px" { (provider_display_name(prov)) }
                                }
                            }
                            td.mono style="font-size:12px;color:var(--fg-mid)" { (pid) }
                            td.mono style="font-size:12px;color:var(--fg-mid)" { (iemail.as_deref().unwrap_or("—")) }
                            td.mono style="font-size:12px;color:var(--fg-mute)" { (fmt_time(*linked)) }
                            td.mono style="font-size:12px;color:var(--fg-mute)" {
                                (ilast.map(rel_time).unwrap_or_else(|| "—".into()))
                            }
                        }
                    }
                }
            }
        }

        h2 style="font-size:14px;margin-top:32px;margin-bottom:12px;font-family:var(--font-mono);color:var(--fg-mute);text-transform:uppercase;letter-spacing:0.06em" { "Service grants" }
        div.table-wrap {
            table {
                thead { tr { th { "Service" } th { "Granted" } th { "Perms" } th {} } }
                tbody {
                    @for (sid, slug, name, granted) in &services {
                        @let perms_here = service_perms.get(sid);
                        @let total_n = perms_here.map(|v| v.len()).unwrap_or(0);
                        @let on_n = perms_here.map(|v| v.iter().filter(|(_,_,_,h,_)| *h).count()).unwrap_or(0);
                        tr {
                            td {
                                div.mono style="font-weight:500" { (slug) }
                                div.mono style="font-size:11px;color:var(--fg-mute)" { (name) }
                            }
                            td {
                                @if *granted { (pill("active", "yes")) } @else { span.pill { "no" } }
                            }
                            td.mono style="font-size:12px;color:var(--fg-mid)" {
                                @if total_n == 0 {
                                    span style="color:var(--fg-mute)" { "—" }
                                } @else if *granted {
                                    (on_n) " / " (total_n)
                                } @else {
                                    span style="color:var(--fg-mute)" { "0 / " (total_n) }
                                }
                            }
                            td style="text-align:right;white-space:nowrap" {
                                @if *granted && total_n > 0 {
                                    button.btn.text type="button"
                                        onclick={
                                            "var r=this.closest('tr').nextElementSibling;"
                                            "r.style.display = (r.style.display === 'table-row' ? 'none' : 'table-row');"
                                        } { "edit perms" }
                                    " "
                                }
                                form method="post" action=(format!("/admin/users/{}/toggle-grant", uid)) style="margin:0;display:inline" {
                                    input type="hidden" name="service_id" value=(sid);
                                    input type="hidden" name="grant" value=(if *granted { "0" } else { "1" });
                                    button.btn type="submit" {
                                        @if *granted { "Revoke" } @else { "Grant" }
                                    }
                                }
                            }
                        }
                        @if *granted && total_n > 0 {
                            @let initially_open = expand_service == Some(*sid);
                            tr style=(if initially_open {
                                "display:table-row;background:var(--bg-elev)"
                            } else {
                                "display:none;background:var(--bg-elev)"
                            }) {
                                td colspan="4" {
                                    div.lbl style="margin-bottom:8px" {
                                        "permissions for " (slug)
                                    }
                                    div style="display:grid;gap:6px;max-width:680px" {
                                        @for (pid, key, desc, has_it, default_allow) in perms_here.unwrap() {
                                            form method="post" action=(format!("/admin/users/{}/toggle-perm", uid)) style="margin:0;display:flex;align-items:center;gap:10px;padding:4px 0" {
                                                input type="hidden" name="permission_id" value=(pid);
                                                input type="hidden" name="grant" value=(if *has_it { "0" } else { "1" });
                                                button.btn type="submit" style=(if *has_it {
                                                    "min-width:80px"
                                                } else {
                                                    "min-width:80px;opacity:0.7"
                                                }) {
                                                    @if *has_it { "✓ on" } @else { "off" }
                                                }
                                                span.mono style="font-size:12px" { (key) }
                                                @if *default_allow {
                                                    span style="color:var(--fg-mute);font-size:10px;text-transform:uppercase;letter-spacing:0.06em" { "default" }
                                                }
                                                @if let Some(d) = desc {
                                                    span style="color:var(--fg-mute);font-size:12px" { "— " (d) }
                                                }
                                            }
                                        }
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
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();

    let row: Option<(i64, String, Option<i64>)> = sqlx::query_as(
        "SELECT service_id, key, removed_at FROM permissions WHERE id = ?",
    )
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
        audit(
            &state.pool,
            Some(admin.id),
            "perm.grant",
            Some(&format!("user:{}", uid)),
            Some(serde_json::json!({
                "serviceId": service_id,
                "permissionId": f.permission_id,
                "key": key,
            })),
        )
        .await
        .map_err(AppError::Other)?;
    } else {
        sqlx::query("DELETE FROM user_perms WHERE user_id = ? AND permission_id = ?")
            .bind(uid)
            .bind(f.permission_id)
            .execute(&state.pool)
            .await?;
        audit(
            &state.pool,
            Some(admin.id),
            "perm.revoke",
            Some(&format!("user:{}", uid)),
            Some(serde_json::json!({
                "serviceId": service_id,
                "permissionId": f.permission_id,
                "key": key,
            })),
        )
        .await
        .map_err(AppError::Other)?;
    }
    // Preserve the expand state so the dropdown stays open across the toggle.
    Ok(Redirect::to(&format!("/admin/users/{}?expand={}", uid, service_id)).into_response())
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
        "SELECT r.id, u.id, u.username, u.avatar, s.slug, r.requested_at, r.resolved_at, r.decision, u.created_at,
                u.sub_anchor_provider
         FROM access_requests r
         JOIN users u ON u.id = r.user_id
         LEFT JOIN services s ON s.id = r.service_id
         WHERE {}
         ORDER BY r.requested_at DESC LIMIT 80",
        where_clause
    );
    let rows: Vec<(
        i64,
        i64,
        String,
        Option<String>,
        Option<String>,
        i64,
        Option<i64>,
        Option<String>,
        i64,
        String,
    )> = sqlx::query_as(&sql).fetch_all(&state.pool).await?;

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
                @for (rid, _uid, uname, uavatar, slug, ra, resolved, decision, created, prov) in &rows {
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
                                    span style="display:inline-flex;width:11px;height:11px" { (provider_icon(prov)) }
                                    span { "via " (prov) }
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
        crate::routes::registration::apply_default_perms(&state.pool, uid, sid).await?;
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

    let rows: Vec<(i64, String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT s.id, s.slug, s.name, s.return_url,
                (SELECT COUNT(*) FROM grants g WHERE g.service_id = s.id) AS user_count,
                (SELECT COUNT(*) FROM permissions p
                   WHERE p.service_id = s.id AND p.removed_at IS NULL) AS perm_count
         FROM services s
         WHERE s.deleted_at IS NULL AND s.status = 'approved'
         ORDER BY s.slug",
    )
    .fetch_all(&state.pool)
    .await?;

    let pending: Vec<(i64, String, String, String, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT id, slug, name, return_url, public_jwk, registered_at
         FROM services
         WHERE deleted_at IS NULL AND status = 'pending'
         ORDER BY registered_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    // Per-service active perm catalogs, for the pending cards.
    let mut pending_perms: std::collections::HashMap<i64, Vec<(String, Option<String>)>> =
        std::collections::HashMap::new();
    if !pending.is_empty() {
        let perm_rows: Vec<(i64, String, Option<String>)> = sqlx::query_as(
            "SELECT service_id, key, description FROM permissions
             WHERE removed_at IS NULL AND service_id IN (
                SELECT id FROM services WHERE status = 'pending' AND deleted_at IS NULL
             )
             ORDER BY service_id, key",
        )
        .fetch_all(&state.pool)
        .await?;
        for (sid, key, desc) in perm_rows {
            pending_perms.entry(sid).or_default().push((key, desc));
        }
    }

    // Full perm catalogs (active + soft-deleted) for the approved services.
    let mut approved_perms: std::collections::HashMap<
        i64,
        Vec<(String, Option<String>, Option<i64>, bool)>,
    > = std::collections::HashMap::new();
    if !rows.is_empty() {
        let perm_rows: Vec<(i64, String, Option<String>, Option<i64>, bool)> = sqlx::query_as(
            "SELECT service_id, key, description, removed_at, default_allow FROM permissions
             WHERE service_id IN (
                SELECT id FROM services WHERE status = 'approved' AND deleted_at IS NULL
             )
             ORDER BY service_id, removed_at IS NOT NULL, key",
        )
        .fetch_all(&state.pool)
        .await?;
        for (sid, key, desc, removed, default_allow) in perm_rows {
            approved_perms
                .entry(sid)
                .or_default()
                .push((key, desc, removed, default_allow));
        }
    }

    let (total_grants,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM grants")
        .fetch_one(&state.pool)
        .await?;
    let meta = format!(
        "{} approved · {} pending · {} grants",
        rows.len(),
        pending.len(),
        total_grants
    );
    let action = html! {
        a.btn href="#add-service" { "+ register service" }
    };

    let body = html! {
        (admin_header("Services", Some(&meta), Some(action)))
        p.admin-desc {
            "Apps that consume bastion-issued JWTs. Self-registered services land below as pending until you approve them; you can also pre-provision a service manually."
        }

        @if !pending.is_empty() {
            h2 style="font-size:14px;margin-top:8px;margin-bottom:12px;font-family:var(--font-mono);color:var(--fg-mute);text-transform:uppercase;letter-spacing:0.06em" {
                "Pending registrations · " (pending.len())
            }
            div.req-grid {
                @for (sid, slug, name, ret, jwk_opt, registered_at) in &pending {
                    div.req-card {
                        div.req-head {
                            div.info {
                                div.uname { (slug) }
                                div.via {
                                    span { (name) }
                                }
                            }
                            (pill("pending", "pending"))
                        }
                        div.req-body style="padding-top:8px;padding-bottom:8px" {
                            div.lbl style="margin-bottom:4px" { "suggested return url" }
                            div.mono style="font-size:12px;color:var(--fg-mid);word-break:break-all" { (ret) }
                        }
                        div.req-meta {
                            div {
                                div.lbl { "kid" }
                                div.val.mono style="font-size:11px" {
                                    (jwk_short(jwk_opt.as_deref()))
                                }
                            }
                            div {
                                div.lbl { "fingerprint" }
                                div.val.mono style="font-size:11px" {
                                    (jwk_thumbprint_short(jwk_opt.as_deref()))
                                }
                            }
                            div {
                                div.lbl { "registered" }
                                div.val { (registered_at.map(|t| rel_time(t)).unwrap_or_else(|| "—".into())) }
                            }
                        }
                        @let perms_here = pending_perms.get(sid);
                        @if let Some(ps) = perms_here {
                            div style="padding:8px 14px 12px;border-top:1px solid var(--border)" {
                                div.lbl style="margin-bottom:6px" { "declared permissions · " (ps.len()) }
                                @for (key, desc) in ps {
                                    div.mono style="font-size:12px;padding:3px 0" {
                                        (key)
                                        @if let Some(d) = desc {
                                            span style="color:var(--fg-mute)" { "  — " (d) }
                                        }
                                    }
                                }
                            }
                        } @else {
                            div style="padding:8px 14px 12px;border-top:1px solid var(--border);color:var(--fg-mute);font-size:12px" {
                                "no permissions declared"
                            }
                        }
                        div style="padding:12px 14px;border-top:1px solid var(--border);display:grid;gap:8px" {
                            form method="post" action="/admin/services/approve-registration" style="display:grid;gap:8px;margin:0" {
                                input type="hidden" name="id" value=(sid);
                                label.field style="margin:0" {
                                    "Return URL (the value users' browsers will be redirected back to)"
                                    input.input.mono name="returnUrl" value=(ret) required type="url" style="font-size:12px";
                                }
                                div style="display:flex;gap:8px;align-items:center" {
                                    button.btn.primary type="submit" { "Approve" }
                                    button.btn.danger type="submit"
                                        formaction="/admin/services/deny-registration"
                                        formnovalidate
                                        onclick="return confirm('Deny this registration? The service will be blocked from re-registering with the same slug until you remove it.')"
                                        { "Deny" }
                                }
                            }
                        }
                    }
                }
            }
        }

        h2 style="font-size:14px;margin-top:24px;margin-bottom:12px;font-family:var(--font-mono);color:var(--fg-mute);text-transform:uppercase;letter-spacing:0.06em" {
            "Approved services · " (rows.len())
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
                    @for (id, slug, name, ret, n, perm_n) in &rows {
                        tr {
                            td {
                                div.mono style="font-size:13px;font-weight:500" { (slug) }
                                div.mono style="font-size:11px;color:var(--fg-mute)" { "aud:" (slug) " · " (name) }
                            }
                            td.mono style="font-size:12px;color:var(--fg-mid);max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" {
                                (ret)
                            }
                            td.mono style="font-size:13px;color:var(--fg)" { (n) }
                            td.mono style="font-size:13px;color:var(--fg)" { (perm_n) }
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
                                div style="display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.4fr);gap:32px;align-items:start" {
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
                                    div {
                                        @let entries = approved_perms.get(id);
                                        @let active_n = entries.map(|v| v.iter().filter(|(_,_,r,_)| r.is_none()).count()).unwrap_or(0);
                                        @let removed_n = entries.map(|v| v.iter().filter(|(_,_,r,_)| r.is_some()).count()).unwrap_or(0);
                                        div.lbl style="margin-bottom:8px" {
                                            "permission catalog · " (active_n) " active"
                                            @if removed_n > 0 { " · " (removed_n) " removed" }
                                        }
                                        @match entries {
                                            Some(es) if !es.is_empty() => {
                                                div style="display:grid;gap:4px" {
                                                    @for (key, desc, removed, default_allow) in es {
                                                        @let is_removed = removed.is_some();
                                                        div.mono style=(if is_removed {
                                                            "font-size:12px;color:var(--fg-mute);text-decoration:line-through"
                                                        } else {
                                                            "font-size:12px;color:var(--fg)"
                                                        }) {
                                                            (key)
                                                            @if *default_allow && !is_removed {
                                                                span style="color:var(--fg-mute);text-decoration:none;margin-left:6px;font-size:10px;text-transform:uppercase;letter-spacing:0.06em" { "default" }
                                                            }
                                                            @if let Some(d) = desc {
                                                                span style="color:var(--fg-mute);text-decoration:none" { "  — " (d) }
                                                            }
                                                            @if let Some(at) = removed {
                                                                span style="color:var(--fg-mute);text-decoration:none;margin-left:6px" {
                                                                    "(removed " (rel_time(*at)) ")"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                div style="margin-top:10px;font-size:11px;color:var(--fg-mute)" {
                                                    "catalog is owned by the service — declared via /api/services/register on boot."
                                                }
                                            }
                                            _ => {
                                                div.mono style="font-size:12px;color:var(--fg-mute)" {
                                                    "no permissions declared"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        h2 id="add-service" style="font-size:14px;margin-top:32px;margin-bottom:12px;font-family:var(--font-mono);color:var(--fg-mute);text-transform:uppercase;letter-spacing:0.06em" { "Pre-provision a service (manual)" }
        p.admin-desc style="margin-top:-6px" {
            "Use this only when a service can't self-register. Most services should POST to /api/services/register on first boot."
        }
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

fn jwk_short(jwk_str: Option<&str>) -> String {
    let Some(s) = jwk_str else { return "—".into() };
    serde_json::from_str::<serde_json::Value>(s)
        .ok()
        .and_then(|v| v.get("kid").and_then(|k| k.as_str()).map(String::from))
        .unwrap_or_else(|| "—".into())
}

fn jwk_thumbprint_short(jwk_str: Option<&str>) -> String {
    let Some(s) = jwk_str else { return "—".into() };
    crate::routes::registration::jwk_thumbprint(s)
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
    crate::routes::registration::apply_default_perms(&state.pool, admin.id, sid).await?;
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
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT slug, status FROM services WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(f.id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((slug, status)) = row else {
        return Err(AppError::BadRequest("not found".into()));
    };
    if status != "pending" {
        return Err(AppError::BadRequest(format!(
            "service is {}, not pending",
            status
        )));
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
    Ok(Redirect::to("/admin/services").into_response())
}

pub async fn deny_registration(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<IdForm>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT slug, status FROM services WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(f.id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((slug, status)) = row else {
        return Err(AppError::BadRequest("not found".into()));
    };
    if status != "pending" {
        return Err(AppError::BadRequest(format!(
            "service is {}, not pending",
            status
        )));
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

// -------------------- Identity providers --------------------

pub async fn providers_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let user = user.map(|Extension(u)| u);
    require_admin(user.as_ref())?;
    let viewer = user.unwrap();
    let origin = origin_from(&state, &headers);
    let host = host_from_origin(&origin).to_string();
    let counts = load_counts(&state).await?;

    let rows: Vec<(String, String, bool, i64)> = sqlx::query_as(
        "SELECT provider, client_id, enabled, updated_at FROM oauth_providers",
    )
    .fetch_all(&state.pool)
    .await?;

    let cb = format!("{}/auth/callback", origin);
    let providers = ["github", "google"];
    let body = html! {
        (admin_header("Identity providers", Some("rotate OAuth client credentials"), None))
        p.admin-desc {
            "OAuth apps registered with each provider. Updating these takes effect on the next login attempt."
        }

        @for slug in &providers {
            @let display = provider_display_name(slug);
            @let configured = rows.iter().find(|(p, _, _, _)| p == slug);
            @let (list_url, create_url) = provider_console_urls(slug);
            div.table-wrap style="padding:20px;background:var(--bg-elev);margin-bottom:20px" {
                div style="display:flex;align-items:center;gap:12px;margin-bottom:12px" {
                    span style="width:18px;height:18px;display:inline-flex" { (provider_icon(slug)) }
                    h2 style="margin:0;font-size:15px" { (display) }
                    @if let Some((_, _, enabled, _)) = configured {
                        @if *enabled { (pill("active", "enabled")) } @else { (pill("denied", "disabled")) }
                    } @else {
                        span.pill { "not configured" }
                    }
                }
                p style="font-size:12px;color:var(--fg-mute);margin:0 0 6px 0;line-height:1.6" {
                    "manage at "
                    a target="_blank" rel="noopener" href=(list_url)
                      style="color:var(--fg);text-decoration:underline" { (list_url) }
                    " · "
                    a target="_blank" rel="noopener" href=(create_url)
                      style="color:var(--fg);text-decoration:underline" { "create new →" }
                }
                p.mono style="font-size:12px;color:var(--fg-mute);margin:0 0 4px 0" {
                    "homepage: " (origin)
                }
                p.mono style="font-size:12px;color:var(--fg-mute);margin:0 0 10px 0" {
                    "callback: " (cb)
                }
                form method="post" action=(format!("/admin/providers/save/{}", slug)) style="display:grid;gap:10px;max-width:520px" {
                    label.field { "Client ID"
                        input.input name="clientId" required
                            value=(configured.map(|(_, c, _, _)| c.as_str()).unwrap_or(""));
                    }
                    label.field { "Client Secret"
                        input.input name="clientSecret" type="password" required
                            placeholder=(if configured.is_some() { "(re-enter to update)" } else { "" });
                    }
                    div.row-actions style="margin-top:6px" {
                        button.btn.primary type="submit" { "Save" }
                        @if configured.is_some() {
                            button.btn.danger type="submit"
                                formaction=(format!("/admin/providers/clear/{}", slug))
                                formnovalidate
                                onclick=(format!(
                                    "return confirm('Clear {} credentials? Users will not be able to sign in with {} until you re-configure it.')",
                                    display, display
                                ))
                                { "Clear" }
                        }
                    }
                }
            }
        }
    };
    Ok(admin_shell(AdminTab::Providers, &viewer, &host, counts, body).into_response())
}

/// (browse-existing URL, create-new URL) for each provider's OAuth admin console.
fn provider_console_urls(slug: &str) -> (&'static str, &'static str) {
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
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
    if provider != "github" && provider != "google" {
        return Err(AppError::BadRequest("unknown provider".into()));
    }
    let cid = f.client_id.trim();
    let cs = f.client_secret.trim();
    if cid.is_empty() || cs.is_empty() {
        return Err(AppError::BadRequest(
            "Both client id and secret are required".into(),
        ));
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
    let user = user.map(|Extension(u)| u);
    let admin = require_admin(user.as_ref())?.clone();
    if provider != "github" && provider != "google" {
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
