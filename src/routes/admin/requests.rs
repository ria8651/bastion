use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Extension, Form,
};
use maud::{html, Markup};
use serde::Deserialize;

use super::ui::{empty, header, status_badge, user_avatar, Nav, Post};
use super::{admin, back_to, ctx, rel_time, OPEN_REQUEST};
use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::models::UserCtx;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RequestsQuery {
    pub filter: Option<String>,
}

pub async fn requests_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
    Query(q): Query<RequestsQuery>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;

    let filter = match q.filter.as_deref() {
        Some(f @ ("granted" | "denied" | "all")) => f,
        _ => "pending",
    };
    let where_clause = match filter {
        "granted" => "r.resolved_at IS NOT NULL AND r.decision = 'approved'",
        "denied" => "r.resolved_at IS NOT NULL AND r.decision = 'denied'",
        "all" => "1=1",
        _ => OPEN_REQUEST,
    };
    let sql = format!(
        "SELECT r.id, u.id, u.username, u.avatar, s.slug, r.requested_at, r.resolved_at,
                r.decision, u.created_at
         FROM access_requests r
         JOIN users u ON u.id = r.user_id
         LEFT JOIN services s ON s.id = r.service_id
         WHERE {}
         ORDER BY r.requested_at DESC LIMIT 100",
        where_clause
    );
    #[allow(clippy::type_complexity)]
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
    )> = sqlx::query_as(&sql).fetch_all(&state.pool).await?;

    let (pending_n, granted_n, denied_n, all_n): (i64, i64, i64, i64) = sqlx::query_as(&format!(
        "SELECT
           COALESCE(SUM({OPEN_REQUEST}), 0),
           COALESCE(SUM(r.resolved_at IS NOT NULL AND r.decision = 'approved'), 0),
           COALESCE(SUM(r.resolved_at IS NOT NULL AND r.decision = 'denied'), 0),
           COUNT(*)
         FROM access_requests r",
    ))
    .fetch_one(&state.pool)
    .await?;

    let here = format!("/admin/requests?filter={}", filter);
    let body = html! {
        (header(None, "Access requests", Some(html! { (pending_n) " pending" }), None))
        nav.seg aria-label="Filter requests" {
            (seg("pending", pending_n, filter))
            (seg("granted", granted_n, filter))
            (seg("denied", denied_n, filter))
            (seg("all", all_n, filter))
        }
        @if rows.is_empty() {
            @if filter == "pending" {
                (empty("No pending requests.", "When someone without a grant tries to sign in to a service, the request lands here."))
            } @else {
                (empty("Nothing here.", "No requests match this filter."))
            }
        } @else {
            div.list {
                @for (rid, uid, uname, avatar, slug, at, resolved, decision, created) in &rows {
                    @let rid = rid.to_string();
                    div.row.decide {
                        a.lead href=(format!("/admin/users/{}", uid)) { (user_avatar(avatar.as_deref(), uname, "lg")) }
                        div.row-body {
                            div.main {
                                div.t {
                                    a href=(format!("/admin/users/{}", uid)) { (uname) }
                                    span.mute { " → " }
                                    (slug.as_deref().unwrap_or("account"))
                                }
                                div.s {
                                    (rel_time(*at))
                                    " · account " (rel_time(*created).replace(" ago", " old"))
                                }
                            }
                            @if resolved.is_some() {
                                div.meta {
                                    @match decision.as_deref() {
                                        Some("approved") => (status_badge("granted")),
                                        Some("denied") => (status_badge("denied")),
                                        _ => (status_badge("resolved")),
                                    }
                                }
                            }
                        }
                        @if resolved.is_none() {
                            div.end {
                                (Post::new("/admin/requests/deny", "Deny").class("btn sm bad")
                                    .fields(&[("id", &rid), ("next", &here)]).stay().render())
                                (Post::new("/admin/requests/approve", "Approve").class("btn sm primary")
                                    .fields(&[("id", &rid), ("next", &here)]).stay().render())
                            }
                        }
                    }
                }
            }
        }
    };
    Ok(ctx
        .page(Nav::Requests, "Access requests", body)
        .into_response())
}

fn seg(label: &str, n: i64, active: &str) -> Markup {
    html! {
        a href=(format!("/admin/requests?filter={}", label))
            aria-current=[(label == active).then_some("page")] {
            span { (label) }
            span.n { (n) }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RequestForm {
    pub id: i64,
    pub next: Option<String>,
}

pub async fn approve_request(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<RequestForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;

    let req: Option<(i64, Option<i64>, Option<i64>)> =
        sqlx::query_as("SELECT user_id, service_id, resolved_at FROM access_requests WHERE id = ?")
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
    Ok(back_to(f.next.as_deref(), "/admin/requests").into_response())
}

pub async fn deny_request(
    State(state): State<AppState>,
    user: Option<Extension<UserCtx>>,
    Form(f): Form<RequestForm>,
) -> AppResult<Response> {
    let admin = admin(user)?;

    let req: Option<(i64, Option<i64>, Option<i64>)> =
        sqlx::query_as("SELECT user_id, service_id, resolved_at FROM access_requests WHERE id = ?")
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
    Ok(back_to(f.next.as_deref(), "/admin/requests").into_response())
}
