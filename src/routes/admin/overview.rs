use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Extension,
};
use maud::html;

use super::ui::{badge, empty, header, section, tile, user_avatar, Nav, Post, Tone};
use super::{ctx, rel_time, ProxyHealth, OPEN_REQUEST};
use crate::error::AppResult;
use crate::models::UserCtx;
use crate::state::AppState;

/// `/admin`: what's waiting on an admin, then the shape of the instance.
pub async fn overview_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;

    let pending_services: Vec<(i64, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, slug, name, registered_at FROM services
         WHERE deleted_at IS NULL AND status = 'pending'
         ORDER BY registered_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    let requests: Vec<(i64, i64, String, Option<String>, Option<String>, i64)> = sqlx::query_as(&format!(
        "SELECT r.id, u.id, u.username, u.avatar, s.slug, r.requested_at
         FROM access_requests r
         JOIN users u ON u.id = r.user_id
         LEFT JOIN services s ON s.id = r.service_id
         WHERE {OPEN_REQUEST}
         ORDER BY r.requested_at DESC LIMIT 20",
    ))
    .fetch_all(&state.pool)
    .await?;

    // Pending accounts that aren't already represented by an open request
    // above, so nobody shows up twice.
    let pending_users: Vec<(i64, String, Option<String>, Option<String>, i64)> = sqlx::query_as(&format!(
        "SELECT u.id, u.username, u.avatar, u.email, u.created_at FROM users u
         WHERE u.status = 'pending'
           AND NOT EXISTS (SELECT 1 FROM access_requests r
                           WHERE r.user_id = u.id AND {OPEN_REQUEST})
         ORDER BY u.created_at DESC",
    ))
    .fetch_all(&state.pool)
    .await?;

    let (sessions, active_7d): (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > unixepoch()),
           (SELECT COUNT(*) FROM users WHERE last_login_at > unixepoch() - 7*86400)",
    )
    .fetch_one(&state.pool)
    .await?;

    let health = ProxyHealth::load(&state).await?;
    let recent = super::audit::load_events(&state, 8).await?;
    let more_requests = ctx.counts.pending_requests as usize > requests.len();
    let nothing_waiting = pending_services.is_empty() && requests.is_empty() && pending_users.is_empty();

    let body = html! {
        (header(None, "Overview", Some(html! { (ctx.host) }), None))

        div.notices { (health.notices()) }

        @if nothing_waiting {
            (section("Needs attention", None, None,
                empty("Nothing waiting on you.", "Access requests, new accounts and service registrations show up here.")))
        }

        @if !pending_services.is_empty() {
            (section("Service registrations", Some(pending_services.len()), None, html! {
                div.list {
                    @for (id, slug, name, registered) in &pending_services {
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

        @if !requests.is_empty() {
            (section("Access requests", Some(ctx.counts.pending_requests as usize),
                more_requests.then(|| html! { a href="/admin/requests" { "view all ›" } }),
                html! {
                div.list {
                    @for (rid, uid, uname, avatar, slug, at) in &requests {
                        @let rid = rid.to_string();
                        div.row.decide {
                            a.lead href=(format!("/admin/users/{}", uid)) { (user_avatar(avatar.as_deref(), uname, "lg")) }
                            div.row-body {
                                div.main {
                                    div.t { a href=(format!("/admin/users/{}", uid)) { (uname) } }
                                    div.s {
                                        "wants " (slug.as_deref().unwrap_or("an account")) " · " (rel_time(*at))
                                    }
                                }
                            }
                            div.end {
                                (Post::new("/admin/requests/deny", "Deny").class("btn sm bad")
                                    .fields(&[("id", &rid), ("next", "/admin")]).stay().render())
                                (Post::new("/admin/requests/approve", "Approve").class("btn sm primary")
                                    .fields(&[("id", &rid), ("next", "/admin")]).stay().render())
                            }
                        }
                    }
                }
            }))
        }

        @if !pending_users.is_empty() {
            (section("New accounts", Some(pending_users.len()), None, html! {
                p.sec-desc { "Signed in but not yet approved, and not asking for any particular service." }
                div.list {
                    @for (uid, uname, avatar, email, created) in &pending_users {
                        @let uid_s = uid.to_string();
                        div.row.decide {
                            a.lead href=(format!("/admin/users/{}", uid)) { (user_avatar(avatar.as_deref(), uname, "lg")) }
                            div.row-body {
                                div.main {
                                    div.t { a href=(format!("/admin/users/{}", uid)) { (uname) } }
                                    div.s { (email.as_deref().unwrap_or("no email")) " · joined " (rel_time(*created)) }
                                }
                            }
                            div.end {
                                (Post::new("/admin/users/set-status", "Deny").class("btn sm bad")
                                    .fields(&[("id", &uid_s), ("status", "denied"), ("next", "/admin")]).stay().render())
                                (Post::new("/admin/users/set-status", "Approve").class("btn sm primary")
                                    .fields(&[("id", &uid_s), ("status", "active"), ("next", "/admin")]).stay().render())
                            }
                        }
                    }
                }
            }))
        }

        (section("At a glance", None, None, html! {
            div.stats {
                a.stat href="/admin/users" { div.v { (ctx.counts.users) } div.k { "users" } }
                div.stat { div.v { (active_7d) } div.k { "signed in, last 7 days" } }
                a.stat href="/admin/services" { div.v { (ctx.counts.services) } div.k { "services" } }
                div.stat { div.v { (sessions) } div.k { "active sessions" } }
            }
        }))

        (section("Recent activity", None, Some(html! { a href="/admin/audit" { "audit log ›" } }),
            if recent.is_empty() {
                empty("No activity yet.", "")
            } else {
                super::audit::render_log(&recent)
            }))
    };
    Ok(ctx.page(Nav::Overview, "Overview", body).into_response())
}
