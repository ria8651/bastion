use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Extension,
};
use maud::{html, Markup};

use super::ui::{empty, header, Nav};
use super::{ctx, fmt_time, rel_time};
use crate::error::AppResult;
use crate::models::UserCtx;
use crate::state::AppState;

const PAGE_LIMIT: i64 = 200;

pub(super) struct Event {
    at: i64,
    action: String,
    actor: Option<String>,
    target: Option<String>,
    meta: Option<String>,
}

pub(super) async fn load_events(state: &AppState, limit: i64) -> AppResult<Vec<Event>> {
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
             ORDER BY a.at DESC, a.id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&state.pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(at, action, actor, target, meta)| Event { at, action, actor, target, meta })
        .collect())
}

pub(super) fn render_log(events: &[Event]) -> Markup {
    html! {
        div.list.log {
            @for e in events {
                div class=(format!("log-row {}", tone(&e.action))) {
                    time.ts datetime=(e.at) title=(fmt_time(e.at)) { (fmt_time(e.at)) }
                    div.ev {
                        span.a { (e.action) }
                        @if let Some(t) = &e.target { span.tgt { (t) } }
                    }
                    span.actor title=(rel_time(e.at)) { (e.actor.as_deref().unwrap_or("system")) }
                    @if let Some(m) = e.meta.as_deref().and_then(meta_line) {
                        div.meta { (m) }
                    }
                }
            }
        }
    }
}

/// Flatten the JSON meta into `key: value · key: value` — enough to see what
/// changed without a click-through.
fn meta_line(raw: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let obj = v.as_object()?;
    let parts: Vec<String> = obj
        .iter()
        .map(|(k, v)| match v {
            serde_json::Value::String(s) => format!("{}: {}", k, s),
            other => format!("{}: {}", k, other),
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

/// Colour of the dot: things that take access away, things that grant or
/// configure it, and everything else.
fn tone(action: &str) -> &'static str {
    if action.ends_with(".deny")
        || action.ends_with(".revoke")
        || action.ends_with(".revoke_all")
        || action.ends_with(".remove")
        || action.ends_with("_cleared")
        || action.ends_with("_unlinked")
    {
        "bad"
    } else if action.ends_with(".add")
        || action.ends_with(".approve")
        || action.ends_with(".grant")
        || action.ends_with("_configured")
        || action.ends_with("_linked")
        || action == "setup.claim_admin"
    {
        "ok"
    } else {
        ""
    }
}

pub async fn audit_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<Response> {
    let ctx = ctx(&state, &headers, user).await?;
    let events = load_events(&state, PAGE_LIMIT).await?;
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&state.pool)
        .await?;

    let body = html! {
        (header(None, "Audit log", Some(html! { "append-only · " (total) " events" }), None))
        @if events.is_empty() {
            (empty("No events yet.", "Admin actions and service registrations are recorded here."))
        } @else {
            (render_log(&events))
            @if total > events.len() as i64 {
                div.list-foot { "showing the latest " (events.len()) " of " (total) }
            }
        }
    };
    Ok(ctx.page(Nav::Audit, "Audit log", body).into_response())
}
