//! Admin panel. One module per section; `ui` holds the shell and components.
//! Every mutation keeps the post-redirect-get shape: do the work, 303 back to
//! a page, let hx-boost swap it in.

use axum::http::HeaderMap;
use axum::response::Redirect;
use axum::Extension;
use chrono::{TimeZone, Utc};

use crate::error::AppResult;
use crate::middleware::require_admin;
use crate::models::UserCtx;
use crate::state::{origin_from, AppState};
use crate::templates::host_from_origin;

mod audit;
mod overview;
mod providers;
mod requests;
mod routes;
mod services;
mod settings;
pub mod ui;
mod users;

pub use audit::*;
pub use overview::*;
pub use providers::*;
pub use requests::*;
pub use routes::*;
pub use services::*;
pub use settings::*;
pub use users::*;

pub fn fmt_time(unix: i64) -> String {
    Utc.timestamp_opt(unix, 0)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

pub fn rel_time(unix: i64) -> String {
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

/// An access request still waiting on a decision, over `access_requests r`.
/// One for a service that has since been removed can't be acted on usefully,
/// so it neither shows in the queue nor counts toward the badge.
const OPEN_REQUEST: &str = "r.resolved_at IS NULL AND (r.service_id IS NULL OR EXISTS (
    SELECT 1 FROM services s_ WHERE s_.id = r.service_id AND s_.deleted_at IS NULL))";

/// Gate on admin and gather what the shell needs. Every admin page starts here.
async fn ctx(
    state: &AppState,
    headers: &HeaderMap,
    user: Option<Extension<UserCtx>>,
) -> AppResult<ui::Ctx> {
    let user = user.map(|Extension(u)| u);
    let viewer = require_admin(user.as_ref())?.clone();
    let host = host_from_origin(&origin_from(state, headers)).to_string();
    let (users, pending_requests, services, pending_services, routes): (i64, i64, i64, i64, i64) =
        sqlx::query_as(&format!(
            "SELECT
               (SELECT COUNT(*) FROM users),
               (SELECT COUNT(*) FROM access_requests r WHERE {OPEN_REQUEST}),
               (SELECT COUNT(*) FROM services WHERE deleted_at IS NULL AND status = 'approved'),
               (SELECT COUNT(*) FROM services WHERE deleted_at IS NULL AND status = 'pending'),
               (SELECT COUNT(*) FROM routes)",
        ))
        .fetch_one(&state.pool)
        .await?;
    Ok(ui::Ctx {
        viewer,
        host,
        counts: ui::NavCounts { users, pending_requests, services, pending_services, routes },
    })
}

/// Admin-only mutations take the user the same way; this is the shared check.
fn admin(user: Option<Extension<UserCtx>>) -> AppResult<UserCtx> {
    let user = user.map(|Extension(u)| u);
    Ok(require_admin(user.as_ref())?.clone())
}

fn back_to(next: Option<&str>, fallback: &str) -> Redirect {
    Redirect::to(&ui::next_or(next, fallback))
}

/// Settings that, when missing, break gated routes in ways whose symptoms
/// point nowhere near the cause. Shown on the overview, the settings page, the
/// routes pages and any service that gates a route.
pub(crate) struct ProxyHealth {
    pub any_gated: bool,
    pub cookie_domain: Option<String>,
    pub origin_pinned: bool,
}

impl ProxyHealth {
    async fn load(state: &AppState) -> AppResult<ProxyHealth> {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM routes WHERE enabled = 1 AND service_id IS NOT NULL",
        )
        .fetch_one(&state.pool)
        .await?;
        Ok(ProxyHealth {
            any_gated: n > 0,
            cookie_domain: crate::settings::cookie_domain(&state.pool).await,
            origin_pinned: state.origin.is_some(),
        })
    }

    fn notices(&self) -> maud::Markup {
        use ui::{notice, Tone};
        maud::html! {
            @if self.any_gated && self.cookie_domain.is_none() {
                (notice(Tone::Warn, maud::html! {
                    strong { "Session cookie domain isn't set." }
                    " Some routes are gated, but sessions are host-only, so the "
                    "gated hosts never see them and every request looks signed out. "
                    a href="/admin/settings" { "Set it in Settings" } "."
                }))
            }
            @if self.any_gated && !self.origin_pinned {
                (notice(Tone::Warn, maud::html! {
                    strong { "ORIGIN isn't set." }
                    " Login redirects are guessed from the request's Host header, which on a "
                    "gated request is the app's hostname, not bastion's. Pin it in the environment."
                }))
            }
        }
    }
}
