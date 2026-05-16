use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use tower_cookies::Cookies;

use crate::error::AppError;
use crate::models::UserCtx;
use crate::session::{clear_session_cookie, read_session_cookie, validate_session_token};
use crate::setup::get_setup_state;
use crate::state::AppState;

/// Loads the signed-in user (if any) into request extensions.
pub async fn load_user(
    State(state): State<AppState>,
    cookies: Cookies,
    mut req: Request,
    next: Next,
) -> Response {
    if let Some(token) = read_session_cookie(&cookies) {
        match validate_session_token(&state.pool, &token).await {
            Ok(Some((user, _sid))) => {
                let ctx: UserCtx = (&user).into();
                req.extensions_mut().insert(ctx);
            }
            Ok(None) => {
                clear_session_cookie(&cookies);
            }
            Err(e) => {
                tracing::error!(error = ?e, "session validation failed");
            }
        }
    }
    next.run(req).await
}

/// Redirects to /setup until first-run setup is complete, except for /setup and the auth flow.
pub async fn setup_gate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let exempt = path.starts_with("/setup")
        || path.starts_with("/auth/")
        || path.starts_with("/static/")
        || path.starts_with("/.well-known/")
        || path.starts_with("/api/");
    if !exempt {
        match get_setup_state(&state.pool).await {
            Ok(s) if !s.complete() => return Redirect::to("/setup").into_response(),
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = ?e, "setup state lookup");
                return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
            }
        }
    }
    next.run(req).await
}

pub fn require_admin(user: Option<&UserCtx>) -> Result<&UserCtx, AppError> {
    let u = user.ok_or(AppError::Unauthorized)?;
    if !u.is_admin() {
        return Err(AppError::Forbidden);
    }
    Ok(u)
}
