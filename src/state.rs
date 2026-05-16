use axum::http::HeaderMap;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    /// Public-facing origin. If `None`, derived from request headers (Host /
    /// X-Forwarded-Host / X-Forwarded-Proto). Set ORIGIN env var to pin it
    /// behind a reverse proxy.
    pub origin: Option<String>,
}

pub fn origin_from(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(o) = &state.origin {
        return o.trim_end_matches('/').to_string();
    }
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:5180");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if host.starts_with("localhost") || host.starts_with("127.0.0.1") {
                "http".into()
            } else {
                "https".into()
            }
        });
    format!("{}://{}", proto, host)
}

pub fn is_secure(state: &AppState, headers: &HeaderMap) -> bool {
    origin_from(state, headers).starts_with("https://")
}
