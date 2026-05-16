use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use crate::keys::get_public_jwks;
use crate::state::AppState;

pub async fn jwks(State(state): State<AppState>) -> Response {
    match get_public_jwks(&state.pool).await {
        Ok(jwks) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            );
            (headers, Json(jwks)).into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, "jwks");
            (StatusCode::INTERNAL_SERVER_ERROR, "jwks error").into_response()
        }
    }
}
