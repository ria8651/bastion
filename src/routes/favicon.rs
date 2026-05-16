use std::sync::LazyLock;

use axum::{
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};

use crate::templates::LOGO_SVG;

// `LOGO_SVG` paints with `currentColor` so in-page usage inherits the local
// text color. A favicon has no such context, so bake in the soft-white `--fg`.
static FAVICON_SVG: LazyLock<String> =
    LazyLock::new(|| LOGO_SVG.replace("currentColor", "#f3f4f5"));

pub async fn favicon() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("image/svg+xml"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    (headers, FAVICON_SVG.as_str()).into_response()
}
