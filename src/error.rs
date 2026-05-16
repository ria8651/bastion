use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use maud::{html, Markup};

use crate::templates::{bottom_strip, corner_mark, layout};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("not signed in")]
    Unauthorized,
    #[error("admin only")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl AppError {
    fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Sqlx(_) | AppError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn headline(&self) -> &'static str {
        match self {
            AppError::BadRequest(_) => "Bad request",
            AppError::Unauthorized => "Sign in required",
            AppError::Forbidden => "Forbidden",
            AppError::NotFound => "Not found",
            AppError::Sqlx(_) | AppError::Other(_) => "Server error",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let headline = self.headline();
        let msg = self.to_string();
        let is_500 = matches!(status, StatusCode::INTERNAL_SERVER_ERROR);
        if is_500 {
            tracing::error!(error = ?self, "server error");
        }
        let body: Markup = html! {
            div.page-chrome.narrow {
                (corner_mark(Some("error")))
            }
            div.error-page {
                div.status { (status.as_u16()) " · " (status.canonical_reason().unwrap_or("error")) }
                h1 { (headline) }
                @if !is_500 || !msg.is_empty() {
                    div.detail { (msg) }
                }
                div.actions {
                    a.btn.primary href="/" { "Home" }
                    @if matches!(status, StatusCode::UNAUTHORIZED) {
                        a.btn href="/auth/login" { "Sign in" }
                    }
                }
            }
            (bottom_strip(None, true))
        };
        (status, layout(&format!("{} — bastion", status.as_u16()), body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
