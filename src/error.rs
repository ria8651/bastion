use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use maud::{html, Markup, DOCTYPE};

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
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let msg = self.to_string();
        if matches!(status, StatusCode::INTERNAL_SERVER_ERROR) {
            tracing::error!(error = ?self, "server error");
        }
        let body: Markup = html! {
            (DOCTYPE)
            html lang="en" {
                head { meta charset="utf-8"; title { (status.as_u16()) " — bastion" } }
                body style="background:#0f1115;color:#e6e8eb;font-family:system-ui;padding:2rem;max-width:640px;margin:0 auto;" {
                    h1 { (status.as_u16()) " — " (status.canonical_reason().unwrap_or("error")) }
                    p style="color:#9aa4af" { (msg) }
                    p { a href="/" style="color:#7cb7ff" { "Home" } }
                }
            }
        };
        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
