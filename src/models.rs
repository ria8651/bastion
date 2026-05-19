use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub avatar: Option<String>,
    pub status: String,
    pub is_admin: bool,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
    pub sub_anchor_provider: String,
    pub sub_anchor_provider_id: String,
}

/// Lightweight service-identity context, returned by verify_service_jwt for
/// requests authenticated as a service rather than a user.
#[derive(Debug, Clone)]
pub struct ServiceCtx {
    pub service_id: i64,
    pub slug: String,
}

/// Lightweight user context attached to request extensions by middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCtx {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub avatar: Option<String>,
    pub status: String,
    pub is_admin: bool,
    pub sub_anchor_provider: String,
    pub sub_anchor_provider_id: String,
}

impl From<&User> for UserCtx {
    fn from(u: &User) -> Self {
        UserCtx {
            id: u.id,
            username: u.username.clone(),
            email: u.email.clone(),
            avatar: u.avatar.clone(),
            status: u.status.clone(),
            is_admin: u.is_admin,
            sub_anchor_provider: u.sub_anchor_provider.clone(),
            sub_anchor_provider_id: u.sub_anchor_provider_id.clone(),
        }
    }
}

impl UserCtx {
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
}
