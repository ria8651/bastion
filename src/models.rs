use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: i64,
    pub github_id: i64,
    pub username: String,
    pub email: Option<String>,
    pub avatar: Option<String>,
    pub status: String,
    pub is_admin: bool,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Service {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub return_url: String,
    pub created_at: i64,
}

/// Lightweight user context attached to request extensions by middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCtx {
    pub id: i64,
    pub github_id: i64,
    pub username: String,
    pub email: Option<String>,
    pub avatar: Option<String>,
    pub status: String,
    pub is_admin: bool,
}

impl From<&User> for UserCtx {
    fn from(u: &User) -> Self {
        UserCtx {
            id: u.id,
            github_id: u.github_id,
            username: u.username.clone(),
            email: u.email.clone(),
            avatar: u.avatar.clone(),
            status: u.status.clone(),
            is_admin: u.is_admin,
        }
    }
}

impl UserCtx {
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
}
