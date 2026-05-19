use anyhow::Result;
use sqlx::SqlitePool;

pub struct SetupState {
    pub has_github: bool,
    pub has_google: bool,
    pub has_admin: bool,
}

impl SetupState {
    pub fn has_provider(&self) -> bool {
        self.has_github || self.has_google
    }
    /// Setup is "complete" once the gate has nothing left to require:
    /// at least one OAuth provider plus a claimed admin. Service
    /// registration is optional — services can self-register via
    /// `POST /api/services/register` and an admin can approve them at any
    /// time, including from step 3 of the wizard.
    pub fn complete(&self) -> bool {
        self.has_provider() && self.has_admin
    }
    pub fn step(&self) -> u8 {
        if !self.has_provider() {
            1
        } else if !self.has_admin {
            2
        } else {
            3
        }
    }
}

pub async fn get_setup_state(pool: &SqlitePool) -> Result<SetupState> {
    let providers: Vec<(String,)> =
        sqlx::query_as("SELECT provider FROM oauth_providers WHERE enabled = 1")
            .fetch_all(pool)
            .await?;
    let has_github = providers.iter().any(|(p,)| p == "github");
    let has_google = providers.iter().any(|(p,)| p == "google");

    let (admin_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        .fetch_one(pool)
        .await?;
    Ok(SetupState {
        has_github,
        has_google,
        has_admin: admin_count > 0,
    })
}

pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
}

pub async fn get_oauth_config(pool: &SqlitePool, provider: &str) -> Result<Option<OAuthConfig>> {
    let row: Option<(String, String, bool)> = sqlx::query_as(
        "SELECT client_id, client_secret, enabled FROM oauth_providers WHERE provider = ?",
    )
    .bind(provider)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(cid, cs, enabled)| {
        if enabled {
            Some(OAuthConfig {
                client_id: cid,
                client_secret: cs,
            })
        } else {
            None
        }
    }))
}

pub async fn set_oauth_config(
    pool: &SqlitePool,
    provider: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oauth_providers (provider, client_id, client_secret, enabled, updated_at)
         VALUES (?, ?, ?, 1, unixepoch())
         ON CONFLICT(provider) DO UPDATE SET
            client_id = excluded.client_id,
            client_secret = excluded.client_secret,
            enabled = 1,
            updated_at = unixepoch()",
    )
    .bind(provider)
    .bind(client_id)
    .bind(client_secret)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn clear_oauth_config(pool: &SqlitePool, provider: &str) -> Result<()> {
    sqlx::query("DELETE FROM oauth_providers WHERE provider = ?")
        .bind(provider)
        .execute(pool)
        .await?;
    Ok(())
}
