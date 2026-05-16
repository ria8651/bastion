use anyhow::Result;
use sqlx::SqlitePool;

pub struct SetupState {
    pub has_github: bool,
    pub has_admin: bool,
    pub has_services: bool,
}

impl SetupState {
    pub fn complete(&self) -> bool {
        self.has_github && self.has_admin && self.has_services
    }
    pub fn step(&self) -> u8 {
        if !self.has_github {
            1
        } else if !self.has_admin {
            2
        } else {
            3
        }
    }
}

pub async fn get_setup_state(pool: &SqlitePool) -> Result<SetupState> {
    let gh: Option<(String,)> =
        sqlx::query_as("SELECT provider FROM oauth_providers WHERE provider = 'github'")
            .fetch_optional(pool)
            .await?;
    let (admin_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        .fetch_one(pool)
        .await?;
    let (svc_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM services")
        .fetch_one(pool)
        .await?;
    Ok(SetupState {
        has_github: gh.is_some(),
        has_admin: admin_count > 0,
        has_services: svc_count > 0,
    })
}

pub struct GithubOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
}

pub async fn get_github_oauth_config(pool: &SqlitePool) -> Result<Option<GithubOAuthConfig>> {
    let row: Option<(String, String, bool)> = sqlx::query_as(
        "SELECT client_id, client_secret, enabled FROM oauth_providers WHERE provider = 'github'",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(cid, cs, enabled)| {
        if enabled {
            Some(GithubOAuthConfig {
                client_id: cid,
                client_secret: cs,
            })
        } else {
            None
        }
    }))
}

pub async fn set_github_oauth_config(
    pool: &SqlitePool,
    client_id: &str,
    client_secret: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oauth_providers (provider, client_id, client_secret, enabled, updated_at)
         VALUES ('github', ?, ?, 1, unixepoch())
         ON CONFLICT(provider) DO UPDATE SET
            client_id = excluded.client_id,
            client_secret = excluded.client_secret,
            enabled = 1,
            updated_at = unixepoch()",
    )
    .bind(client_id)
    .bind(client_secret)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn clear_github_oauth_config(pool: &SqlitePool) -> Result<()> {
    sqlx::query("DELETE FROM oauth_providers WHERE provider = 'github'")
        .execute(pool)
        .await?;
    Ok(())
}
