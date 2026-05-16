use anyhow::{anyhow, Result};
use data_encoding::BASE32_NOPAD;
use josekit::jwk::Jwk;
use josekit::jws::RS256;
use rand::RngCore;
use serde_json::Value;
use sqlx::SqlitePool;

const ALG: &str = "RS256";

fn new_kid() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes).to_lowercase()
}

pub struct ActiveKey {
    pub kid: String,
    pub private_jwk: Jwk,
}

/// Get the active signing key, generating one on first use.
pub async fn get_active_signing_key(pool: &SqlitePool) -> Result<ActiveKey> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT kid, private_jwk FROM signing_keys WHERE retired_at IS NULL LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    if let Some((kid, private_jwk)) = row {
        let jwk = Jwk::from_bytes(private_jwk.as_bytes())
            .map_err(|e| anyhow!("decode private jwk: {}", e))?;
        return Ok(ActiveKey {
            kid,
            private_jwk: jwk,
        });
    }

    // Generate a fresh RSA 2048 keypair, split into public + private JWKs.
    let keypair = RS256
        .generate_key_pair(2048)
        .map_err(|e| anyhow!("rsa keygen: {}", e))?;
    let mut private_jwk = keypair.to_jwk_private_key();
    let mut public_jwk = keypair.to_jwk_public_key();

    let kid = new_kid();
    private_jwk.set_key_id(&kid);
    private_jwk.set_algorithm(ALG);
    public_jwk.set_key_id(&kid);
    public_jwk.set_algorithm(ALG);
    public_jwk.set_key_use("sig");

    let pub_str = serde_json::to_string(public_jwk.as_ref())?;
    let priv_str = serde_json::to_string(private_jwk.as_ref())?;

    sqlx::query(
        "INSERT INTO signing_keys (kid, alg, public_jwk, private_jwk) VALUES (?, ?, ?, ?)",
    )
    .bind(&kid)
    .bind(ALG)
    .bind(&pub_str)
    .bind(&priv_str)
    .execute(pool)
    .await?;

    Ok(ActiveKey { kid, private_jwk })
}

/// Public JWKS (all non-retired public keys), as JSON.
pub async fn get_public_jwks(pool: &SqlitePool) -> Result<Value> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT public_jwk FROM signing_keys WHERE retired_at IS NULL")
            .fetch_all(pool)
            .await?;
    let keys: Vec<Value> = rows
        .into_iter()
        .filter_map(|(s,)| serde_json::from_str(&s).ok())
        .collect();
    Ok(serde_json::json!({ "keys": keys }))
}
