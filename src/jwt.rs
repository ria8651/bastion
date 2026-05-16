use anyhow::{anyhow, Result};
use chrono::Utc;
use data_encoding::BASE64URL_NOPAD;
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, RS256};
use josekit::jwt::{self, JwtPayload};
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::keys::get_active_signing_key;

const TOKEN_TTL_SECONDS: i64 = 15 * 60;

fn random_jti() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Stable-across-wipe user identifier. Unsalted SHA-256 of "<provider>:<id>",
/// base64url-encoded. Public on purpose.
pub fn identity_hash(provider: &str, provider_user_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("{}:{}", provider, provider_user_id).as_bytes());
    BASE64URL_NOPAD.encode(&h.finalize())
}

pub struct IssueArgs<'a> {
    pub issuer: &'a str,
    pub user_id: i64,
    pub provider: &'a str,
    pub provider_user_id: &'a str,
    pub username: &'a str,
    pub service: &'a str,
    pub perms: Vec<String>,
}

pub struct IssuedToken {
    pub jwt: String,
    #[allow(dead_code)]
    pub expires_at: i64,
}

pub async fn issue_service_token(pool: &SqlitePool, args: IssueArgs<'_>) -> Result<IssuedToken> {
    let key = get_active_signing_key(pool).await?;
    let now = Utc::now().timestamp();
    let exp = now + TOKEN_TTL_SECONDS;
    let sub = identity_hash(args.provider, args.provider_user_id);

    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_key_id(&key.kid);
    header.set_algorithm("RS256");

    let mut payload = JwtPayload::new();
    payload.set_subject(&sub);
    payload.set_issuer(args.issuer);
    payload.set_audience(vec![args.service.to_string()]);
    payload.set_issued_at(&systime(now));
    payload.set_expires_at(&systime(exp));
    payload.set_jwt_id(random_jti());

    payload
        .set_claim("username", Some(Value::String(args.username.to_string())))
        .map_err(|e| anyhow!("set username: {}", e))?;
    payload
        .set_claim("svc", Some(Value::String(args.service.to_string())))
        .map_err(|e| anyhow!("set svc: {}", e))?;
    payload
        .set_claim(
            "perms",
            Some(Value::Array(
                args.perms.into_iter().map(Value::String).collect(),
            )),
        )
        .map_err(|e| anyhow!("set perms: {}", e))?;
    payload
        .set_claim(
            "bastion_uid",
            Some(Value::Number(serde_json::Number::from(args.user_id))),
        )
        .map_err(|e| anyhow!("set bastion_uid: {}", e))?;

    let signer = RS256
        .signer_from_jwk(&key.private_jwk)
        .map_err(|e| anyhow!("build signer: {}", e))?;
    let jwt = jwt::encode_with_signer(&payload, &header, &signer)
        .map_err(|e| anyhow!("encode jwt: {}", e))?;

    Ok(IssuedToken { jwt, expires_at: exp })
}

fn systime(unix: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(unix.max(0) as u64)
}

/// Verify a bastion-issued JWT against the live JWKS. Returns the payload on success.
pub async fn verify_service_token(
    pool: &SqlitePool,
    issuer: &str,
    token: &str,
) -> Result<JwtPayload> {
    let header =
        jwt::decode_header(token).map_err(|e| anyhow!("decode header: {}", e))?;
    let kid = header
        .claim("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing kid"))?;

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT public_jwk FROM signing_keys WHERE kid = ? AND retired_at IS NULL",
    )
    .bind(kid)
    .fetch_optional(pool)
    .await?;
    let (jwk_str,) = row.ok_or_else(|| anyhow!("unknown or retired kid"))?;
    let jwk =
        Jwk::from_bytes(jwk_str.as_bytes()).map_err(|e| anyhow!("decode public jwk: {}", e))?;

    let verifier = RS256
        .verifier_from_jwk(&jwk)
        .map_err(|e| anyhow!("build verifier: {}", e))?;
    let (payload, _) =
        jwt::decode_with_verifier(token, &verifier).map_err(|e| anyhow!("verify jwt: {}", e))?;

    match payload.issuer() {
        Some(iss) if iss == issuer => {}
        Some(_) => return Err(anyhow!("issuer mismatch")),
        None => return Err(anyhow!("missing issuer")),
    }
    if let Some(exp) = payload.expires_at() {
        if exp < SystemTime::now() {
            return Err(anyhow!("token expired"));
        }
    }
    Ok(payload)
}
