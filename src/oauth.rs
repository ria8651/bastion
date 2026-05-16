use anyhow::{anyhow, Result};
use data_encoding::BASE32_NOPAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tower_cookies::{cookie::SameSite, Cookie, Cookies};

use crate::setup::GithubOAuthConfig;

const STATE_COOKIE: &str = "bastion_oauth_state";
const STATE_TTL_SECONDS: i64 = 10 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    pub state: String,
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_admin: Option<bool>,
}

pub fn generate_state() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes).to_lowercase()
}

pub fn build_authorize_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    let mut u = url::Url::parse("https://github.com/login/oauth/authorize").unwrap();
    u.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", "read:user user:email")
        .append_pair("state", state);
    u.to_string()
}

pub fn set_state_cookie(cookies: &Cookies, data: &OAuthState, secure: bool) {
    let payload = serde_json::to_string(data).unwrap();
    let mut c = Cookie::new(STATE_COOKIE, payload);
    c.set_path("/");
    c.set_http_only(true);
    c.set_same_site(SameSite::Lax);
    c.set_secure(secure);
    c.set_max_age(tower_cookies::cookie::time::Duration::seconds(
        STATE_TTL_SECONDS,
    ));
    cookies.add(c);
}

pub fn read_state_cookie(cookies: &Cookies) -> Option<OAuthState> {
    let c = cookies.get(STATE_COOKIE)?;
    serde_json::from_str(c.value()).ok()
}

pub fn clear_state_cookie(cookies: &Cookies) {
    let mut c = Cookie::from(STATE_COOKIE);
    c.set_path("/");
    cookies.remove(c);
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub async fn exchange_code(
    cfg: &GithubOAuthConfig,
    redirect_uri: &str,
    code: &str,
) -> Result<String> {
    let client = reqwest::Client::builder()
        .user_agent("bastion")
        .build()?;
    let res = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", cfg.client_id.as_str()),
            ("client_secret", cfg.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await?
        .error_for_status()?;
    let body: TokenResponse = res.json().await?;
    if let Some(err) = body.error {
        return Err(anyhow!(
            "OAuth error: {} - {}",
            err,
            body.error_description.unwrap_or_default()
        ));
    }
    body.access_token
        .ok_or_else(|| anyhow!("missing access_token in response"))
}

#[derive(Debug, Deserialize)]
pub struct GithubUser {
    pub id: i64,
    pub login: String,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GhEmail {
    email: String,
    primary: bool,
    verified: bool,
}

pub async fn fetch_user(access_token: &str) -> Result<GithubUser> {
    let client = reqwest::Client::builder()
        .user_agent("bastion")
        .build()?;
    let res = client
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;
    if !res.status().is_success() {
        return Err(anyhow!("GitHub /user failed: {}", res.status()));
    }
    let mut u: GithubUser = res.json().await?;
    if u.email.is_none() {
        let emails_res = client
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?;
        if emails_res.status().is_success() {
            let emails: Vec<GhEmail> = emails_res.json().await?;
            let primary = emails
                .iter()
                .find(|e| e.primary && e.verified)
                .or_else(|| emails.iter().find(|e| e.verified));
            if let Some(p) = primary {
                u.email = Some(p.email.clone());
            }
        }
    }
    Ok(u)
}
