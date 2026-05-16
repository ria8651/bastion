use anyhow::{anyhow, Result};
use data_encoding::BASE32_NOPAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tower_cookies::{cookie::SameSite, Cookie, Cookies};

use crate::setup::OAuthConfig;

const STATE_COOKIE: &str = "bastion_oauth_state";
const STATE_TTL_SECONDS: i64 = 10 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Github,
    Google,
}

impl Provider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Github => "github",
            Provider::Google => "google",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "github" => Some(Provider::Github),
            "google" => Some(Provider::Google),
            _ => None,
        }
    }
    pub fn display_name(&self) -> &'static str {
        match self {
            Provider::Github => "GitHub",
            Provider::Google => "Google",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    pub state: String,
    pub provider: Provider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_admin: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_to_user_id: Option<i64>,
}

pub fn generate_state() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes).to_lowercase()
}

pub fn build_authorize_url(
    provider: Provider,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
) -> String {
    match provider {
        Provider::Github => {
            let mut u = url::Url::parse("https://github.com/login/oauth/authorize").unwrap();
            u.query_pairs_mut()
                .append_pair("client_id", client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("scope", "read:user user:email")
                .append_pair("state", state);
            u.to_string()
        }
        Provider::Google => {
            let mut u = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap();
            u.query_pairs_mut()
                .append_pair("client_id", client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", "openid email profile")
                .append_pair("access_type", "online")
                .append_pair("prompt", "select_account")
                .append_pair("state", state);
            u.to_string()
        }
    }
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

/// Provider-agnostic remote-user payload after a successful OAuth round-trip.
pub struct RemoteUser {
    pub provider_id: String,
    pub username: String,
    pub email: Option<String>,
    pub avatar: Option<String>,
}

pub async fn exchange_code(
    provider: Provider,
    cfg: &OAuthConfig,
    redirect_uri: &str,
    code: &str,
) -> Result<String> {
    match provider {
        Provider::Github => exchange_code_github(cfg, redirect_uri, code).await,
        Provider::Google => exchange_code_google(cfg, redirect_uri, code).await,
    }
}

pub async fn fetch_user(provider: Provider, access_token: &str) -> Result<RemoteUser> {
    match provider {
        Provider::Github => fetch_user_github(access_token).await,
        Provider::Google => fetch_user_google(access_token).await,
    }
}

// ──────────────────────── GitHub ────────────────────────

#[derive(Debug, Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn exchange_code_github(cfg: &OAuthConfig, redirect_uri: &str, code: &str) -> Result<String> {
    let client = reqwest::Client::builder().user_agent("bastion").build()?;
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
    let body: GithubTokenResponse = res.json().await?;
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
struct GithubUser {
    id: i64,
    login: String,
    email: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GhEmail {
    email: String,
    primary: bool,
    verified: bool,
}

async fn fetch_user_github(access_token: &str) -> Result<RemoteUser> {
    let client = reqwest::Client::builder().user_agent("bastion").build()?;
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
    Ok(RemoteUser {
        provider_id: u.id.to_string(),
        username: u.login,
        email: u.email,
        avatar: u.avatar_url,
    })
}

// ──────────────────────── Google ────────────────────────

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn exchange_code_google(cfg: &OAuthConfig, redirect_uri: &str, code: &str) -> Result<String> {
    let client = reqwest::Client::builder().user_agent("bastion").build()?;
    let res = client
        .post("https://oauth2.googleapis.com/token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", cfg.client_id.as_str()),
            ("client_secret", cfg.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await?;
    let status = res.status();
    let body: GoogleTokenResponse = res.json().await?;
    if let Some(err) = body.error {
        return Err(anyhow!(
            "OAuth error: {} - {}",
            err,
            body.error_description.unwrap_or_default()
        ));
    }
    if !status.is_success() {
        return Err(anyhow!("Google token endpoint returned {}", status));
    }
    body.access_token
        .ok_or_else(|| anyhow!("missing access_token in Google response"))
}

#[derive(Debug, Deserialize)]
struct GoogleUserinfo {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    picture: Option<String>,
}

async fn fetch_user_google(access_token: &str) -> Result<RemoteUser> {
    let client = reqwest::Client::builder().user_agent("bastion").build()?;
    let res = client
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(access_token)
        .send()
        .await?;
    if !res.status().is_success() {
        return Err(anyhow!("Google userinfo failed: {}", res.status()));
    }
    let u: GoogleUserinfo = res.json().await?;
    // Only treat the email as known if Google says it's verified.
    let email = u
        .email
        .as_ref()
        .filter(|_| u.email_verified.unwrap_or(false))
        .cloned();
    let username = email
        .as_deref()
        .and_then(|e| e.split('@').next())
        .map(sanitize_username)
        .or_else(|| u.name.as_deref().map(sanitize_username))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("google-{}", &u.sub));
    Ok(RemoteUser {
        provider_id: u.sub,
        username,
        email,
        avatar: u.picture,
    })
}

fn sanitize_username(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}
