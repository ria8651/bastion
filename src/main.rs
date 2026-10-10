mod audit;
mod db;
mod edge;
mod error;
mod forwarded;
mod grants;
mod host;
mod jwt;
mod keys;
mod middleware;
mod models;
mod oauth;
mod proxy;
mod routes;
mod serve;
mod session;
mod settings;
mod setup;
mod state;
mod templates;
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context};

use axum::{
    middleware as axmw,
    routing::{get, post},
    Router,
};
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;

use crate::state::{AppState, Edge};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,sqlx=warn,tower_http=info")),
        )
        .init();

    let database_path =
        std::env::var("DATABASE_PATH").unwrap_or_else(|_| "./data/bastion.db".to_string());
    let origin = std::env::var("ORIGIN").ok().filter(|s| !s.is_empty());
    let port = env_port("PORT", 5180)?;
    let trusted = forwarded::Trusted::parse(env("TRUSTED_PROXIES").as_deref())
        .map_err(anyhow::Error::msg)?;
    let edge = edge_config(origin.as_deref())?;

    tracing::info!(db = %database_path, "connecting to sqlite");
    let pool = db::connect(&database_path).await?;
    let state = AppState {
        pool,
        origin,
        proxy: proxy::client(),
        trusted: Arc::new(trusted),
        ports: std::iter::once(port)
            .chain(edge.iter().flat_map(|e| std::iter::once(e.https_port).chain(e.http_port)))
            .collect(),
        edge: edge.clone(),
    };

    let app = Router::new()
        // public
        .route("/favicon.svg", get(routes::favicon::favicon))
        .route("/", get(routes::home::index))
        .route("/pending", get(routes::home::pending))
        .route("/denied", get(routes::home::denied))
        // auth
        .route(
            "/auth/login",
            get(routes::auth::login_page).post(routes::auth::login_post),
        )
        .route("/auth/callback", get(routes::auth::callback))
        .route("/auth/logout", post(routes::auth::logout))
        .route("/launch/:slug", get(routes::auth::launch))
        // setup
        .route("/setup", get(routes::setup::page))
        .route(
            "/setup/save-provider/:provider",
            post(routes::setup::save_provider),
        )
        .route(
            "/setup/reset-provider/:provider",
            post(routes::setup::reset_provider),
        )
        .route("/setup/pending", get(routes::setup::pending_partial))
        .route("/setup/add-service", post(routes::setup::add_service))
        .route("/setup/remove-service", post(routes::setup::remove_service))
        .route("/setup/approve-service", post(routes::setup::approve_service))
        .route("/setup/deny-service", post(routes::setup::deny_service))
        .route("/setup/finish", post(routes::setup::finish))
        // account
        .route("/account", get(routes::account::page))
        .route("/account/link", post(routes::account::link_post))
        .route("/account/unlink", post(routes::account::unlink_post))
        // admin
        .route("/admin", get(routes::admin::overview_page))
        .route("/admin/audit", get(routes::admin::audit_page))
        .route("/admin/requests", get(routes::admin::requests_page))
        .route(
            "/admin/requests/approve",
            post(routes::admin::approve_request),
        )
        .route("/admin/requests/deny", post(routes::admin::deny_request))
        .route("/admin/users", get(routes::admin::users_page))
        .route("/admin/users/set-status", post(routes::admin::set_status))
        .route("/admin/users/set-admin", post(routes::admin::set_admin))
        .route("/admin/users/:id", get(routes::admin::user_detail))
        .route(
            "/admin/users/:id/toggle-grant",
            post(routes::admin::toggle_grant),
        )
        .route(
            "/admin/users/:id/toggle-perm",
            post(routes::admin::toggle_perm),
        )
        .route(
            "/admin/users/:id/revoke-sessions",
            post(routes::admin::revoke_sessions),
        )
        .route("/admin/services", get(routes::admin::services_page))
        .route("/admin/services/new", get(routes::admin::service_new_page))
        .route("/admin/services/:id", get(routes::admin::service_detail))
        .route("/admin/services/add", post(routes::admin::add_service))
        .route(
            "/admin/services/update",
            post(routes::admin::update_service),
        )
        .route(
            "/admin/services/remove",
            post(routes::admin::remove_service),
        )
        .route(
            "/admin/services/approve-registration",
            post(routes::admin::approve_registration),
        )
        .route(
            "/admin/services/deny-registration",
            post(routes::admin::deny_registration),
        )
        .route("/admin/routes", get(routes::admin::routes_page))
        .route("/admin/routes/new", get(routes::admin::route_new_page))
        .route("/admin/routes/:id", get(routes::admin::route_detail))
        .route("/admin/routes/add", post(routes::admin::add_route))
        .route("/admin/routes/update", post(routes::admin::update_route))
        .route("/admin/routes/toggle", post(routes::admin::toggle_route))
        .route("/admin/routes/remove", post(routes::admin::remove_route))
        .route("/admin/providers", get(routes::admin::providers_page))
        .route("/admin/settings", get(routes::admin::settings_page))
        .route(
            "/admin/settings/cookie-domain",
            post(routes::admin::cookie_domain_save),
        )
        .route(
            "/admin/providers/save/:provider",
            post(routes::admin::providers_save),
        )
        .route(
            "/admin/providers/clear/:provider",
            post(routes::admin::providers_clear),
        )
        // public api
        .route("/.well-known/jwks.json", get(routes::jwks::jwks))
        .route("/api/introspect", get(routes::introspect::introspect))
        .route(
            "/api/services/register",
            post(routes::registration::register),
        )
        .route(
            "/api/services/:slug/status",
            get(routes::registration::status),
        )
        .route(
            "/api/services/:slug/permissions",
            axum::routing::put(routes::registration::put_permissions),
        )
        // middleware
        .layer(axmw::from_fn_with_state(state.clone(), middleware::setup_gate))
        .layer(axmw::from_fn_with_state(state.clone(), middleware::load_user))
        // Outside load_user and setup_gate — a gated host is not part of
        // bastion's UI and must not be redirected into the setup wizard — but
        // inside the cookie layer, since it reads the session itself.
        .layer(axmw::from_fn_with_state(state.clone(), proxy::proxy_gate))
        .layer(CookieManagerLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    // The plaintext port always runs. Behind a gateway it is the only one;
    // as the edge it is the LAN way in that doesn't depend on the certificate.
    let mut listeners = tokio::task::JoinSet::new();
    listeners.spawn(serve::plain(bind(port, "http").await?, app.clone()));

    if let Some(edge) = &edge {
        edge.certs.clone().spawn_reloader();
        let config = Arc::new(tls::server_config(edge.certs.clone())?);
        listeners.spawn(serve::tls(bind(edge.https_port, "https").await?, config, app.clone()));
        if let Some(p) = edge.http_port {
            let redirect = serve::redirect_app(state.clone(), edge.https_port);
            listeners.spawn(serve::plain(bind(p, "http → https redirect").await?, redirect));
        }
    }

    // The accept loops never return; if one panics, go down with it rather
    // than limp on with a port silently dead.
    if let Some(Err(e)) = listeners.join_next().await {
        bail!("listener crashed: {}", e);
    }
    Ok(())
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn env_port(key: &str, default: u16) -> anyhow::Result<u16> {
    match env(key) {
        Some(s) => s.parse().with_context(|| format!("{} must be a port number, got {:?}", key, s)),
        None => Ok(default),
    }
}

async fn bind(port: u16, what: &str) -> anyhow::Result<tokio::net::TcpListener> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {} on {}", what, addr))?;
    tracing::info!(%addr, "listening ({})", what);
    Ok(listener)
}

/// `TLS_CERT` + `TLS_KEY` turn on the edge listeners: TLS on `HTTPS_PORT`
/// (443) and a redirect to it on `HTTP_PORT` (80, or `off`).
fn edge_config(origin: Option<&str>) -> anyhow::Result<Option<Arc<Edge>>> {
    let (cert, key) = match (env("TLS_CERT"), env("TLS_KEY")) {
        (Some(c), Some(k)) => (c, k),
        (None, None) => return Ok(None),
        _ => bail!("TLS_CERT and TLS_KEY go together: set both or neither"),
    };
    // As the edge, the only other source for bastion's own name is the Host
    // and X-Forwarded-Host of whoever connects — anyone on the internet.
    if origin.is_none() {
        bail!("TLS_CERT is set but ORIGIN isn't: as the edge, bastion must be told its own name");
    }
    let certs = tls::CertStore::load(cert.into(), key.into())?;
    let info = certs.info();
    tracing::info!(
        names = ?info.names,
        expires = %routes::admin::fmt_time(info.not_after),
        "loaded TLS certificate"
    );
    let http_port = match env("HTTP_PORT").as_deref() {
        Some("off") | Some("0") => None,
        _ => Some(env_port("HTTP_PORT", 80)?),
    };
    Ok(Some(Arc::new(Edge {
        certs: Arc::new(certs),
        https_port: env_port("HTTPS_PORT", 443)?,
        http_port,
    })))
}
