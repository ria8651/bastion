mod audit;
mod db;
mod error;
mod jwt;
mod keys;
mod middleware;
mod models;
mod oauth;
mod proxy;
mod routes;
mod session;
mod settings;
mod setup;
mod state;
mod templates;

use std::net::SocketAddr;

use axum::{
    middleware as axmw,
    routing::{get, post},
    Router,
};
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

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
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5180);

    tracing::info!(db = %database_path, "connecting to sqlite");
    let pool = db::connect(&database_path).await?;
    let state = AppState {
        pool,
        origin,
        proxy: proxy::client(),
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
        .route("/admin", get(routes::admin::index_redirect))
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
            "/admin/services/proxy-settings",
            post(routes::admin::proxy_settings_save),
        )
        .route(
            "/admin/services/approve-registration",
            post(routes::admin::approve_registration),
        )
        .route(
            "/admin/services/deny-registration",
            post(routes::admin::deny_registration),
        )
        .route("/admin/providers", get(routes::admin::providers_page))
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
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%addr, "bastion listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
