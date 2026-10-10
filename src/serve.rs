//! Listeners: the plaintext port bastion has always had, and — when a
//! certificate is configured — the edge pair, TLS on 443 and a redirect on 80.
//!
//! `axum::serve` can't do TLS, so connections are driven by hyper directly.
//! Each request gets `ConnectInfo` (the socket peer) and `ConnMeta` (whether it
//! came in over TLS) as extensions, which is what `forwarded::resolve` needs
//! to decide how much of the request's own story to believe.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Router,
};
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tower::ServiceExt;

use crate::forwarded::ConnMeta;
use crate::state::AppState;

/// Long enough for a slow phone, short enough that a client trickling header
/// bytes can't hold a connection open indefinitely now this faces the internet.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn serve_conn<I>(io: I, peer: SocketAddr, meta: ConnMeta, app: Router)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
            req.extensions_mut().insert(ConnectInfo(peer));
            req.extensions_mut().insert(meta);
            let app = app.clone();
            async move { Ok::<_, Infallible>(app.oneshot(req.map(Body::new)).await.into_response()) }
        });
        let conn = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .serve_connection(TokioIo::new(io), svc)
            // Without this a 101 never hands the socket over, and every
            // WebSocket through the proxy dies at the handshake.
            .with_upgrades();
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, %peer, "connection ended");
        }
    });
}

/// Accept errors are mostly transient — out of descriptors under load, a
/// connection reset before accept returned. Back off briefly instead of
/// taking the listener, and with it every host, down.
async fn accept(listener: &TcpListener) -> (tokio::net::TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok((s, peer)) => {
                let _ = s.set_nodelay(true);
                return (s, peer);
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

pub async fn plain(listener: TcpListener, app: Router) {
    loop {
        let (stream, peer) = accept(&listener).await;
        serve_conn(stream, peer, ConnMeta { tls: false }, app.clone());
    }
}

pub async fn tls(listener: TcpListener, config: Arc<rustls::ServerConfig>, app: Router) {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    loop {
        let (stream, peer) = accept(&listener).await;
        let acceptor = acceptor.clone();
        let app = app.clone();
        // The handshake runs off the accept loop, so one slow client can't
        // stall everyone else's.
        tokio::spawn(async move {
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => serve_conn(tls, peer, ConnMeta { tls: true }, app),
                Ok(Err(e)) => tracing::debug!(error = %e, %peer, "TLS handshake failed"),
                Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
            }
        });
    }
}

/// Port 80: send anything bastion serves to https, and nothing else anywhere.
pub fn redirect_app(state: AppState, https_port: u16) -> Router {
    Router::new()
        .fallback(move |State(state): State<AppState>, req: Request| async move {
            redirect_to_https(&state, https_port, req).await
        })
        .with_state(state)
}

async fn redirect_to_https(state: &AppState, https_port: u16, req: Request) -> Response {
    let Some(host) = crate::proxy::request_host(&req) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match crate::proxy::serves_host(state, &host).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "nothing is served under this name",
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, "host lookup on the redirect listener");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    let authority = if https_port == 443 { host } else { format!("{}:{}", host, https_port) };
    let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    // 308 rather than 301 so a POST stays a POST.
    Redirect::permanent(&format!("https://{}{}", authority, pq)).into_response()
}
