//! Listeners: the plaintext port bastion has always had, and — when a
//! certificate is configured — the edge pair, TLS on 443 and a redirect on 80.
//!
//! `axum::serve` can't do TLS, so connections are driven by hyper directly.
//! Each request gets `ConnectInfo` (the socket peer) and `ConnMeta` (whether it
//! came in over TLS) as extensions, which is what `forwarded::resolve` needs
//! to decide how much of the request's own story to believe.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Router,
};
use hyper::body::{Bytes, Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};
use tower::ServiceExt;

use crate::forwarded::ConnMeta;
use crate::state::AppState;

/// Long enough for a slow phone, short enough that a client trickling header
/// bytes can't hold a connection open indefinitely now this faces the internet.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a request body may go without sending anything. A slow upload is
/// fine; one that stops is holding a connection here and another to the
/// upstream for nothing.
const BODY_STALL_TIMEOUT: Duration = Duration::from_secs(60);

/// Open connections across every listener, counting pending TLS handshakes
/// and upgraded (WebSocket) connections. Each proxied one costs two
/// descriptors, so this stays well inside a typical 4096 limit; past it,
/// accepting pauses and new clients wait in the kernel's backlog rather than
/// pushing the process into EMFILE, where every host fails at once.
const MAX_CONNECTIONS: usize = 1500;

/// One per open connection; dropped when it closes. Cloned into requests so
/// `proxy::forward` can hold it for the life of an upgraded connection, which
/// outlives hyper's own connection future.
#[derive(Clone)]
pub struct ConnPermit(#[allow(dead_code)] Arc<OwnedSemaphorePermit>);

/// Shared by every listener, so the cap is on the process, not per port.
#[derive(Clone)]
pub struct Limits(Arc<Semaphore>);

impl Default for Limits {
    fn default() -> Limits {
        Limits(Arc::new(Semaphore::new(MAX_CONNECTIONS)))
    }
}

fn serve_conn<I>(io: I, peer: SocketAddr, meta: ConnMeta, permit: ConnPermit, app: Router)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
            req.extensions_mut().insert(ConnectInfo(peer));
            req.extensions_mut().insert(meta);
            req.extensions_mut().insert(permit.clone());
            let app = app.clone();
            let req = req.map(|b| Body::new(StallTimeout::new(b, BODY_STALL_TIMEOUT)));
            async move { Ok::<_, Infallible>(app.oneshot(req).await.into_response()) }
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

/// Waits for room under [`MAX_CONNECTIONS`], then for a connection.
///
/// Accept errors are mostly transient — out of descriptors under load, a
/// connection reset before accept returned. Back off briefly instead of
/// taking the listener, and with it every host, down.
async fn accept(listener: &TcpListener, limits: &Limits) -> (tokio::net::TcpStream, SocketAddr, ConnPermit) {
    let permit = limits
        .0
        .clone()
        .acquire_owned()
        .await
        .expect("the connection semaphore is never closed");
    loop {
        match listener.accept().await {
            Ok((s, peer)) => {
                let _ = s.set_nodelay(true);
                return (s, peer, ConnPermit(Arc::new(permit)));
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

pub async fn plain(listener: TcpListener, limits: Limits, app: Router) {
    loop {
        let (stream, peer, permit) = accept(&listener, &limits).await;
        serve_conn(stream, peer, ConnMeta { tls: false }, permit, app.clone());
    }
}

pub async fn tls(listener: TcpListener, limits: Limits, config: Arc<rustls::ServerConfig>, app: Router) {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    loop {
        let (stream, peer, permit) = accept(&listener, &limits).await;
        let acceptor = acceptor.clone();
        let app = app.clone();
        // The handshake runs off the accept loop, so one slow client can't
        // stall everyone else's.
        tokio::spawn(async move {
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => serve_conn(tls, peer, ConnMeta { tls: true }, permit, app),
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

/// A request body that fails once it has gone [`BODY_STALL_TIMEOUT`] without
/// a frame.
///
/// The clock only runs while someone is waiting on the body: it restarts at
/// the first poll after each frame. Time the handler spends not reading —
/// an upstream applying backpressure to a large upload, say — never counts
/// against the client.
struct StallTimeout {
    inner: Incoming,
    after: Duration,
    sleep: Pin<Box<Sleep>>,
    waiting: bool,
}

impl StallTimeout {
    fn new(inner: Incoming, after: Duration) -> StallTimeout {
        StallTimeout { inner, after, sleep: Box::pin(tokio::time::sleep(after)), waiting: false }
    }
}

impl hyper::body::Body for StallTimeout {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;
        if !this.waiting {
            this.waiting = true;
            let deadline = Instant::now() + this.after;
            this.sleep.as_mut().reset(deadline);
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(frame) => {
                this.waiting = false;
                Poll::Ready(frame.map(|f| f.map_err(Into::into)))
            }
            Poll::Pending => match this.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Some(Err("request body stalled".into()))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
