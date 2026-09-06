//! In-process reverse proxy for `mode = 'proxy'` services.
//!
//! bastion answers on the app's own hostname, checks the session and the grant,
//! then forwards the request to `upstream_url` with the caller's identity
//! attached as headers. The app needs no knowledge of bastion at all.
//!
//! The alternative is forward auth, where a gateway asks bastion about each
//! request and does the proxying itself. The trade is straightforward: this way
//! there is no gateway config to write and no way to misconfigure the gate off,
//! at the cost of bastion being in the data path for every byte — so streaming,
//! WebSocket upgrades, timeouts and buffering all become bastion's problem, and
//! bastion's uptime becomes the app's uptime.
//!
//! ## Why identity headers can't be forged here
//!
//! The outbound header map is built from scratch rather than edited, and
//! [`is_identity_header`] drops every inbound header in bastion's namespace
//! before anything is copied across. There is no configuration involved, so
//! there is nothing to get wrong — in particular the whole `x-bastion-*` prefix
//! is stripped, which stock nginx cannot express and a forward-auth deployment
//! therefore has to enumerate by hand.

use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{
        header::{self, HeaderMap, HeaderName, HeaderValue},
        StatusCode, Uri,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use sqlx::SqlitePool;
use tower_cookies::Cookies;

use crate::session::{read_session_cookie, validate_session_token};
use crate::state::{self_origin, AppState};

pub type ProxyClient = Client<HttpConnector, Body>;

pub fn client() -> ProxyClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_secs(10)));
    connector.set_nodelay(true);
    // No overall response timeout on purpose: WebSockets and SSE are long-lived
    // by design, and a blanket deadline would sever them.
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .build(connector)
}

// ──────────────────────── identity ────────────────────────

pub struct Identity {
    pub username: String,
    pub email: Option<String>,
    pub sub: String,
}

/// The headers bastion attaches to a proxied request.
///
/// `Remote-User`/`Remote-Email` are there because a lot of apps that already
/// support proxy auth (Grafana, Gitea, Miniflux…) read those names and nothing
/// else.
///
/// No permissions: a permission catalog is declared by the service itself
/// through `/api/services/register`, which a proxied app by definition cannot
/// do, so the header would be empty on every request. Proxy mode is a gate —
/// the grant is the whole decision.
pub fn identity_headers(id: &Identity) -> Vec<(&'static str, String)> {
    let email = id.email.as_deref().map(header_safe).unwrap_or_default();
    vec![
        ("x-bastion-user", header_safe(&id.username)),
        ("x-bastion-sub", header_safe(&id.sub)),
        ("x-bastion-email", email.clone()),
        ("remote-user", header_safe(&id.username)),
        ("remote-email", email),
    ]
}

/// Anything in bastion's identity namespace, whether or not bastion sets it.
///
/// Matched by prefix, so a name added later is stripped from inbound requests
/// from the moment it exists rather than the moment someone remembers to add it
/// to a list.
fn is_identity_header(name: &HeaderName) -> bool {
    let n = name.as_str();
    n.starts_with("x-bastion-") || matches!(n, "remote-user" | "remote-email" | "remote-groups")
}

/// Reduce a value to printable ASCII.
///
/// Usernames and emails come from OAuth providers, i.e. from outside. A CR or
/// LF in one would be header injection, and a non-ASCII byte makes
/// `HeaderValue::from_str` fail, turning a display-name quirk into a 500 on
/// every request to a gated app.
pub fn header_safe(s: &str) -> String {
    let mut out: String = s.chars().filter(|c| (' '..='~').contains(c)).collect();
    out.truncate(512);
    out.trim().to_string()
}

/// Per-connection headers, which are meaningless to the next hop.
/// `upgrade` is handled separately — it is hop-by-hop but has to be replayed.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
}

/// Re-serialize a `Cookie` header without bastion's own cookies, returning
/// `None` if nothing is left to send.
///
/// The session token is a bearer credential — `validate_session_token` needs
/// nothing besides it — and proxy mode requires a `cookie_domain`, so the
/// browser sends `bastion_session` to every gated host. Forwarding it would
/// hand each proxied app, its access logs and anything that compromises it a
/// credential good for bastion's own admin UI, `/account`, and every other
/// gated app that user can reach.
///
/// That inverts the entire point of the header design: identity is injected
/// precisely *because* an app is not trusted to assert it, so it must not also
/// be handed something strictly stronger than the assertion.
///
/// Only bastion's own pairs are dropped — the app's cookies are its own
/// business, and it needs them to keep any session of its own.
fn strip_bastion_cookies(value: &str) -> Option<String> {
    let kept: Vec<&str> = value
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .filter(|pair| {
            let name = pair.split('=').next().unwrap_or("").trim();
            name != crate::session::SESSION_COOKIE && name != crate::oauth::STATE_COOKIE
        })
        .collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}

/// Whether a path contains a `.` or `..` segment once percent-decoded.
///
/// `http::Uri` keeps the path verbatim: no dot-segment removal, no decoding.
/// `glob_match`'s `*` spans `/` by design, so the admin UI's own placeholder
/// pattern `/api/hooks/*` matches `/api/hooks/../../admin` — which would skip
/// the session and grant checks and then be forwarded still un-normalized, for
/// the upstream to resolve back to `/admin`. nginx, Go's `ServeMux` and most
/// frameworks all do resolve it. That is a full authentication bypass on any
/// service with a wildcard public path, which is exactly what the feature
/// exists for.
///
/// Rejecting beats normalizing. Normalizing only for the match while forwarding
/// the raw path re-opens the gap, and normalizing both would silently change
/// what the app sees. Browsers resolve dot-segments before sending, so nothing
/// legitimate arrives carrying one.
///
/// Decoding the whole path first is what catches `%2e%2e%2f`, where the encoded
/// slash hides the segment boundary. Matching whole segments rather than any
/// `..` substring is what keeps `/files/%2egitignore` working.
fn has_dot_segment(path: &str) -> bool {
    urlencoding::decode_binary(path.as_bytes())
        .split(|b| *b == b'/')
        .any(|seg| seg == b"." || seg == b"..")
}

// ──────────────────────── public paths ────────────────────────

pub fn parse_public_paths(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or("")
        .lines()
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(str::to_string)
        .collect()
}

pub fn is_public_path(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, path))
}

/// Wildcard match where `*` spans any run of characters, `/` included.
/// Deliberately not a full glob — `/health`, `/api/*` and `*.png` cover the
/// health-check and webhook cases without inviting pattern-authoring bugs.
pub fn glob_match(pattern: &str, s: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;

    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

// ──────────────────────── redirect allowlist ────────────────────────

/// Validate a post-login redirect target against the registered proxy hosts.
///
/// This is the one place a URL from the query string is handed back to the
/// browser, so it is an open redirect in bastion's own SSO unless the host is
/// checked against the DB. Substring or prefix matching would not be enough —
/// `https://evil.com/?x=app.example.com` has to fail — so the parsed host must
/// equal a `proxy_host` exactly.
pub async fn validate_redirect(
    pool: &SqlitePool,
    raw: &str,
    service_slug: Option<&str>,
) -> Option<String> {
    let u = url::Url::parse(raw).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    if !u.username().is_empty() || u.password().is_some() {
        return None;
    }
    let host = u.host_str()?.to_ascii_lowercase();

    let row: Option<(i64,)> = match service_slug {
        Some(slug) => sqlx::query_as(
            "SELECT id FROM services
             WHERE proxy_host = ? AND slug = ?
               AND status = 'approved' AND deleted_at IS NULL",
        )
        .bind(&host)
        .bind(slug)
        .fetch_optional(pool)
        .await
        .ok()?,
        None => sqlx::query_as(
            "SELECT id FROM services
             WHERE proxy_host = ? AND status = 'approved' AND deleted_at IS NULL",
        )
        .bind(&host)
        .fetch_optional(pool)
        .await
        .ok()?,
    };
    row.map(|_| u.to_string())
}

/// Whether a denial should be answered with a redirect to the login page.
///
/// A `fetch()` call or a WebSocket handshake redirected to an OAuth page fails
/// in a way that's near-impossible to debug from the app side, so those get a
/// bare status and the app's own client code decides what to do.
pub fn wants_html(headers: &HeaderMap) -> bool {
    if headers.contains_key(header::UPGRADE) {
        return false;
    }
    let get = |k: &str| headers.get(k).and_then(|v| v.to_str().ok());

    if let Some(dest) = get("sec-fetch-dest") {
        return matches!(dest, "document" | "iframe" | "frame" | "embed" | "object");
    }
    if get("x-requested-with").map(|v| v.eq_ignore_ascii_case("xmlhttprequest")) == Some(true) {
        return false;
    }
    if let Some(mode) = get("sec-fetch-mode") {
        if matches!(mode, "cors" | "no-cors" | "websocket") {
            return false;
        }
    }
    get("accept").map(|a| a.contains("text/html")) == Some(true)
}

// ──────────────────────── the middleware ────────────────────────

struct Gated {
    id: i64,
    slug: String,
    /// The registered `proxy_host`. Equal to the request's host by the `WHERE`
    /// clause that found this row, but this is the copy that came from the DB —
    /// so it, not the request, is what public URLs get built from.
    host: String,
    upstream: String,
    public_paths: Option<String>,
}

/// Routes a request to a proxied app if its `Host` names one, otherwise passes
/// it through to bastion's own router.
///
/// Sits outside `load_user` and `setup_gate`: a gated host is not part of
/// bastion's UI and must not be redirected into the setup wizard.
pub async fn proxy_gate(
    State(state): State<AppState>,
    cookies: Cookies,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let Some(host) = request_host(&req) else {
        return next.run(req).await;
    };

    let row: Result<Option<(i64, String, Option<String>, Option<String>)>, _> = sqlx::query_as(
        "SELECT id, slug, upstream_url, public_paths FROM services
         WHERE proxy_host = ? AND mode = 'proxy'
           AND status = 'approved' AND deleted_at IS NULL",
    )
    .bind(&host)
    .fetch_optional(&state.pool)
    .await;

    let svc = match row {
        Ok(Some((id, slug, Some(upstream), public_paths))) => Gated {
            id,
            slug,
            host: host.clone(),
            upstream,
            public_paths,
        },
        // Registered as a proxy host but with no upstream: refuse rather than
        // fall through to bastion's own UI, which would serve the wrong site.
        Ok(Some((_, slug, None, _))) => {
            tracing::error!(%slug, %host, "proxy service has no upstream_url");
            return bad_gateway("this app has no upstream configured");
        }
        Ok(None) => {
            // Not a gated host. Serve bastion's own UI only under a name that
            // is actually bastion's: a decommissioned proxy host whose DNS
            // still points here would otherwise serve the entire instance
            // under that name. Auth still holds either way, but a login page
            // answering to an arbitrary name is worth not doing.
            if !is_bastion_host(&state, &host) {
                tracing::warn!(%host, "request for a host bastion does not serve");
                return StatusCode::NOT_FOUND.into_response();
            }
            return next.run(req).await;
        }
        Err(e) => {
            tracing::error!(error = ?e, "proxy service lookup");
            return bad_gateway("could not look up this app");
        }
    };

    let path = req.uri().path().to_string();

    // Before any routing decision, and for every proxied request rather than
    // only the public ones: a dot-segment makes the path bastion matches on and
    // the path the upstream resolves two different things, and every rule below
    // is written against the former.
    if has_dot_segment(&path) {
        tracing::warn!(slug = %svc.slug, %path, "rejected dot-segment in proxied path");
        return (StatusCode::BAD_REQUEST, "bad request path").into_response();
    }

    let patterns = parse_public_paths(svc.public_paths.as_deref());
    if is_public_path(&patterns, &path) {
        return forward(&state, &svc, req, None, peer).await;
    }

    // ── who is this? ──
    let user = match read_session_cookie(&cookies) {
        Some(token) => validate_session_token(&state.pool, &token)
            .await
            .unwrap_or(None)
            .map(|(u, _sid)| u),
        None => None,
    };
    let origin = self_origin(&state, req.headers());
    let html = wants_html(req.headers());

    let Some(user) = user else {
        let (scheme, authority) = public_origin(&state, &svc.host, &req);
        let target = format!("{}://{}{}", scheme, authority, req.uri());
        return deny(
            StatusCode::UNAUTHORIZED,
            html.then(|| {
                format!(
                    "{}/auth/login?service={}&redirect={}",
                    origin,
                    urlencoding::encode(&svc.slug),
                    urlencoding::encode(&target),
                )
            }),
        );
    };

    if user.status == "denied" {
        return deny(StatusCode::FORBIDDEN, html.then(|| format!("{}/denied", origin)));
    }
    let pending = || format!("{}/pending?service={}", origin, urlencoding::encode(&svc.slug));
    if user.status != "active" {
        return deny(StatusCode::FORBIDDEN, html.then(pending));
    }

    // ── are they allowed in here? ──
    let granted: Result<Option<(i64,)>, _> =
        sqlx::query_as("SELECT user_id FROM grants WHERE user_id = ? AND service_id = ?")
            .bind(user.id)
            .bind(svc.id)
            .fetch_optional(&state.pool)
            .await;
    match granted {
        Ok(Some(_)) => {}
        Ok(None) => {
            // Only file a request off a real navigation: this runs on every
            // subresource of every page, and one gated page load would
            // otherwise produce a burst of identical rows.
            if html {
                let _ = record_access_request(&state.pool, user.id, svc.id, &svc.slug).await;
            }
            return deny(StatusCode::FORBIDDEN, html.then(pending));
        }
        Err(e) => {
            tracing::error!(error = ?e, "grant lookup");
            return bad_gateway("could not check access for this app");
        }
    }

    let identity = Identity {
        username: user.username.clone(),
        email: user.email.clone(),
        sub: crate::jwt::identity_hash(&user.sub_anchor_provider, &user.sub_anchor_provider_id),
    };
    forward(&state, &svc, req, Some(identity), peer).await
}

/// Mirrors the access request the OAuth callback files on a service redirect,
/// so an app reached directly still shows up in the admin requests queue.
async fn record_access_request(
    pool: &SqlitePool,
    user_id: i64,
    service_id: i64,
    slug: &str,
) -> Result<(), sqlx::Error> {
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM access_requests
         WHERE user_id = ? AND service_id = ? AND resolved_at IS NULL",
    )
    .bind(user_id)
    .bind(service_id)
    .fetch_optional(pool)
    .await?;
    if existing.is_none() {
        sqlx::query("INSERT INTO access_requests (user_id, service_id, note) VALUES (?, ?, ?)")
            .bind(user_id)
            .bind(service_id)
            .bind(format!("Requested via proxy on {}", slug))
            .execute(pool)
            .await?;
    }
    Ok(())
}

// ──────────────────────── forwarding ────────────────────────

async fn forward(
    state: &AppState,
    svc: &Gated,
    mut req: Request,
    identity: Option<Identity>,
    peer: SocketAddr,
) -> Response {
    // From the DB and ORIGIN, not from the request: this feeds X-Forwarded-Host,
    // X-Forwarded-Proto and the Location rewrite, and the client must not get to
    // choose any of them. Includes the port, without which all three are wrong
    // on a non-default port.
    let (scheme, authority) = public_origin(state, &svc.host, &req);

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let target: Uri = match format!(
        "{}{}",
        svc.upstream.trim_end_matches('/'),
        path_and_query
    )
    .parse()
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = ?e, upstream = %svc.upstream, "bad upstream url");
            return bad_gateway("this app's upstream URL is not valid");
        }
    };

    let upgrade = req.headers().get(header::UPGRADE).cloned();

    let mut out = Request::builder().method(req.method()).uri(target);
    {
        let h = out.headers_mut().expect("fresh builder");
        // Built from scratch, not edited: anything the client sent in bastion's
        // identity namespace is simply never copied across.
        for (name, value) in req.headers() {
            if is_hop_by_hop(name) || is_identity_header(name) || name == header::COOKIE {
                continue;
            }
            h.append(name, value.clone());
        }
        // Cookies are rebuilt rather than copied: the app keeps its own, and
        // bastion's session token — a bearer credential for bastion itself —
        // never leaves bastion.
        for value in req.headers().get_all(header::COOKIE) {
            let Some(kept) = value.to_str().ok().and_then(strip_bastion_cookies) else {
                continue;
            };
            if let Ok(v) = HeaderValue::from_str(&kept) {
                h.append(header::COOKIE, v);
            }
        }
        set(h, "x-forwarded-host", &authority);
        set(h, "x-forwarded-proto", &scheme);
        set(h, "x-real-ip", &peer.ip().to_string());
        let fwd = match req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(prev) => format!("{}, {}", prev, peer.ip()),
            None => peer.ip().to_string(),
        };
        set(h, "x-forwarded-for", &fwd);

        if let Some(id) = &identity {
            for (name, value) in identity_headers(id) {
                set(h, name, &value);
            }
        }
        // Replay the upgrade intent that was stripped as hop-by-hop.
        if let Some(u) = &upgrade {
            h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            h.insert(header::UPGRADE, u.clone());
        }
    }

    // Must be taken before the request is consumed.
    let client_upgrade = hyper::upgrade::on(&mut req);
    let out_req = match out.body(req.into_body()) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "building upstream request");
            return bad_gateway("could not build the upstream request");
        }
    };

    let mut res = match state.proxy.request(out_req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, slug = %svc.slug, upstream = %svc.upstream, "upstream unreachable");
            return bad_gateway("this app is not responding");
        }
    };

    // A 101 means both sides want to switch protocols; splice the two
    // connections together once each has finished upgrading. Protocol-agnostic,
    // so WebSockets and anything else built on Upgrade both work.
    if res.status() == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_upgrade = hyper::upgrade::on(&mut res);
        let slug = svc.slug.clone();
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, upstream_upgrade) {
                Ok((downstream, upstream)) => {
                    let mut a = TokioIo::new(downstream);
                    let mut b = TokioIo::new(upstream);
                    if let Err(e) = tokio::io::copy_bidirectional(&mut a, &mut b).await {
                        tracing::debug!(error = %e, %slug, "upgraded connection closed");
                    }
                }
                Err(e) => tracing::warn!(error = %e, %slug, "upgrade failed"),
            }
        });
        let (parts, _) = res.into_parts();
        return Response::from_parts(parts, Body::empty());
    }

    let (mut parts, body) = res.into_parts();
    let strip: Vec<HeaderName> = parts
        .headers
        .keys()
        .filter(|n| is_hop_by_hop(n))
        .cloned()
        .collect();
    for name in strip {
        parts.headers.remove(&name);
    }
    rewrite_location(&mut parts.headers, &svc.upstream, &scheme, &authority);

    Response::from_parts(parts, Body::new(body))
}

/// Rewrite a `Location` pointing at the upstream's own address back to the
/// public one.
///
/// Apps that don't know they're proxied routinely redirect to
/// `http://127.0.0.1:8080/…`, which is a dead end in the browser. Only an exact
/// upstream-prefix match is rewritten; anything else is left alone.
fn rewrite_location(headers: &mut HeaderMap, upstream: &str, scheme: &str, host: &str) {
    let Some(loc) = headers.get(header::LOCATION).and_then(|v| v.to_str().ok()) else {
        return;
    };
    let base = upstream.trim_end_matches('/');
    let Some(rest) = loc.strip_prefix(base) else {
        return;
    };
    if !rest.is_empty() && !rest.starts_with('/') {
        return;
    }
    if let Ok(v) = HeaderValue::from_str(&format!("{}://{}{}", scheme, host, rest)) {
        headers.insert(header::LOCATION, v);
    }
}

// ──────────────────────── small helpers ────────────────────────

fn set(h: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        h.insert(n, v);
    }
}

/// The authority the request was addressed to, **port included**. HTTP/2 puts
/// it in the URI authority; HTTP/1.1 in the Host header.
///
/// This is the one to build URLs from — a return URL or a rewritten `Location`
/// that drops a non-default port sends the browser somewhere that isn't
/// listening. Use [`request_host`] for matching against `proxy_host`, which is
/// stored without a port.
fn request_authority(req: &Request) -> Option<String> {
    let raw = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })?;
    let raw = raw.trim().to_ascii_lowercase();
    (!raw.is_empty()).then_some(raw)
}

/// Whether bastion should serve its own UI under this hostname.
///
/// Only meaningful once `ORIGIN` is pinned; unpinned, bastion has no idea what
/// it is called and anything goes. Loopback and bare IPs are always allowed:
/// an `nginx` in front that hasn't been given `proxy_set_header Host $host`
/// sends its own upstream address, and health checks dial the container
/// directly — neither should 404.
fn is_bastion_host(state: &AppState, host: &str) -> bool {
    let Some(origin) = &state.origin else {
        return true;
    };
    if host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return true;
    }
    url::Url::parse(origin)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase()))
        .map(|h| h == host)
        .unwrap_or(true)
}

/// The public origin of a gated app as **bastion** knows it: `(scheme,
/// authority)`.
///
/// The host is the registered `proxy_host`; scheme and port come from `ORIGIN`,
/// which is sound because one process serves every gated host on one port.
///
/// Echoing the request instead would let the client pick both halves.
/// `request_host` strips the port before matching `proxy_host`, so
/// `Host: app.example.com:1337` matches the service and would then go upstream
/// as `X-Forwarded-Host: app.example.com:1337`; `X-Forwarded-Proto` is worse
/// still, being copied straight from the client with no trusted-gateway check.
/// An app that builds absolute URLs out of those — password-reset and invite
/// mail being the classic — would emit links carrying an attacker's port or a
/// downgraded scheme.
///
/// With `ORIGIN` unset there is nothing better than the request to fall back
/// on, which is one more reason the admin UI warns about leaving it unpinned.
fn public_origin(state: &AppState, proxy_host: &str, req: &Request) -> (String, String) {
    if let Some(origin) = &state.origin {
        if let Ok(u) = url::Url::parse(origin) {
            let authority = match u.port() {
                Some(p) => format!("{}:{}", proxy_host, p),
                None => proxy_host.to_string(),
            };
            return (u.scheme().to_string(), authority);
        }
    }
    (
        request_scheme(req).to_string(),
        request_authority(req).unwrap_or_else(|| proxy_host.to_string()),
    )
}

/// Hostname only, port stripped, for matching against `proxy_host`.
fn request_host(req: &Request) -> Option<String> {
    let raw = request_authority(req)?;
    // Leave IPv6 literals alone; they are not valid proxy_host values anyway.
    if raw.starts_with('[') {
        return Some(raw);
    }
    // Trailing root dot too: `app.example.com.` is the same name to DNS, and
    // `normalize_host` strips dots on the way in, so without this the fully
    // qualified form misses `proxy_host` and falls through to bastion's own UI.
    Some(
        raw.split(':')
            .next()
            .unwrap_or(&raw)
            .trim_end_matches('.')
            .to_string(),
    )
}

fn request_scheme(req: &Request) -> &str {
    req.headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .filter(|s| *s == "http" || *s == "https")
        .unwrap_or("http")
}

fn deny(status: StatusCode, redirect: Option<String>) -> Response {
    match redirect {
        Some(to) => axum::response::Redirect::to(&to).into_response(),
        None => status.into_response(),
    }
}

fn bad_gateway(detail: &str) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "<!doctype html><meta charset=utf-8><title>502</title>\
             <style>body{{font:14px system-ui;padding:48px;color:#444}}</style>\
             <h1 style=\"font-size:16px\">502 &middot; bad gateway</h1><p>{}</p>",
            detail
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderName;

    /// HTTP/1.1 shape: origin-form URI, authority in the Host header.
    fn req(pairs: &[(&str, &str)]) -> Request {
        let mut b = Request::builder().uri("/x");
        for (k, v) in pairs {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    #[test]
    fn identity_namespace_is_stripped_by_prefix() {
        // The structural win over a gateway config: bastion drops the whole
        // x-bastion-* prefix, so a name added later is protected the moment it
        // exists rather than the moment someone remembers to list it.
        for name in [
            "x-bastion-user",
            "x-bastion-sub",
            "x-bastion-email",
            "x-bastion-perms",
            "x-bastion-admin",
            "x-bastion-anything-at-all",
            "remote-user",
            "remote-email",
            "remote-groups",
        ] {
            assert!(
                is_identity_header(&HeaderName::from_static(name)),
                "{} would reach the app unfiltered",
                name
            );
        }
        for name in ["accept", "cookie", "x-forwarded-for", "x-real-ip"] {
            assert!(!is_identity_header(&HeaderName::from_static(name)));
        }
    }

    #[test]
    fn bastion_session_never_reaches_an_upstream() {
        // proxy mode requires a cookie_domain, so the browser sends the session
        // token to every gated host. It is a bearer credential for bastion
        // itself — the app must never see it, however much it is trusted.
        let out = strip_bastion_cookies("app_sid=abc; bastion_session=SECRET; theme=dark").unwrap();
        assert!(!out.contains("SECRET"));
        assert!(!out.contains("bastion_session"));
        assert_eq!(out, "app_sid=abc; theme=dark");

        // The app's own cookies must survive, or it can't keep a session.
        assert_eq!(strip_bastion_cookies("a=1; b=2").as_deref(), Some("a=1; b=2"));
        // Nothing left means no header at all, not an empty one.
        assert_eq!(strip_bastion_cookies("bastion_session=x"), None);
        assert_eq!(strip_bastion_cookies(""), None);
        // The OAuth state cookie is bastion's too.
        assert_eq!(
            strip_bastion_cookies("bastion_oauth_state=y; keep=1").as_deref(),
            Some("keep=1")
        );
        // Whitespace and value-embedded '=' must not confuse the name split.
        assert_eq!(
            strip_bastion_cookies("  bastion_session = x ; t=a=b").as_deref(),
            Some("t=a=b")
        );
    }

    #[test]
    fn dot_segments_are_rejected_before_any_public_path_match() {
        // The bypass: '*' spans '/', so /api/hooks/* matched
        // /api/hooks/../../admin, skipped auth, and forwarded the raw path for
        // the upstream to resolve back to /admin.
        assert!(is_public_path(
            &["/api/hooks/*".to_string()],
            "/api/hooks/../../admin"
        ));
        for bad in [
            "/api/hooks/../../admin",
            "/api/hooks/%2e%2e/%2e%2e/admin",
            "/api/hooks/%2E%2E%2F%2E%2E%2Fadmin",
            "/a/./b",
            "/..",
        ] {
            assert!(has_dot_segment(bad), "{} would slip through", bad);
        }
        for ok in [
            "/api/hooks/github",
            "/health",
            "/files/%2egitignore", // decodes to /files/.gitignore
            "/a..b/c",             // dots inside a segment are just characters
            "/",
        ] {
            assert!(!has_dot_segment(ok), "{} rejected but is legitimate", ok);
        }
    }

    #[test]
    fn trailing_root_dot_still_matches_a_proxy_host() {
        assert_eq!(
            request_host(&req(&[("host", "app.example.com.")])).as_deref(),
            Some("app.example.com")
        );
        assert_eq!(
            request_host(&req(&[("host", "app.example.com.:8443")])).as_deref(),
            Some("app.example.com")
        );
    }

    #[test]
    fn header_safe_strips_control_and_non_ascii() {
        assert_eq!(header_safe("bob\r\nX-Bastion-Sub: forged"), "bobX-Bastion-Sub: forged");
        assert_eq!(header_safe("zoë"), "zo");
        assert_eq!(header_safe(&"x".repeat(9000)).len(), 512);
    }

    #[test]
    fn identity_headers_are_the_documented_set() {
        let id = Identity {
            username: "brian".into(),
            email: Some("b@example.com".into()),
            sub: "abc".into(),
        };
        let got: std::collections::HashMap<_, _> = identity_headers(&id).into_iter().collect();
        assert_eq!(got.len(), 5);
        assert_eq!(got["x-bastion-user"], "brian");
        assert_eq!(got["x-bastion-sub"], "abc");
        assert_eq!(got["remote-user"], "brian");
        // Everything bastion emits must be inside the stripped namespace, or an
        // inbound copy would survive and then be appended to.
        for (name, _) in identity_headers(&id) {
            assert!(is_identity_header(&HeaderName::from_static(name)));
        }
    }

    #[test]
    fn hop_by_hop_headers_are_not_forwarded() {
        for name in ["connection", "keep-alive", "transfer-encoding", "te", "upgrade"] {
            assert!(is_hop_by_hop(&HeaderName::from_static(name)));
        }
        assert!(!is_hop_by_hop(&HeaderName::from_static("content-type")));
    }

    #[test]
    fn host_matches_without_a_port_but_urls_keep_it() {
        // proxy_host is stored without a port, so lookups strip it...
        assert_eq!(
            request_host(&req(&[("host", "App.Example.com:8443")])).as_deref(),
            Some("app.example.com")
        );
        // ...but anything that becomes a URL the browser follows must not,
        // or a non-default port sends it somewhere nothing is listening.
        assert_eq!(
            request_authority(&req(&[("host", "App.Example.com:8443")])).as_deref(),
            Some("app.example.com:8443")
        );
        assert_eq!(
            request_authority(&req(&[("host", "app.example.com")])).as_deref(),
            Some("app.example.com")
        );
        // HTTP/2 carries it as the URI authority instead, which also wins over
        // a stale Host header.
        let h2 = Request::builder()
            .uri("https://app.example.com:8443/x")
            .header("host", "wrong.example.com")
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_authority(&h2).as_deref(), Some("app.example.com:8443"));
        assert_eq!(request_host(&h2).as_deref(), Some("app.example.com"));
    }

    #[test]
    fn glob_matches_public_paths() {
        assert!(glob_match("/health", "/health"));
        assert!(!glob_match("/health", "/healthz"));
        assert!(glob_match("/api/*", "/api/webhooks/stripe"));
        assert!(glob_match("*.png", "/static/img/logo.png"));
        assert!(!glob_match("/adm", "/admin"));
    }

    #[test]
    fn public_paths_parse_ignores_comments_and_blanks() {
        assert_eq!(
            parse_public_paths(Some("/health\n\n# note\n/api/*, /ping\n")),
            vec!["/health", "/api/*", "/ping"]
        );
        assert!(parse_public_paths(None).is_empty());
    }

    #[test]
    fn only_navigations_get_redirected() {
        assert!(wants_html(req(&[("sec-fetch-dest", "document")]).headers()));
        assert!(wants_html(req(&[("accept", "text/html,*/*")]).headers()));
        assert!(!wants_html(req(&[("sec-fetch-dest", "empty")]).headers()));
        // Unlike forward auth, Upgrade reaches us intact — nothing has stripped
        // it as hop-by-hop on the way in.
        assert!(!wants_html(
            req(&[("upgrade", "websocket"), ("accept", "text/html")]).headers()
        ));
        assert!(!wants_html(req(&[("accept", "application/json")]).headers()));
    }

    #[test]
    fn location_rewriting_only_touches_the_upstream() {
        let rewrite = |loc: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::LOCATION, HeaderValue::from_str(loc).unwrap());
            rewrite_location(&mut h, "http://127.0.0.1:8080", "https", "app.example.com");
            h[header::LOCATION].to_str().unwrap().to_string()
        };
        assert_eq!(
            rewrite("http://127.0.0.1:8080/dash?a=1"),
            "https://app.example.com/dash?a=1"
        );
        assert_eq!(rewrite("http://127.0.0.1:8080"), "https://app.example.com");
        // Relative and third-party locations are left alone.
        assert_eq!(rewrite("/dash"), "/dash");
        assert_eq!(rewrite("https://accounts.google.com/o"), "https://accounts.google.com/o");
        // Prefix confusion: a host that merely starts with the upstream string.
        assert_eq!(
            rewrite("http://127.0.0.1:80808/evil"),
            "http://127.0.0.1:80808/evil"
        );
    }
}
