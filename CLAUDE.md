# bastion

Central SSO auth service for `../boom` and `../binkflix`. axum + sqlx (SQLite) + maud + htmx + josekit (RS256 JWT/JWKS). Supports GitHub and Google OAuth; either can be used to set up bastion, and a single bastion user can have multiple linked identities.

A service integrates in one of two **modes** (`services.mode`): `redirect`, the JWT wire contract below, or `proxy`, where bastion reverse-proxies the app itself and it needs no knowledge of bastion.

## DB workflow: sqlx migrations

Schema lives in `migrations/NNNN_<name>.sql`, applied via `sqlx::migrate!("./migrations")` from `src/db.rs::connect()` at startup. Each schema change is a new numbered file — never edit an applied migration in place, since `sqlx` records its checksum in `_sqlx_migrations` and a mismatch aborts boot.

To add a delta: create `migrations/NNNN_<name>.sql` (use the next free number), put plain SQL in it, restart. The migration runs in a transaction; if any statement fails the whole migration rolls back. Use `ALTER TABLE ... ADD COLUMN` for additive changes and `DROP INDEX IF EXISTS` + `CREATE [UNIQUE] INDEX` for index swaps.

## Config lives in DB, not env

Env vars: `DATABASE_PATH` (default `./data/bastion.db`), `ORIGIN` (optional; otherwise derived from `X-Forwarded-{Host,Proto}` / `Host`), `PORT` (default 5180), `RUST_LOG`. OAuth creds (GitHub and/or Google), services, first admin — all set via the `/setup` wizard, stored in DB. Post-setup, an admin can rotate or add provider creds from `/admin/providers`.

Instance-wide settings that belong to no single service live in the `settings` key/value table (`src/settings.rs`); setting a key to `""` deletes it, so "unset" and "empty" are one state. Currently only `cookie_domain`.

## Setup state is derived, not stored

`/setup` step is computed from DB on each request: no provider creds at all → step 1, no admin → step 2, no services → step 3. Either GitHub or Google (or both) satisfies step 1. `middleware::setup_gate` redirects all non-setup routes to `/setup` until complete.

## Multi-provider identity model

`users` is a single account record. `user_identities` is one row per linked OAuth identity (`provider`, `provider_id`, `email`, `avatar`, `last_login_at`). Users can link more providers via `/account` and unlink any of them as long as ≥1 remains.

The JWT `sub` is derived from a frozen pair `(users.sub_anchor_provider, users.sub_anchor_provider_id)` set once at signup, **never** updated. Linking or unlinking other identities does not change `sub`, so downstream services keep seeing the same user. `users.github_id` is legacy and unread by new code (kept for the existing NOT NULL constraint).

## Templating

Pages are plain async handlers returning `maud::Markup`. Layouts compose via function calls — `templates::layout(title, user, body)` and `templates::admin_layout(title, tab, user, body)`. No `.html` files. The stylesheet at `static/style.css` is inlined into pages via `include_str!` in `templates.rs`.

## htmx

`<body hx-boost="true">` makes all link clicks and form submissions XHR-driven swaps of the body. Mutation handlers do their work and return `303 See Other`; the browser/htmx re-fetches the new page. No JSON API for the UI. Logout uses `hx-boost="false"` for a hard reload.

## Proxy mode (`mode = 'proxy'`)

bastion answers on the app's own hostname (`proxy_host`), checks the session and the grant, then forwards to `upstream_url` with the caller's identity attached as headers. The app needs no knowledge of bastion.

`src/proxy.rs` holds the whole thing — decision plus transport. `proxy_gate` is a middleware layered *outside* `load_user` and `setup_gate` (a gated host is not part of bastion's UI and must not be redirected into the setup wizard) but *inside* the cookie layer, since it reads the session itself. Invariants worth keeping:

- **The outbound header map is built from scratch, never edited.** `is_identity_header()` drops the entire `x-bastion-*` prefix plus the `remote-*` names before anything is copied across, so a client cannot smuggle in an identity header. Prefix matching is the point: a name added later is protected the moment it exists. This is the structural advantage over forward auth, where the equivalent has to be enumerated by hand in gateway config.
- **Redirect targets are allowlisted.** `?redirect=` on `/auth/login` comes from a 401 on an attacker-reachable host. `validate_redirect()` requires the parsed host to *equal* a registered `proxy_host` — re-validated at every hop, including the hidden form field.
- **Only navigations get redirected.** `wants_html()` gates it, so a `fetch()` or WebSocket handshake gets a bare 401 rather than an OAuth page.
- **`upstream_url` is admin-only.** A self-registering service that could set its own upstream would turn bastion into an open proxy onto whatever the box can reach. `registration.rs` cannot touch it.
- **bastion's session cookie never leaves bastion.** Proxy mode requires a `cookie_domain`, so the browser sends `bastion_session` to every gated host. It is a bearer credential — `validate_session_token` needs nothing else — so forwarding it would hand each app, its access logs and anything that compromises it a credential for bastion's own admin UI and every other gated app. `strip_bastion_cookies()` rebuilds the outbound `Cookie` header without it; the app's own cookies pass through untouched.
- **Dot-segments are rejected outright.** `http::Uri` keeps the path verbatim and `glob_match`'s `*` spans `/`, so `/api/hooks/*` matched `/api/hooks/../../admin` — public path, no auth, forwarded un-normalized for the upstream to resolve back to `/admin`. `has_dot_segment()` runs before any routing decision and on every proxied request. Normalizing instead would be worse: normalize only for the match and the gap reopens; normalize both and the app silently sees a different path.
- **Public URLs come from config, not the request.** `public_origin()` builds `(scheme, authority)` from the stored `proxy_host` plus `ORIGIN`'s scheme and port. Echoing the request would let a client pick the port (`request_host` strips it before matching, so `Host: app.example.com:1337` matches fine) and the scheme (`X-Forwarded-Proto` is unauthenticated), and any app that builds absolute URLs from `X-Forwarded-Host` — password-reset mail being the classic — would emit them. `request_host()` still strips the port for matching `proxy_host`; `request_authority()` remains only as the `ORIGIN`-unpinned fallback.
- **Proxy mode sends no permissions.** A proxied app can't register a catalog, so the header would always be empty. The grant is the whole decision; `permissions`/`user_perms` remain redirect-mode only.
- **A loop marker guards against recursion.** An upstream that resolves back to bastion — directly, or via a DNS alias config-time validation can't see through — recurses, because `Host` is copied to the upstream and so matches the same service on arrival. On a public path that needs no session, one request spirals until the process runs out of descriptors. `LOOP_MARKER` is checked in `proxy_gate` against the *raw* inbound request, which works only because `is_identity_header` runs later, in `forward` — keep that ordering.
- **`cookie_domain` is enforced, not just advised.** Without one the session cookie never reaches the gated host, so the browser is sent to log in, comes back with nothing, and is sent again — and that is the state a service is in the moment it is first switched to proxy mode. `proxy_gate` refuses with a 503 explaining it rather than looping. `normalize_cookie_domain` separately refuses a domain that doesn't cover `ORIGIN`'s host, which would otherwise lock everyone out *and* destroy the admin's own session on their next page load.
- **The upstream hop is plaintext.** TLS terminates at the gateway in front of bastion, and an upstream is the app itself, normally on loopback. `ProxyClient` is `HttpConnector` only and `validate()` refuses `https://` upstreams to match — the two have to move together, or the form accepts config that 502s on every request with nothing to explain why.
- **Hostnames go through `host.rs`.** Five call sites had grown their own normaliser and disagreed about ports, trailing root dots and case — and several of these values are compared against each other to make access decisions. Two bugs already came out of that. New comparisons use `host::bare`/`of_url`/`covers`, never ad-hoc string work.

Being in the data path makes streaming, upgrades and timeouts bastion's problem: bodies are streamed rather than buffered, a `101` splices both connections with `copy_bidirectional` (protocol-agnostic, so WebSockets and anything else on `Upgrade` both work), hop-by-hop headers are stripped in both directions, and there is deliberately no overall response timeout because SSE and WebSockets are long-lived. It also means bastion's uptime is the app's uptime.

Authorization is re-read from the DB per request, so revoking a session or a grant applies immediately.

### Cookie scoping

bastion authenticates on its own hostname but serves the app on another, so the session cookie must carry `Domain=<parent>` (the `cookie_domain` setting) or it is never sent to the proxied host. `session::expire_host_only_session()` exists because `tower-cookies` keys removals by cookie *name*, so the jar can't clear the host-only and domain-scoped cookies at once; a leftover host-only cookie sorts first under RFC 6265 and would shadow every new session.

Turning the setting on with sessions already live is the case to watch. `middleware::load_user` only clears a host-only leftover on the branch where it *fails* to validate — a leftover that still works never trips it, and the user then looks signed in on bastion while the gated host sees nothing, so `login_page`'s shortcut bounces them back and forth forever. `login_page` therefore re-issues the same token domain-scoped and expires the host-only copy before taking that shortcut, which fixes it in one pass with no re-login. `normalize_cookie_domain()` also refuses public suffixes, since a browser drops those silently and the symptom is indistinguishable.

## Wire contract (`mode = 'redirect'`)

Services redirect unauthenticated users to `${BASTION}/auth/login?service=<slug>`. bastion authenticates via whichever provider the user picked, checks the grant, and redirects to the service's registered Return URL with `?bastion_token=<RS256 JWT>` appended. Consumers verify via `/.well-known/jwks.json` or call `GET /api/introspect` for live revocation-sensitive checks. JWT claims: `sub` (stable identity hash derived from the user's frozen sub anchor), `iss`, `aud=<slug>`, `svc=<slug>`, `username`, `perms[]`, `bastion_uid`, `exp`, `iat`, `jti`.

## Phase status

- Phase 1: GitHub OAuth, sessions, whitelist/pending/denied ✅
- Phase 2: Admin panel (users, requests, services, audit log) ✅
- Phase 3: RS256 JWT + JWKS + `/api/introspect` ✅
- First-run setup wizard ✅
- Google OAuth + multi-provider identities + `/account` link/unlink ✅
- Phase 4 (fine-grained per-service permissions) ✅
- Proxy mode (bastion reverse-proxies gated apps; identity as headers) ✅
