# bastion

Central SSO auth service for `../boom` and `../binkflix`. axum + sqlx (SQLite) + maud + htmx + josekit (RS256 JWT/JWKS). Supports GitHub and Google OAuth; either can be used to set up bastion, and a single bastion user can have multiple linked identities.

Two concepts, one optional link. A **service** is the access side: slug, grants, access requests, launcher entry, and — if the app verifies bastion's JWT itself — a `return_url` (the wire contract below). A **route** is the network side: hostnames → upstream. `routes.service_id`, when set, **gates** the route: only people granted that service get through, with identity headers, so the app needs no knowledge of bastion. There is no mode column; a service with a return URL uses tokens, a service some route points at is gated at the edge, and both or neither are fine. `return_url = ''` means none (relaxing its NOT NULL would mean rebuilding `services`, which cascades through every grant). bastion can also be the **edge** for every host on the box, terminating TLS itself (see Edge mode).

## DB workflow: sqlx migrations

Schema lives in `migrations/NNNN_<name>.sql`, applied via `sqlx::migrate!("./migrations")` from `src/db.rs::connect()` at startup. Each schema change is a new numbered file — never edit an applied migration in place, since `sqlx` records its checksum in `_sqlx_migrations` and a mismatch aborts boot.

To add a delta: create `migrations/NNNN_<name>.sql` (use the next free number), put plain SQL in it, restart. The migration runs in a transaction; if any statement fails the whole migration rolls back. Use `ALTER TABLE ... ADD COLUMN` for additive changes and `DROP INDEX IF EXISTS` + `CREATE [UNIQUE] INDEX` for index swaps.

## Config lives in DB, not env

Env vars: `DATABASE_PATH` (default `./data/bastion.db`), `ORIGIN` (optional; otherwise derived from `X-Forwarded-{Host,Proto}` / `Host`; required in edge mode), `PORT` (default 5180), `RUST_LOG`, plus the edge set: `TLS_CERT`/`TLS_KEY`, `HTTPS_PORT` (443), `HTTP_PORT` (80 or `off`), `TRUSTED_PROXIES`. Listener and TLS config stays in env on purpose: a mistake there is one the admin UI couldn't be reached to fix. OAuth creds (GitHub and/or Google), services, first admin — all set via the `/setup` wizard, stored in DB. Post-setup, an admin can rotate or add provider creds from `/admin/providers`.

Instance-wide settings that belong to no single service live in the `settings` key/value table (`src/settings.rs`); setting a key to `""` deletes it, so "unset" and "empty" are one state. Currently only `cookie_domain`.

## Setup state is derived, not stored

`/setup` step is computed from DB on each request: no provider creds at all → step 1, no admin → step 2, no services → step 3. Either GitHub or Google (or both) satisfies step 1. `middleware::setup_gate` redirects all non-setup routes to `/setup` until complete.

## Multi-provider identity model

`users` is a single account record. `user_identities` is one row per linked OAuth identity (`provider`, `provider_id`, `email`, `avatar`, `last_login_at`). Users can link more providers via `/account` and unlink any of them as long as ≥1 remains.

The JWT `sub` is derived from a frozen pair `(users.sub_anchor_provider, users.sub_anchor_provider_id)` set once at signup, **never** updated. Linking or unlinking other identities does not change `sub`, so downstream services keep seeing the same user. `users.github_id` is legacy and unread by new code (kept for the existing NOT NULL constraint).

## Templating

Pages are plain async handlers returning `maud::Markup`. Layouts compose via function calls — `templates::layout(title, body)` for everything outside admin. No `.html` files. The stylesheet at `static/style.css` is inlined into pages via `include_str!` in `templates.rs`.

### Admin UI

`src/routes/admin/` is one module per section (`overview`, `users`, `requests`, `services`, `routes`, `providers`, `settings`, `audit`), plus `ui.rs`, which holds the shell and the components every page is built from: `header`, `section`, `badge`/`status_badge`, `notice`, `empty`, `field`, `Post` (one-button forms), `switch`. Pages compose those instead of using inline `style=` attributes. If a page needs something they don't cover, add a component or a class in `static/admin.css`. Every handler starts with `ctx(&state, &headers, user)`, which gates on admin and loads the nav counts.

- **`admin.css` is inlined inside `<body>`, not `<head>`,** because hx-boost swaps only the body. A head stylesheet wouldn't arrive when you click from the dashboard into admin.
- **Responsive by default.** There's a sidebar above 900px and a top bar plus drawer below it. Lists are `.row`s, not tables, so they reflow at any width; `.row.decide` puts a pair of decision buttons full-width underneath on phones.
- **Nav groups (Access / Apps / System) are where roadmap pages slot in**: groups and roles under Access, routes under Apps, certificates under System.
- **In-place toggles use `Post::stay()` / `switch()`,** which set `hx-swap="innerHTML show:none"` so the page doesn't jump to the top. Handlers that several pages post to take a `next` param, validated by `ui::next_or` (local `/admin` paths only).
- **No dead controls.** Don't add a filter, sort or export control that isn't wired up.

## htmx

`<body hx-boost="true">` makes all link clicks and form submissions XHR-driven swaps of the body. Mutation handlers do their work and return `303 See Other`; the browser/htmx re-fetches the new page. No JSON API for the UI. Logout uses `hx-boost="false"` for a hard reload.

## Routes and the gate

bastion answers on the app's own hostname, looks up the route, and forwards to its upstream. For a gated route it first checks the session and the grant, then attaches the caller's identity as headers.

`src/proxy.rs` holds the decision plus transport; `src/edge.rs` the route lookup and validation. `proxy_gate` is a middleware layered *outside* `load_user` and `setup_gate` (a routed host is not part of bastion's UI and must not be redirected into the setup wizard) but *inside* the cookie layer, since it reads the session itself. Order: bastion's own host (`ORIGIN`, or a bare IP / localhost) → route (exact, then the most specific `*.` wildcard) → bastion if `ORIGIN` is unpinned → 404. Own host goes first so a wildcard covering it can't take over the admin UI. Invariants worth keeping:

- **The outbound header map is built from scratch, never edited.** `is_identity_header()` drops the entire `x-bastion-*` prefix plus the `remote-*` names before anything is copied across, so a client cannot smuggle in an identity header. Prefix matching is the point: a name added later is protected the moment it exists. This is the structural advantage over forward auth, where the equivalent has to be enumerated by hand in gateway config.
- **Redirect targets are allowlisted.** `?redirect=` on `/auth/login` comes from a 401 on an attacker-reachable host. `validate_redirect()` puts the parsed host through the router's own `edge::lookup` and requires it to land on a route gated by a live service (the named one, if any) — so wildcards cover exactly what they cover for traffic, and an open route is never a post-login target. Re-validated at every hop, including the hidden form field.
- **A gate whose service is gone stays shut.** `routes.service_id` points at a soft-deleted service once it's removed. `proxy_gate` answers 503 rather than forwarding ungated — otherwise removing a service would publish whatever it protected. The route form offers the dead service as a marked option so an unrelated edit can't silently fall back to "Open".
- **Only navigations get redirected.** `wants_html()` gates it, so a `fetch()` or WebSocket handshake gets a bare 401 rather than an OAuth page.
- **Upstreams are admin-only.** They live on routes, which only the admin UI creates. A self-registering service that could set its own upstream would turn bastion into an open proxy onto whatever the box can reach.
- **bastion's session cookie never leaves bastion.** A gated route requires a `cookie_domain`, so the browser sends `bastion_session` to every host under it, open routes included. It is a bearer credential — `validate_session_token` needs nothing else — so forwarding it would hand each app, its access logs and anything that compromises it a credential for bastion's own admin UI and every other gated app. `strip_bastion_cookies()` rebuilds the outbound `Cookie` header without it; the app's own cookies pass through untouched.
- **Dot-segments are rejected outright.** `http::Uri` keeps the path verbatim and `glob_match`'s `*` spans `/`, so `/api/hooks/*` matched `/api/hooks/../../admin` — public path, no auth, forwarded un-normalized for the upstream to resolve back to `/admin`. `has_dot_segment()` runs before any routing decision and on every proxied request. Normalizing instead would be worse: normalize only for the match and the gap reopens; normalize both and the app silently sees a different path.
- **Public URLs come from config, not the request.** `public_origin()` builds `(scheme, authority)` from the matched route hostname plus `ORIGIN`'s scheme and port. Echoing the request would let a client pick the port (`request_host` strips it before matching, so `Host: app.example.com:1337` matches fine) and the scheme (`X-Forwarded-Proto` is unauthenticated), and any app that builds absolute URLs from `X-Forwarded-Host` — password-reset mail being the classic — would emit them. `request_host()` still strips the port for matching routes; `request_authority()` remains only as the `ORIGIN`-unpinned fallback. A request on bastion's own TLS listener uses that listener instead (`https`, `HTTPS_PORT`), equally config-derived and more precise, since `ORIGIN` describes how bastion itself is reached.
- **A gated route sends no permissions.** An app behind one can't register a catalog, so the header would always be empty. The grant is the whole decision; `permissions`/`user_perms` travel in the JWT only.
- **A loop marker guards against recursion.** An upstream that resolves back to bastion — directly, or via a DNS alias config-time validation can't see through — recurses, because `Host` is copied to the upstream and so matches the same route on arrival. `edge::validate_upstream` catches the obvious case up front: a route's own hostname on 80, 443 or one of bastion's ports (a different port on the same name is the app next door, not a loop). On a public path that needs no session, one request spirals until the process runs out of descriptors. `LOOP_MARKER` is checked in `proxy_gate` against the *raw* inbound request, which works only because `is_identity_header` runs later, in `forward` — keep that ordering.
- **`cookie_domain` is enforced, not just advised.** Without one the session cookie never reaches the gated host, so the browser is sent to log in, comes back with nothing, and is sent again — and that is the state a route is in the moment it is first gated. `proxy_gate` refuses with a 503 explaining it rather than looping. `normalize_cookie_domain` separately refuses a domain that doesn't cover `ORIGIN`'s host, which would otherwise lock everyone out *and* destroy the admin's own session on their next page load.
- **Upstreams may be https.** `ProxyClient` holds two hyper-rustls clients, one verifying against the webpki roots and one (`AnyCert`) accepting any certificate, for self-signed LAN upstreams — an admin flag on the route.
- **Hostnames go through `host.rs`.** Five call sites had grown their own normaliser and disagreed about ports, trailing root dots and case — and several of these values are compared against each other to make access decisions. Two bugs already came out of that. New comparisons use `host::bare`/`of_url`/`covers`, never ad-hoc string work.

- **Forwarding headers are believed only from `TRUSTED_PROXIES`** (default `none` in edge mode, private ranges behind a gateway). `forwarded::resolve` gives the client IP (rightmost untrusted `X-Forwarded-For` entry, else the peer) and the scheme (`https` on bastion's own TLS listener, a trusted `X-Forwarded-Proto` otherwise). An untrusted peer's chain is dropped rather than appended to, and an inbound `Forwarded` is never passed on. The exception is `state::origin_from` with `ORIGIN` unset, which still reads `X-Forwarded-Host`/`-Proto` from anyone — only possible behind a gateway, since edge mode requires `ORIGIN`.
- **Routing and the upstream agree on the host.** Routing reads the URI authority before `Host` (HTTP/2 has nothing else, and an absolute-form request line overrides `Host` per RFC 9112). A request naming two hosts — `GET http://open.example.com/` with `Host: gated.example.com` — would be matched on one and served by an upstream picking its site by the other, past the gate. `names_two_hosts` refuses it with a 400 before anything is decided, and `forward` sets the outbound `Host` from the routed authority regardless.
- **A disabled route keeps its names.** `edge::lookup` picks the most specific pattern first and only then checks `enabled`; filtering first would let disabling gated `secret.example.com` hand it to an open `*.example.com`.
- **Upstreams can't set bastion's cookies.** `drop_bastion_set_cookies` removes `Set-Cookie` for `bastion_session`/`bastion_oauth_state` from every response — any app under the cookie domain could otherwise overwrite the session.
- **Gated hosts must be under the cookie domain.** The route form refuses one that isn't, and the gate answers 503 for it, since the cookie never arrives and `login_page` would bounce a signed-in user back forever.
- **A gate-only service can't be claimed by registration.** `/api/services/register` refuses a keyless service with no return URL: nothing legitimate registers against it, and its slug is visible in the gate's login redirect. Keyless *with* a return URL is the setup-wizard flow, where the app binds its key on first boot.

Being in the data path makes streaming, upgrades and timeouts bastion's problem: bodies are streamed rather than buffered, a `101` splices both connections with `copy_bidirectional` (protocol-agnostic, so WebSockets and anything else on `Upgrade` both work), hop-by-hop headers are stripped in both directions, and there is deliberately no overall response timeout because SSE and WebSockets are long-lived. It also means bastion's uptime is the app's uptime.

Authorization is re-read from the DB per request, so revoking a session or a grant applies immediately.

## Edge mode (routes + TLS)

`TLS_CERT` + `TLS_KEY` turn it on. `serve.rs` drives hyper directly (axum::serve can't do TLS) and puts `ConnectInfo` and `ConnMeta { tls }` on every request; the plaintext `PORT` keeps serving the same app, and port 80 only redirects hosts something answers on. HTTP/1.1 only, matching the nginx it replaced. `serve::Limits` caps open connections process-wide (pending TLS handshakes and upgraded WebSockets included — `forward` carries the permit into the splice task); at the cap, accepting pauses rather than running into EMFILE. Headers must arrive within 30s and a request body may not go 60s without a frame (`StallTimeout`, whose clock only runs while the body is being read). Idle upgraded connections aren't timed out — WebSockets are legitimately quiet.

Routes work the same with or without it — behind a gateway, it forwards the names to the plaintext port. `route_hosts.host` is the primary key, so two routes can't hold one pattern; `edge::host_owner` turns that into a readable form error.

`tls::CertStore` re-reads the pair when either mtime moves (checked every minute). A pair that fails to load leaves the old one serving and surfaces as `reload_error` on the settings page. bastion never issues certificates. Whatever owns renewal keeps owning it, which is also the only way to cover private names like `*.lan` — but it has to be DNS-01, since bastion holds port 80 and redirects every request, ACME challenges included.

### Cookie scoping

bastion authenticates on its own hostname but serves the app on another, so the session cookie must carry `Domain=<parent>` (the `cookie_domain` setting) or it is never sent to the proxied host. `session::expire_host_only_session()` exists because `tower-cookies` keys removals by cookie *name*, so the jar can't clear the host-only and domain-scoped cookies at once; a leftover host-only cookie sorts first under RFC 6265 and would shadow every new session.

Turning the setting on with sessions already live is the case to watch. `middleware::load_user` only clears a host-only leftover on the branch where it *fails* to validate — a leftover that still works never trips it, and the user then looks signed in on bastion while the gated host sees nothing, so `login_page`'s shortcut bounces them back and forth forever. `login_page` therefore re-issues the same token domain-scoped and expires the host-only copy before taking that shortcut, which fixes it in one pass with no re-login. `normalize_cookie_domain()` also refuses public suffixes, since a browser drops those silently and the symptom is indistinguishable.

## Wire contract (services with a `return_url`)

Services redirect unauthenticated users to `${BASTION}/auth/login?service=<slug>`. bastion authenticates via whichever provider the user picked, checks the grant, and redirects to the service's registered Return URL with `?bastion_token=<RS256 JWT>` appended. Consumers verify via `/.well-known/jwks.json` or call `GET /api/introspect` for live revocation-sensitive checks. JWT claims: `sub` (stable identity hash derived from the user's frozen sub anchor), `iss`, `aud=<slug>`, `svc=<slug>`, `username`, `perms[]`, `bastion_uid`, `exp`, `iat`, `jti`, plus `device_id` on tokens minted for a paired device.

### Device sign-in (RFC 8628)

For clients with no browser (the binkflix Apple TV app). `src/device.rs` holds the grant; `src/routes/device.rs` the HTTP side. The device calls `POST /api/device/code` and polls `POST /api/device/token` (both form-encoded, RFC-shaped errors); a person confirms at `/device` on their phone. Pairing yields a refresh token, which the device swaps for the same JWT a browser gets. Invariants:

- **Off per service** (`services.device_login`). The client is public, so anyone can start a pairing for any slug, and the confirm page is the only defence against a phished code. It names the device and service and always needs a click, even with the code prefilled from the QR.
- **Refresh re-derives everything.** User active, service live and still `device_login`, grant held, current perms. Nothing is copied at pairing time, so a revocation reaches the device within one JWT lifetime. `/api/introspect` checks `devices.revoked_at` for an instant answer. Losing the grant doesn't revoke the device, so restoring the grant brings it back.
- **Refresh tokens don't rotate.** A TV that lost a rotation response would be locked out. They're stored hashed, with a 90-day idle expiry.
- **Codes are single-use, and taking them is atomic.** The approving poll `DELETE … RETURNING`s the `device_codes` row, so two racing polls can't both mint a device.
- **No unauthenticated code oracle.** Signed out, `/device` only carries the code through login (`OAuthState.device`, re-checked in the callback since that cookie is unsigned) and never looks it up. Signed in, wrong codes are counted per user, in memory, on the page and on the approve and deny posts alike. A user is refused after 10 in 10 minutes.
- **Approve and deny must come from bastion's own page.** `SameSite=Lax` doesn't ensure it, because every host bastion fronts is the same site, so `same_origin()` checks `Sec-Fetch-Site`, falling back to `Origin`. `/device` responses also forbid framing, since the confirm page is one click from a 90-day credential.
- **The device name is attacker-chosen.** It comes from an unauthenticated request, so control and bidi characters are stripped, and the page says "a device calling itself …". Pending codes are capped at 50 per service, so flooding one service can't block pairing for the others.
- "Sign out everywhere" on the admin user page revokes devices too.

## Phase status

- Phase 1: GitHub OAuth, sessions, whitelist/pending/denied ✅
- Phase 2: Admin panel (users, requests, services, audit log) ✅
- Phase 3: RS256 JWT + JWKS + `/api/introspect` ✅
- First-run setup wizard ✅
- Google OAuth + multi-provider identities + `/account` link/unlink ✅
- Phase 4 (fine-grained per-service permissions) ✅
- Proxy mode (bastion reverse-proxies gated apps; identity as headers) ✅
- Edge mode (TLS termination, routes open or gated, trusted-proxy forwarding) ✅
- Device sign-in (RFC 8628 device flow, refresh tokens, per-service opt-in) ✅
