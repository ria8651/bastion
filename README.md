# bastion

Central SSO auth service for my self-hosted apps. GitHub and/or Google OAuth. axum + sqlx (SQLite) + maud + htmx, single static binary.

Apps integrate either by **verifying a JWT** (the app knows about bastion) or by being **reverse-proxied** by bastion (the app knows nothing at all — see [Gating an app that knows nothing about bastion](#gating-an-app-that-knows-nothing-about-bastion)).

## Status

- ✅ **Phase 1** — GitHub OAuth, sessions, whitelist/pending/denied user states
- ✅ **Phase 2** — Admin panel: users, access requests, service CRUD, audit log
- ✅ **Phase 3** — RS256 JWT + JWKS + `/api/introspect` for consumer verification
- ✅ **First-run setup wizard** — no env-based bootstrap
- ✅ **Google OAuth** — multi-provider identities, `/account` link/unlink
- ✅ **Phase 4** — Fine-grained per-service permissions
- ✅ **Proxy mode** — bastion reverse-proxies and gates apps that know nothing about it

## Run (dev)

```bash
cargo run
```

Open <http://localhost:5180> → complete the setup wizard (OAuth creds → claim admin → add services). The binary creates the SQLite file and runs `migrations/*.sql` via `sqlx::migrate!` on startup.

## Env vars

| Var | Default | Purpose |
|---|---|---|
| `DATABASE_PATH` | `./data/bastion.db` | SQLite file path |
| `ORIGIN` | (derived from request headers) | Public-facing URL, e.g. `https://auth.example.com`. Set behind a reverse proxy if it doesn't forward `X-Forwarded-{Host,Proto}`. |
| `PORT` | `5180` | Listen port |
| `RUST_LOG` | `info,sqlx=warn,tower_http=info` | Tracing filter |

Everything else — OAuth credentials, services, the session cookie domain — lives in the database and is managed from `/setup` and `/admin`.

## Run (Docker)

Multi-stage build → ~10 MB image with a single static binary inside.

```yaml
services:
  bastion:
    build:
      context: https://github.com/ria8651/bastion.git#main
    environment:
      DATABASE_PATH: /data/bastion.db
      ORIGIN: https://auth.yourdomain.com
    volumes:
      - bastion_data:/data
    ports:
      - "127.0.0.1:5180:5180"
    restart: unless-stopped
volumes:
  bastion_data:
```

Terminate TLS at nginx/Caddy and proxy to `127.0.0.1:5180` with `X-Forwarded-Proto` + `X-Forwarded-Host` set (or pin `ORIGIN` explicitly).

## Integrating a service

Services redirect unauthenticated users to:

```
https://auth.yourdomain.com/auth/login?service=<slug>
```

bastion authenticates via GitHub, checks the grant, and redirects back to the service's **registered Return URL** with `?bastion_token=<JWT>` appended — or to `/pending` if the user needs admin approval.

The consumer app:

1. Registers the full return URL (e.g. `https://binkflix.yourdomain.com/auth/bastion`) via bastion's admin panel.
2. Verifies the token using the JWKS at `/.well-known/jwks.json`, checking `iss`, `aud = <slug>`, and `svc = <slug>`.
3. Mints its own session cookie and redirects to the app root.

Fresh grant/perm state is available via `GET /api/introspect` with an `Authorization: Bearer <jwt>` header — useful for revocation-sensitive checks that shouldn't wait for JWT expiry.

## Gating an app that knows nothing about bastion

Switch a service to **proxy mode** and bastion serves the app's hostname itself: it checks the session and the grant, then forwards upstream with the caller's identity attached as headers. No gateway config, no auth code in the app.

Setup, in `/admin/services`:

1. **Set a session cookie domain** under *Proxy mode* (e.g. `example.com`). Sign-in happens on bastion's own hostname, so a host-only cookie is never sent to the app. This is required, not advisory — without it a gated host answers 503 rather than bouncing the browser between bastion and the app forever. It must cover bastion's own host, which is checked when you save it. Use a domain you control end to end; every host under it receives the token.
2. **Pin `ORIGIN`**, since a proxied request's `Host` is the app's hostname, not bastion's.
3. **Add the service** in proxy mode with its public hostname and upstream (`http://127.0.0.1:8080`), then point that hostname's DNS and TLS at bastion.

The app receives `X-Bastion-User`, `-Sub` (the same stable `sub` as the JWT) and `-Email`, plus `Remote-User`/`Remote-Email` for off-the-shelf apps that already read those. It's free to ignore all of them; the gate has already happened.

No permissions are sent. A permission catalog is declared by the service through `/api/services/register`, which a proxied app can't do — so proxy mode is a plain gate and per-service permissions stay a redirect-mode feature.

Three things worth knowing. **Forged identity headers are impossible by construction** — the outbound header map is built from scratch and bastion's whole header namespace is dropped from the inbound request, with no configuration involved. **Revocation is immediate**, because every request re-reads the session and the grant. And **bastion is now in the data path**: bodies stream rather than buffer, WebSockets and other `Upgrade` protocols are spliced through, but bastion's uptime is the app's uptime.

Per-service *public paths* skip auth entirely for health probes and webhooks; `*` matches any run of characters (`/health`, `/api/hooks/*`).

## Data model

```
users            github-linked accounts, status: active|pending|denied, is_admin flag
services         registered apps (slug, return_url, mode, proxy_host, upstream_url, public_paths)
grants           which users can access which services
permissions      per-service permission keys (unused until phase 4)
user_perms       fine-grained permission assignments
sessions         opaque bastion session tokens, sha256-hashed
access_requests  audit trail for "user X wants into service Y", admin-resolved
oauth_providers  github/google client id + secret (managed by setup wizard)
settings         instance-wide config; currently the session cookie domain
signing_keys     RS256 keypairs for service-bound JWTs (auto-generated, rotatable)
audit_log        admin actions
```

## Source layout

```
src/
  main.rs           router + middleware + listener
  state.rs          AppState, origin/secure helpers
  error.rs          AppError -> HTML error page
  db.rs             sqlite pool + sqlx migrations
  models.rs         User, Service, UserCtx, ...
  session.rs        token gen, sha256 store, sliding renewal, cookie scoping
  settings.rs       instance-wide key/value config
  proxy.rs          reverse proxy for mode='proxy': gate, header injection, upgrades
  host.rs           hostname normalisation + cookie-domain containment
  grants.rs         "is this user allowed into this service"
  oauth.rs          GitHub OAuth (authorize URL, code exchange, /user fetch)
  keys.rs           RS256 keypair gen, JWK persistence
  jwt.rs            identity_hash, issue_service_token, verify_service_token
  audit.rs          audit_log insert helper
  setup.rs          setup-state derivation + oauth_providers CRUD
  middleware.rs     load_user, setup_gate, require_admin
  templates.rs      maud layout + admin_layout + status_pill
  routes/
    home.rs         GET /, /pending, /denied
    auth.rs         /auth/login (GET+POST), /auth/callback, /auth/logout
    setup.rs        /setup wizard + actions
    admin.rs        /admin/* (overview, requests, users, services + actions)
    jwks.rs         /.well-known/jwks.json
    introspect.rs   /api/introspect
static/
  style.css         inlined into pages via include_str!
```

## Templating

Pages are async handlers that return `maud::Markup`. Layouts compose via plain function calls — `templates::layout(title, user, body)` or `templates::admin_layout(title, tab, user, body)`. No `.html` files, no template inheritance, no client-side framework.

`<body hx-boost="true">` makes all links + forms XHR-driven swaps of the body; the server still does full server-side rendering on every request. Mutation handlers do their work and return `303 See Other` to the relevant GET page; the browser re-fetches it. No JSON API for the UI.
