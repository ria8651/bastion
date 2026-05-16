# bastion

Central GitHub-SSO auth service for my self-hosted apps. axum + sqlx (SQLite) + maud + htmx, single static binary.

## Status

- ✅ **Phase 1** — GitHub OAuth, sessions, whitelist/pending/denied user states
- ✅ **Phase 2** — Admin panel: users, access requests, service CRUD, audit log
- ✅ **Phase 3** — RS256 JWT + JWKS + `/api/introspect` for consumer verification
- ✅ **First-run setup wizard** — no env-based bootstrap
- ⏳ **Phase 4** — Fine-grained per-service permissions

## Run (dev)

```bash
cargo run
```

Open <http://localhost:5180> → complete the setup wizard (GitHub OAuth creds → claim admin → add services). The binary creates the SQLite file and applies its schema (`CREATE TABLE IF NOT EXISTS …`) on startup — no migrations.

## Env vars

| Var | Default | Purpose |
|---|---|---|
| `DATABASE_PATH` | `./data/bastion.db` | SQLite file path |
| `ORIGIN` | (derived from request headers) | Public-facing URL, e.g. `https://auth.example.com`. Set behind a reverse proxy if it doesn't forward `X-Forwarded-{Host,Proto}`. |
| `PORT` | `5180` | Listen port |
| `RUST_LOG` | `info,sqlx=warn,tower_http=info` | Tracing filter |

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

## Data model

```
users            github-linked accounts, status: active|pending|denied, is_admin flag
services         registered apps (slug, return_url)
grants           which users can access which services
permissions      per-service permission keys (unused until phase 4)
user_perms       fine-grained permission assignments
sessions         opaque bastion session tokens, sha256-hashed
access_requests  audit trail for "user X wants into service Y", admin-resolved
oauth_providers  github client id + secret (managed by setup wizard)
signing_keys     RS256 keypairs for service-bound JWTs (auto-generated, rotatable)
audit_log        admin actions
```

## Source layout

```
src/
  main.rs           router + middleware + listener
  state.rs          AppState, origin/secure helpers
  error.rs          AppError -> HTML error page
  db.rs             sqlite pool + CREATE-IF-NOT-EXISTS bootstrap
  models.rs         User, Service, UserCtx, ...
  session.rs        token gen, sha256 store, sliding renewal
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
