# bastion

Central GitHub-SSO auth service for `../boom` and `../binkflix`. axum + sqlx (SQLite) + maud + htmx + josekit (RS256 JWT/JWKS).

## DB workflow: sqlx migrations

Schema lives in `migrations/NNNN_<name>.sql`, applied via `sqlx::migrate!("./migrations")` from `src/db.rs::connect()` at startup. Each schema change is a new numbered file — never edit an applied migration in place, since `sqlx` records its checksum in `_sqlx_migrations` and a mismatch aborts boot.

To add a delta: create `migrations/NNNN_<name>.sql` (use the next free number), put plain SQL in it, restart. The migration runs in a transaction; if any statement fails the whole migration rolls back. Use `ALTER TABLE ... ADD COLUMN` for additive changes and `DROP INDEX IF EXISTS` + `CREATE [UNIQUE] INDEX` for index swaps.

## Config lives in DB, not env

Env vars: `DATABASE_PATH` (default `./data/bastion.db`), `ORIGIN` (optional; otherwise derived from `X-Forwarded-{Host,Proto}` / `Host`), `PORT` (default 5180), `RUST_LOG`. GitHub OAuth creds, services, first admin — all set via the `/setup` wizard, stored in DB.

## Setup state is derived, not stored

`/setup` step is computed from DB on each request: no github creds → step 1, no admin → step 2, no services → step 3. `middleware::setup_gate` redirects all non-setup routes to `/setup` until complete.

## Templating

Pages are plain async handlers returning `maud::Markup`. Layouts compose via function calls — `templates::layout(title, user, body)` and `templates::admin_layout(title, tab, user, body)`. No `.html` files. The stylesheet at `static/style.css` is inlined into pages via `include_str!` in `templates.rs`.

## htmx

`<body hx-boost="true">` makes all link clicks and form submissions XHR-driven swaps of the body. Mutation handlers do their work and return `303 See Other`; the browser/htmx re-fetches the new page. No JSON API for the UI. Logout uses `hx-boost="false"` for a hard reload.

## Wire contract (unchanged from the SvelteKit version)

Services redirect unauthenticated users to `${BASTION}/auth/login?service=<slug>`. bastion authenticates via GitHub, checks the grant, and redirects to the service's registered Return URL with `?bastion_token=<RS256 JWT>` appended. Consumers verify via `/.well-known/jwks.json` or call `GET /api/introspect` for live revocation-sensitive checks. JWT claims: `sub` (stable identity hash), `iss`, `aud=<slug>`, `svc=<slug>`, `username`, `perms[]`, `bastion_uid`, `exp`, `iat`, `jti`.

## Phase status

- Phase 1: GitHub OAuth, sessions, whitelist/pending/denied ✅
- Phase 2: Admin panel (users, requests, services, audit log) ✅
- Phase 3: RS256 JWT + JWKS + `/api/introspect` ✅
- First-run setup wizard ✅
- Phase 4 (fine-grained per-service permissions): not started
