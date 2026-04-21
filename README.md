# bastion

Central GitHub-SSO auth service for my self-hosted apps. SvelteKit + SQLite + Drizzle.

## Status

- ✅ **Phase 1** — GitHub OAuth, sessions, user upsert, whitelist/pending/denied flow
- ✅ **Phase 2** — Admin panel: users, access requests, service CRUD, audit log
- ✅ **First-run setup wizard** — no env-based bootstrap; configure via the UI
- ⏳ **Phase 3** — RS256 JWT + JWKS + `/api/introspect` so consumer apps can actually verify identity
- ⏳ **Phase 4** — Fine-grained per-service permissions

## Run

```bash
npm install
npm run db:push
npm run dev
```

Open <http://localhost:5180> → complete the setup wizard (GitHub OAuth creds → claim admin → add services).

Only env var: `DATABASE_PATH` (default `./data/bastion.db`).

## Integrating a service

Services redirect unauthenticated users to:

```
http://localhost:5180/auth/login?service=<slug>&return=<url-back-to-your-app>
```

Bastion authenticates via GitHub, checks the grant, and redirects back to `return` on success — or to `/pending` if the user needs admin approval. The `return` URL must start with the service's registered `returnUrlPrefix`.

**Current caveat**: Phase 3 isn't done, so no token is issued yet. Consumer apps have no way to verify the user's identity — they're just gated on "did bastion let them through". Fine for dev, not for anything real.

## Data model

```
users            github-linked accounts, status: active|pending|denied, is_admin flag
services         registered apps (slug, return_url_prefix)
grants           which users can access which services
permissions      per-service permission keys (unused until phase 4)
user_perms       fine-grained permission assignments
sessions         opaque bastion session tokens, sha256-hashed
access_requests  audit trail for "user X wants into service Y", admin-resolved
oauth_providers  github client id + secret (managed by setup wizard)
audit_log        admin actions
```

## Dev workflow

No migrations during early dev:

```bash
npm run db:push    # sync schema
npm run db:wipe    # start fresh (back to setup wizard)
npm run db:studio  # inspect
```

Wipe the DB on breaking schema changes.
