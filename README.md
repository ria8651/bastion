# bastion

Central GitHub-SSO auth service for my self-hosted apps. SvelteKit + SQLite + Drizzle.

## Status

- ✅ **Phase 1** — GitHub OAuth, sessions, whitelist/pending/denied user states
- ✅ **Phase 2** — Admin panel: users, access requests, service CRUD, audit log
- ✅ **Phase 3** — RS256 JWT + JWKS + `/api/introspect` for consumer verification
- ✅ **First-run setup wizard** — no env-based bootstrap
- ⏳ **Phase 4** — Fine-grained per-service permissions

## Run (dev)

```bash
npm install
npm run db:push
npm run dev
```

Open <http://localhost:5180> → complete the setup wizard (GitHub OAuth creds → claim admin → add services).

Only env var: `DATABASE_PATH` (default `./data/bastion.db`).

## Run (Docker)

Image is a multi-stage Node build. The container runs `drizzle-kit push` at start, then the SvelteKit node server on port 5180.

Sample `docker-compose.yml` (not tracked here — keep in your own ops config):

```yaml
services:
  bastion:
    build:
      context: https://github.com/ria8651/bastion.git#main
    environment:
      DATABASE_PATH: /data/bastion.db
      # Must match your public-facing URL so GitHub OAuth redirects are built correctly.
      ORIGIN: https://auth.yourdomain.com
      PROTOCOL_HEADER: x-forwarded-proto
      HOST_HEADER: x-forwarded-host
    volumes:
      - bastion_data:/data
    ports:
      - "127.0.0.1:5180:5180"
    restart: unless-stopped
volumes:
  bastion_data:
```

Terminate TLS at nginx/caddy and proxy to `127.0.0.1:5180` with `X-Forwarded-Proto` + `X-Forwarded-Host` set.

## Integrating a service

Services redirect unauthenticated users to:

```
https://auth.yourdomain.com/auth/login?service=<slug>
```

Bastion authenticates via GitHub, checks the grant, and redirects back to the service's **registered Return URL** with `?bastion_token=<JWT>` appended — or to `/pending` if the user needs admin approval.

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

## Dev workflow

No migrations during early dev:

```bash
npm run db:push    # sync schema
npm run db:wipe    # start fresh (back to setup wizard)
npm run db:studio  # inspect
```

Wipe the DB on breaking schema changes.
