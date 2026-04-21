# bastion

Central GitHub-SSO auth service for `../boom` and `../binkflix`. SvelteKit + SQLite + Drizzle + Arctic.

## DB workflow: no migrations

Schema lives in `src/lib/server/db/schema.ts`. Sync with `drizzle-kit push`, not migrations.

- `npm run db:push` — sync schema
- `npm run db:wipe` — delete DB + repush (redoes setup wizard)

On breaking schema changes just wipe. Don't write migrations until real data matters.

## Config lives in DB, not env

Only env var: `DATABASE_PATH` (default `./data/bastion.db`). GitHub OAuth creds, services, first admin — all set via the `/setup` wizard, stored in DB.

## Setup state is derived, not stored

`/setup` step is computed from DB on each request: no github creds → step 1, no admin → step 2, no services → step 3. `hooks.server.ts` redirects all non-setup routes to `/setup` until complete.

## Phase status

Phase 1+2 done: OAuth login, sessions, admin panel. No JWT yet — services currently just get redirect-based gating, no token to verify. Phase 3 will add RS256 JWT + JWKS + `/api/introspect`.
