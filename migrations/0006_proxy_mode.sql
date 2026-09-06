-- Proxy mode: bastion gates apps that know nothing about it.
--
-- A service now operates in one of two modes:
--
--   'redirect' — the original wire contract. bastion redirects to return_url
--                with ?bastion_token=<RS256 JWT> and the service verifies it
--                against /.well-known/jwks.json.
--
--   'proxy'    — bastion serves proxy_host itself, checks the session and the
--                grant, and forwards the request to upstream_url with the
--                caller's identity attached as headers. The app needs no
--                knowledge of bastion; if it wants the identity it reads the
--                headers, and if it doesn't it just sees authenticated traffic.
--
-- proxy_host is the public hostname bastion answers on for this app, and is
-- also the allowlist for post-login redirects — a redirect target is honoured
-- only if its host is a registered proxy_host.
--
-- upstream_url is where the app actually listens (http://127.0.0.1:8080).
-- It is admin-only on purpose: a service that could set its own upstream could
-- point bastion at anything reachable from the box.
--
-- public_paths is a newline-separated list of path globs ('*' matches any run
-- of characters) that skip the auth check, for health probes and webhook
-- receivers. Matched against the request path, query excluded.
--
-- settings holds instance-wide config that belongs to no single service.
-- Currently only cookie_domain: bastion authenticates on its own hostname but
-- serves the app on another, so the session cookie has to be scoped to a
-- parent domain covering both or it is never sent to the proxied host.

ALTER TABLE services ADD COLUMN mode         TEXT NOT NULL DEFAULT 'redirect';
ALTER TABLE services ADD COLUMN proxy_host   TEXT NULL;
ALTER TABLE services ADD COLUMN upstream_url TEXT NULL;
ALTER TABLE services ADD COLUMN public_paths TEXT NULL;

CREATE UNIQUE INDEX services_proxy_host_idx
  ON services(proxy_host) WHERE proxy_host IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
