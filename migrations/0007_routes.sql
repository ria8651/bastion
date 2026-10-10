-- Edge routes: hostnames bastion forwards without asking who you are.
--
-- A proxy-mode service is a gate — session, grant, identity headers. A route
-- is the same transport with no gate, for everything else bastion fronts as
-- the edge: media servers, the static site, anything with its own login.
-- Gated hosts stay services; a hostname is either one or the other, which the
-- admin UI enforces in both directions.
--
-- route_hosts is one row per name rather than a list column so the database
-- keeps two routes from claiming the same host, and so a lookup is an index
-- probe. A name is either exact (app.example.com) or a wildcard covering any
-- depth of subdomain (*.apps.example.com). Matching tries the exact name
-- first, then each parent wildcard from most to least specific.
--
-- upstream_url may be https; tls_skip_verify is for upstreams with a
-- self-signed certificate, which on a LAN is most of them.

CREATE TABLE routes (
  id              INTEGER PRIMARY KEY,
  name            TEXT NOT NULL,
  upstream_url    TEXT NOT NULL,
  tls_skip_verify INTEGER NOT NULL DEFAULT 0,
  enabled         INTEGER NOT NULL DEFAULT 1,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE route_hosts (
  host     TEXT PRIMARY KEY,
  route_id INTEGER NOT NULL REFERENCES routes(id) ON DELETE CASCADE
);

CREATE INDEX route_hosts_route_idx ON route_hosts(route_id);
