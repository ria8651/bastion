-- Routes own the network side; services own access.
--
-- Proxy mode used to be a kind of service: a service row carrying one
-- hostname and one upstream. That fused two independent things — where
-- traffic goes, and who may go there — and left routes and proxy services
-- each missing what the other had (wildcards and https upstreams on one side,
-- public paths and the gate on the other).
--
-- Now a route is hostnames → upstream, and route.service_id, when set, gates
-- it: only people granted that service get through, with identity headers.
-- A service is the access unit — grants, requests, the launcher entry — and,
-- if it verifies bastion's JWT itself, a return URL. There is no mode column;
-- which integration a service uses is whatever is configured:
--
--   return_url set         → redirect integration (JWT wire contract)
--   a route points at it   → gated at the edge
--   both, or neither       → both are fine
--
-- return_url becomes optional, stored as '' rather than NULL: relaxing NOT
-- NULL means rebuilding the table, and dropping `services` with foreign keys
-- on would cascade-delete every grant and permission.

ALTER TABLE routes ADD COLUMN service_id   INTEGER NULL REFERENCES services(id);
ALTER TABLE routes ADD COLUMN public_paths TEXT NULL;

CREATE INDEX routes_service_idx ON routes(service_id);

-- Every live proxy service becomes a route gated by that same service.
INSERT INTO routes (name, upstream_url, service_id, public_paths)
SELECT slug, upstream_url, id, public_paths
FROM services
WHERE mode = 'proxy' AND proxy_host IS NOT NULL AND upstream_url IS NOT NULL
  AND deleted_at IS NULL;

-- The admin forms kept a hostname from being claimed by a route and a
-- service at once, so OR IGNORE should never fire; if it does, the existing
-- route keeps the name rather than the migration failing.
INSERT OR IGNORE INTO route_hosts (host, route_id)
SELECT s.proxy_host, r.id
FROM services s JOIN routes r ON r.service_id = s.id
WHERE s.mode = 'proxy' AND s.proxy_host IS NOT NULL AND s.deleted_at IS NULL;

-- A proxy service's return_url was filled in as https://<proxy_host>/ only so
-- /launch had somewhere to go. Left in place it would now mean "redirect
-- integration", and /launch would mint a JWT and append it to the URL of an
-- app that never asked for one.
UPDATE services SET return_url = '' WHERE mode = 'proxy';

DROP INDEX IF EXISTS services_proxy_host_idx;
ALTER TABLE services DROP COLUMN mode;
ALTER TABLE services DROP COLUMN proxy_host;
ALTER TABLE services DROP COLUMN upstream_url;
ALTER TABLE services DROP COLUMN public_paths;
