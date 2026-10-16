-- Device sign-in: the OAuth device authorization grant (RFC 8628) for clients
-- with no browser of their own — a TV app, a CLI.
--
-- The device asks for a code, shows it (and a QR of /device?code=…), and polls.
-- Someone signs in to bastion on their phone, enters the code, confirms, and
-- the device's next poll collects a refresh token. It trades that for the
-- same short-lived JWT a browser gets, so the app verifies one kind of token.
--
-- Off per service: the client is public, so anyone can start a pairing for any
-- slug, and the only thing standing between a phished code and an account is
-- the confirm page. Services that have no device client shouldn't carry that.

ALTER TABLE services ADD COLUMN device_login INTEGER NOT NULL DEFAULT 0;

-- A pairing in progress. Short-lived and single-use: the poll that collects
-- the refresh token deletes the row. device_code is the device's secret, so
-- only its hash is kept; user_code is typed by a person and looked up as-is.
CREATE TABLE device_codes (
  device_code_hash TEXT PRIMARY KEY,
  user_code        TEXT NOT NULL UNIQUE,
  service_id       INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  created_at       INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at       INTEGER NOT NULL,
  last_poll_at     INTEGER NULL,
  approved_by      INTEGER NULL REFERENCES users(id) ON DELETE CASCADE,
  denied           INTEGER NOT NULL DEFAULT 0
);

-- A paired device. Holds the hash of a long-lived refresh token; every refresh
-- re-checks the user, the service and the grant, so revoking any of them cuts
-- the device off by the time its current JWT expires.
CREATE TABLE devices (
  id           INTEGER PRIMARY KEY,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  service_id   INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  last_used_at INTEGER NULL,
  revoked_at   INTEGER NULL
);

CREATE INDEX devices_user_idx ON devices(user_id) WHERE revoked_at IS NULL;
CREATE INDEX devices_service_idx ON devices(service_id) WHERE revoked_at IS NULL;
