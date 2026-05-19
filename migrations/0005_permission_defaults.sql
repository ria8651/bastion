-- Service-declared default-allow flag on permissions.
--
-- A permission with default_allow = 1 is automatically inserted into
-- user_perms when a user is granted access to the service. Admins can revoke
-- it per-user afterwards; the service flipping default_allow back to 0
-- doesn't retroactively remove anything.
--
-- Flipping a perm from default_allow=0 to default_allow=1 backfills user_perms
-- for everyone currently holding a grant on that service (once, at the
-- transition). After that, re-asserting the same flag is a no-op — so a
-- service can't force-regrant a permission that an admin has manually
-- revoked.

ALTER TABLE permissions ADD COLUMN default_allow INTEGER NOT NULL DEFAULT 0;
