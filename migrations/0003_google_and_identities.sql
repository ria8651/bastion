-- Multi-provider auth: per-user linked identities + frozen JWT sub anchor.
--
-- A bastion user is now a one-to-many on `user_identities`. Each row is one
-- linked login method (GitHub, Google, …). The JWT `sub` is derived from a
-- frozen `(sub_anchor_provider, sub_anchor_provider_id)` pair stored on
-- `users`, set once at signup and never updated — so linking or unlinking a
-- provider doesn't change a user's downstream identity.
--
-- The legacy `users.github_id` column is left in place (no-op data) so the
-- existing UNIQUE index keeps the table valid; new code reads from
-- `user_identities` and `sub_anchor_*` instead.

CREATE TABLE user_identities (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider      TEXT NOT NULL,
  provider_id   TEXT NOT NULL,
  email         TEXT,
  avatar        TEXT,
  linked_at     INTEGER NOT NULL DEFAULT (unixepoch()),
  last_login_at INTEGER
);
CREATE UNIQUE INDEX user_identities_provider_idx ON user_identities(provider, provider_id);
CREATE INDEX        user_identities_user_idx     ON user_identities(user_id);

INSERT INTO user_identities (user_id, provider, provider_id, email, avatar, linked_at, last_login_at)
SELECT id, 'github', CAST(github_id AS TEXT), email, avatar, created_at, last_login_at
FROM users;

ALTER TABLE users ADD COLUMN sub_anchor_provider    TEXT;
ALTER TABLE users ADD COLUMN sub_anchor_provider_id TEXT;
UPDATE users
SET sub_anchor_provider    = 'github',
    sub_anchor_provider_id = CAST(github_id AS TEXT);

-- Drop the legacy UNIQUE index on github_id. Multiple non-github signups will
-- share the sentinel value 0 in that column; uniqueness now lives on
-- user_identities(provider, provider_id).
DROP INDEX IF EXISTS users_github_id_idx;
