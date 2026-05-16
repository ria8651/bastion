-- Soft-delete for services. Replaces the strict unique slug index with a
-- partial unique index so a previously-deleted slug can be re-registered.

ALTER TABLE services ADD COLUMN deleted_at INTEGER;

DROP INDEX IF EXISTS services_slug_idx;
CREATE UNIQUE INDEX services_active_slug_idx
  ON services(slug) WHERE deleted_at IS NULL;
