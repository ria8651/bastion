-- Service self-registration + per-service permission soft-delete.
--
-- Services can now self-register: on first boot a service generates an RSA
-- keypair, posts its identity + public JWK + permission catalog to
-- /api/services/register, and waits for an admin to approve. Subsequent
-- authenticated calls from the service (e.g. permission-catalog re-sync) are
-- signed with a short-lived JWT and verified against the stored public_jwk.
--
-- Existing manually-created services default to status='approved' so nothing
-- breaks at upgrade. Only fresh self-registrations land as 'pending'.

ALTER TABLE services ADD COLUMN status        TEXT    NOT NULL DEFAULT 'approved';
ALTER TABLE services ADD COLUMN public_jwk    TEXT    NULL;
ALTER TABLE services ADD COLUMN registered_at INTEGER NULL;
ALTER TABLE services ADD COLUMN approved_at   INTEGER NULL;
ALTER TABLE services ADD COLUMN approved_by   INTEGER NULL REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE permissions ADD COLUMN removed_at INTEGER NULL;

CREATE INDEX services_status_idx ON services(status) WHERE deleted_at IS NULL;
