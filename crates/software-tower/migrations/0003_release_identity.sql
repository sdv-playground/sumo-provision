-- Content identity for releases, so re-seeding is idempotent + auto-versioned.
--
-- A release's *identity* is the hash of its content (a component's parts; a
-- vehicle's member set). The *version* is just a human label (a build number).
-- The reconcile resolves a freshly-built component/vehicle to a release by its
-- identity hash: same hash -> reuse the existing release (even an old one, so a
-- revert lands back on it); new hash -> cut a new version. `created_at` is the
-- build time (when this content was first cut).

ALTER TABLE component_releases ADD COLUMN IF NOT EXISTS identity_hash TEXT;
ALTER TABLE vehicle_releases   ADD COLUMN IF NOT EXISTS identity_hash TEXT;

-- One release per (entity, content) and per (tag, content). Partial so the
-- pre-identity rows (NULL) don't collide; new rows always carry a hash.
CREATE UNIQUE INDEX IF NOT EXISTS component_releases_identity
    ON component_releases (entity_path, identity_hash)
    WHERE identity_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS vehicle_releases_identity
    ON vehicle_releases (tag, identity_hash)
    WHERE identity_hash IS NOT NULL;
