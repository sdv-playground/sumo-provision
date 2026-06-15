-- Optional authoring config snapshot for an immutable target release.
--
-- Tower 2 always owns the resolved release tree. When seed/publish tooling has
-- the source target config, it can attach that snapshot to the target release
-- so UIs can show the authored target_type/profile/components shape instead of
-- only the flattened resolved tree.

ALTER TABLE vehicle_releases ADD COLUMN IF NOT EXISTS config_snapshot JSONB;
