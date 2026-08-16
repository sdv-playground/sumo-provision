-- Per-member release state: a member can be administratively DISABLED in a
-- vehicle release (deactivated rather than flashed). L1 assembly then emits a
-- signed disable manifest for it instead of a flash envelope. Additive — the
-- default (false) preserves the pre-disable behavior for every existing member.
ALTER TABLE vehicle_release_members ADD COLUMN disabled BOOLEAN NOT NULL DEFAULT false;
