-- (channel, target_type, profile) -> immutable target release.
--
-- The multi-profile spec's first-class resolution tuple
-- (docs/sumo-provision-multi-profile-update-draft.md §11). Replaces the single
-- channels(name -> vehicle_release) pointer: a channel is a moving release
-- STREAM; the target_type (reusable topology/compatibility class, e.g.
-- `managed-cvc-rig`, `qemu-virtual`) + profile (variant, e.g. `dev`,
-- `integration-test`) select WHICH desired target (vehicle) release the stream
-- points at.
--
-- tree_hash binds plan -> execute (§2.2): the canonical CONTENT hash of the
-- resolved tree (sorted entity_path -> sorted (part_id, content_hash)). Unlike a
-- vehicle release's id-based identity_hash, it is content-stable across DB
-- instances, so a campaign planned against a channel resolves and executes the
-- exact same tree.
--
-- The DB is dev/truncatable, so this replaces `channels` outright rather than
-- migrating rows. The degenerate case — one channel folder, one type/profile —
-- is a single row.
CREATE TABLE IF NOT EXISTS channel_targets (
    channel            TEXT        NOT NULL,
    target_type        TEXT        NOT NULL,
    profile            TEXT        NOT NULL,
    vehicle_release_id BIGINT      NOT NULL REFERENCES vehicle_releases(id),
    tree_hash          TEXT        NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (channel, target_type, profile)
);

DROP TABLE IF EXISTS channels;
