-- Replace the (channel, target_type, profile) selector with
-- (channel, device, architecture).
--
-- The opaque `target_type` is decomposed into an explicit `device` (the ECU /
-- target class, e.g. `rig` vs `emulated` — it also encodes the platform, qvm vs
-- qemu) and `architecture` (`arm64` | `amd64`). `profile` (always "default" in
-- practice) is dropped. Artifacts stay content-addressed, so each
-- (device, architecture) combo resolves to its own arch-specific vehicle
-- release; tree_hash still binds plan -> execute.
--
-- The DB is dev/truncatable, so recreate the table rather than migrate rows
-- (target_type + profile were both in the primary key).
DROP TABLE IF EXISTS channel_targets;

CREATE TABLE channel_targets (
    channel            TEXT        NOT NULL,
    device             TEXT        NOT NULL,
    architecture       TEXT        NOT NULL,
    vehicle_release_id BIGINT      NOT NULL REFERENCES vehicle_releases(id),
    tree_hash          TEXT        NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (channel, device, architecture)
);
