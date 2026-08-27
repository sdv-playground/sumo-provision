-- Record every device/architecture tuple a release has legitimately served.
-- Unlike channel_targets, this history is immutable when a channel moves and
-- therefore safely binds pinned L1 signing requests to their intended target.
CREATE TABLE vehicle_release_targets (
    vehicle_release_id BIGINT NOT NULL REFERENCES vehicle_releases(id),
    device             TEXT   NOT NULL,
    architecture       TEXT   NOT NULL,
    PRIMARY KEY (vehicle_release_id, device, architecture)
);

INSERT INTO vehicle_release_targets (vehicle_release_id, device, architecture)
SELECT DISTINCT vehicle_release_id, device, architecture FROM channel_targets
ON CONFLICT DO NOTHING;
