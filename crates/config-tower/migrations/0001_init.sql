-- What a configuration tower holds, and it is exactly two things.
--
-- A SCHEMA is what a model version DECLARES: the sets, and for each set the
-- JSON Schema its values must satisfy. It is keyed by `(model, version)` and by
-- nothing else, because a declaration belongs to a build of the vehicle rather
-- than to any one vehicle, and two vehicles of the same version have one
-- declaration between them.
--
-- An ASSIGNMENT is what ONE vehicle was given for one of those sets. It is
-- keyed by `(vehicle_id, set_id)` — the current assignment, one row — and it
-- carries the `(model, version)` it was validated against, because a vehicle
-- that has been reflashed has assignments from two declarations and a row that
-- did not say which one it was checked against could not be re-checked.
--
-- `revision` counts writes of that pair from 1, and `content_hash` is the
-- sha256 of the canonical blob those five columns render to — see `blob.rs`,
-- which is where the bytes are defined. The hash is over the blob and NOT over
-- `values_json`: what a delivery path content-addresses is the document, and
-- the document names its set, its version and its revision.

CREATE TABLE IF NOT EXISTS schemas (
    model   TEXT  NOT NULL,
    version TEXT  NOT NULL,
    sets    JSONB NOT NULL,
    PRIMARY KEY (model, version)
);

CREATE TABLE IF NOT EXISTS assignments (
    vehicle_id   TEXT        NOT NULL,
    set_id       TEXT        NOT NULL,
    model        TEXT        NOT NULL,
    version      TEXT        NOT NULL,
    revision     BIGINT      NOT NULL,
    content_hash TEXT        NOT NULL,
    values_json  JSONB       NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (vehicle_id, set_id)
);
