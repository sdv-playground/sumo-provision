-- Release & channel storage.
--
-- L2 = component_releases: one entity's versioned parts (e.g. "vm1" "1.1.0").
-- L1 = campaign_releases: a tagged combination of component releases.
-- channels: a mutable pointer (e.g. "bleeding") to a campaign release.
-- The desired wire::Tree for a channel is resolved by joining these.

CREATE TABLE IF NOT EXISTS component_releases (
    id          BIGSERIAL   PRIMARY KEY,
    entity_path TEXT        NOT NULL,
    entity_kind TEXT        NOT NULL,
    version     TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (entity_path, version)
);

CREATE TABLE IF NOT EXISTS component_release_parts (
    release_id   BIGINT NOT NULL REFERENCES component_releases(id) ON DELETE CASCADE,
    part_id      TEXT   NOT NULL,
    part_kind    TEXT   NOT NULL,
    content_hash TEXT   NOT NULL,
    PRIMARY KEY (release_id, part_id)
);

CREATE TABLE IF NOT EXISTS campaign_releases (
    id         BIGSERIAL   PRIMARY KEY,
    tag        TEXT        NOT NULL,
    version    TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tag, version)
);

CREATE TABLE IF NOT EXISTS campaign_release_members (
    campaign_id          BIGINT NOT NULL REFERENCES campaign_releases(id) ON DELETE CASCADE,
    component_release_id BIGINT NOT NULL REFERENCES component_releases(id),
    PRIMARY KEY (campaign_id, component_release_id)
);

CREATE TABLE IF NOT EXISTS channels (
    name                TEXT        PRIMARY KEY,
    campaign_release_id BIGINT      REFERENCES campaign_releases(id),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
