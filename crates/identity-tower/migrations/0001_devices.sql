-- Device identity roster (Tower 1).
--
-- Registration records a device's identity; keystore minting (pubkey -> signed
-- key material) lands with the enrollment flow.

CREATE TABLE IF NOT EXISTS devices (
    id         TEXT        PRIMARY KEY,
    model      TEXT,
    status     TEXT        NOT NULL DEFAULT 'registered',
    pubkey     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
