-- Device leaf certs become per-(device, key_id): tls-identity gets its own leaf,
-- distinct from the device-decrypt registration (which is pubkey + PoP, no cert).
-- The single cert_* columns on `devices` are retired — nothing reads them (the
-- EnrollResponse is built from the freshly-issued cert, and the keystore mint now
-- sources the tls-identity leaf from device_certs).

DROP INDEX IF EXISTS devices_cert_serial_uq;

ALTER TABLE devices
    DROP COLUMN IF EXISTS cert_der,
    DROP COLUMN IF EXISTS cert_serial,
    DROP COLUMN IF EXISTS cert_not_after,
    DROP COLUMN IF EXISTS cert_fingerprint,
    DROP COLUMN IF EXISTS enrolled_at;

CREATE TABLE IF NOT EXISTS device_certs (
    device_id        TEXT        NOT NULL REFERENCES devices(id),
    key_id           TEXT        NOT NULL,
    cert_der         BYTEA       NOT NULL,
    cert_serial      TEXT,
    cert_not_after   TEXT,
    cert_fingerprint TEXT,
    enrolled_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, key_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS device_certs_serial_uq
    ON device_certs (cert_serial) WHERE cert_serial IS NOT NULL;
