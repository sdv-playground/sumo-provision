-- Device certificates (Tower 1 CA): the clientAuth leaf issued from the device
-- CSR ("the CSR response"), reusable later as the device's mTLS client identity.
-- not_after is stored as TEXT (RFC3339) — the workspace sqlx has no date feature;
-- enrolled_at is written only via SQL now().
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS cert_der         BYTEA,
    ADD COLUMN IF NOT EXISTS cert_serial      TEXT,
    ADD COLUMN IF NOT EXISTS cert_not_after   TEXT,
    ADD COLUMN IF NOT EXISTS cert_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS enrolled_at      TIMESTAMPTZ;

-- A serial is unique per issued cert; the partial index makes a collision a clean
-- DB error rather than a silent overwrite.
CREATE UNIQUE INDEX IF NOT EXISTS devices_cert_serial_uq
    ON devices (cert_serial) WHERE cert_serial IS NOT NULL;
