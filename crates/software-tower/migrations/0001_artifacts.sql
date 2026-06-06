-- Tower 2 artifact index: one row per published artifact.
--
-- Keyed by the inner (plaintext) hash — the device-independent software
-- identity. Holds the content-encryption key + nonce so the ciphertext blob
-- (content-addressed by outer_hash in the blob store) can be decrypted.
CREATE TABLE IF NOT EXISTS artifacts (
    inner_hash TEXT PRIMARY KEY,
    outer_hash TEXT        NOT NULL,
    cek        BYTEA       NOT NULL,
    nonce      BYTEA       NOT NULL,
    size       BIGINT      NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
