//! Storage backends for Tower 2.
//!
//! Two seams, each with the impl we use today and room for the impl we'll add:
//!   - [`BlobStore`]    : content-addressed ciphertext. Filesystem now, S3 later.
//!   - [`ArtifactIndex`]: the per-artifact key index (CEK + hashes). Postgres
//!     now ([`PgIndex`]); [`MemIndex`] backs the tests so they need no database.

use std::io;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use sqlx::Row;
use wire::ContentHash;

use crate::crypto::{CEK_LEN, NONCE_LEN};

/// One artifact's index entry: how to find and decrypt its blob.
#[derive(Clone, Debug)]
pub struct ArtifactEntry {
    pub inner: ContentHash,
    pub outer: ContentHash,
    pub cek: [u8; CEK_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub size: u64,
}

// --- blob store ------------------------------------------------------------

/// Content-addressed store for ciphertext blobs, keyed by the outer hash.
#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn put(&self, outer: &ContentHash, bytes: &[u8]) -> io::Result<()>;
    async fn get(&self, outer: &ContentHash) -> io::Result<Option<Vec<u8>>>;
}

/// Filesystem blob store: one file per blob, named by its hex outer hash.
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    fn path(&self, outer: &ContentHash) -> PathBuf {
        self.root.join(hex::encode(outer.as_bytes()))
    }
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn put(&self, outer: &ContentHash, bytes: &[u8]) -> io::Result<()> {
        tokio::fs::create_dir_all(&self.root).await?;
        let path = self.path(outer);
        // Write to a temp file then rename, so a blob is never half-written.
        let tmp = path.with_extension("tmp");
        tokio::fs::write(&tmp, bytes).await?;
        tokio::fs::rename(&tmp, &path).await?;
        Ok(())
    }

    async fn get(&self, outer: &ContentHash) -> io::Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.path(outer)).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// --- artifact index --------------------------------------------------------

/// The per-artifact key index, keyed by the inner (plaintext) hash.
#[async_trait]
pub trait ArtifactIndex: Send + Sync {
    /// Look up an artifact by its inner hash.
    async fn get(&self, inner: &ContentHash) -> anyhow::Result<Option<ArtifactEntry>>;
    /// Record an artifact. Idempotent: re-putting the same inner hash is a no-op.
    async fn put(&self, entry: &ArtifactEntry) -> anyhow::Result<()>;
}

/// Postgres-backed index (the production backend).
pub struct PgIndex {
    pool: sqlx::PgPool,
}

impl PgIndex {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ArtifactIndex for PgIndex {
    async fn get(&self, inner: &ContentHash) -> anyhow::Result<Option<ArtifactEntry>> {
        let row =
            sqlx::query("SELECT outer_hash, cek, nonce, size FROM artifacts WHERE inner_hash = $1")
                .bind(inner.to_prefixed())
                .fetch_optional(&self.pool)
                .await?;

        let Some(row) = row else { return Ok(None) };
        let outer: String = row.get("outer_hash");
        let cek: Vec<u8> = row.get("cek");
        let nonce: Vec<u8> = row.get("nonce");
        let size: i64 = row.get("size");
        Ok(Some(ArtifactEntry {
            inner: *inner,
            outer: outer.parse()?,
            cek: cek.as_slice().try_into()?,
            nonce: nonce.as_slice().try_into()?,
            size: size as u64,
        }))
    }

    async fn put(&self, entry: &ArtifactEntry) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO artifacts (inner_hash, outer_hash, cek, nonce, size) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (inner_hash) DO NOTHING",
        )
        .bind(entry.inner.to_prefixed())
        .bind(entry.outer.to_prefixed())
        .bind(entry.cek.as_slice())
        .bind(entry.nonce.as_slice())
        .bind(entry.size as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// In-memory index for tests (no database required).
#[cfg(test)]
#[derive(Default)]
pub struct MemIndex {
    entries: std::sync::Mutex<std::collections::HashMap<ContentHash, ArtifactEntry>>,
}

#[cfg(test)]
#[async_trait]
impl ArtifactIndex for MemIndex {
    async fn get(&self, inner: &ContentHash) -> anyhow::Result<Option<ArtifactEntry>> {
        Ok(self.entries.lock().unwrap().get(inner).cloned())
    }

    async fn put(&self, entry: &ArtifactEntry) -> anyhow::Result<()> {
        self.entries
            .lock()
            .unwrap()
            .entry(entry.inner)
            .or_insert_with(|| entry.clone());
        Ok(())
    }
}
