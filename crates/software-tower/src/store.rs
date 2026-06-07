//! Storage backends for Tower 2.
//!
//! Two seams, each with the impl we use today and room for the impl we'll add:
//!   - [`BlobStore`]    : content-addressed ciphertext, streamed both ways.
//!     Filesystem now ([`FsBlobStore`]), S3 later.
//!   - [`ArtifactIndex`]: the per-artifact key index (CEK + hashes). Postgres
//!     now ([`PgIndex`]); [`MemIndex`] backs the tests so they need no database.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use sqlx::Row;
use tokio::io::{AsyncRead, AsyncWriteExt};
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

/// Content-addressed store for ciphertext blobs, keyed by the outer hash. Both
/// directions stream, so a bank image (hundreds of MB) never sits in memory in
/// full: [`begin`](BlobStore::begin) writes a new blob chunk by chunk, and
/// [`open`](BlobStore::open) reads one back the same way.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Open a sink for a new blob. Bytes are streamed to a temp location and
    /// published under their content address by [`BlobSink::commit`].
    async fn begin(&self) -> io::Result<Box<dyn BlobSink>>;

    /// Open an existing blob for streaming reads — `(size, reader)`, or `None`
    /// if absent.
    async fn open(
        &self,
        outer: &ContentHash,
    ) -> io::Result<Option<(u64, Box<dyn AsyncRead + Send + Unpin>)>>;
}

/// A write sink for a single blob being streamed into the store.
#[async_trait]
pub trait BlobSink: Send {
    /// Append the next chunk of ciphertext.
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;

    /// Publish the streamed bytes under content address `outer`. Idempotent: if a
    /// blob already exists there, the temp is dropped instead. Not calling
    /// `commit` (a dedup hit, or an error mid-stream) discards the temp on drop.
    async fn commit(&mut self, outer: &ContentHash) -> io::Result<()>;
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

/// Process-unique suffix for temp blob names (so concurrent publishes don't
/// collide on the staging file).
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn begin(&self) -> io::Result<Box<dyn BlobSink>> {
        tokio::fs::create_dir_all(&self.root).await?;
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self.root.join(format!(".tmp.{}.{seq}", std::process::id()));
        let file = tokio::fs::File::create(&tmp).await?;
        Ok(Box::new(FsBlobSink {
            root: self.root.clone(),
            tmp,
            file: Some(file),
            committed: false,
        }))
    }

    async fn open(
        &self,
        outer: &ContentHash,
    ) -> io::Result<Option<(u64, Box<dyn AsyncRead + Send + Unpin>)>> {
        match tokio::fs::File::open(self.path(outer)).await {
            Ok(file) => {
                let size = file.metadata().await?.len();
                Ok(Some((size, Box::new(file))))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Streaming sink for [`FsBlobStore`]: writes to a temp file, then atomically
/// renames it to its content address on commit. The temp is removed on drop if
/// it was never committed, so dedup hits and mid-stream errors leave no litter.
struct FsBlobSink {
    root: PathBuf,
    tmp: PathBuf,
    file: Option<tokio::fs::File>,
    committed: bool,
}

#[async_trait]
impl BlobSink for FsBlobSink {
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.as_mut().expect("sink open").write_all(buf).await
    }

    async fn commit(&mut self, outer: &ContentHash) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush().await?;
            file.sync_all().await?;
        }
        let dest = self.root.join(hex::encode(outer.as_bytes()));
        if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
            // Same ciphertext already present — drop our temp instead.
            tokio::fs::remove_file(&self.tmp).await.ok();
        } else {
            tokio::fs::rename(&self.tmp, &dest).await?;
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for FsBlobSink {
    fn drop(&mut self) {
        if !self.committed {
            // Discard the uncommitted temp (dedup hit, or an error mid-stream).
            let _ = std::fs::remove_file(&self.tmp);
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
