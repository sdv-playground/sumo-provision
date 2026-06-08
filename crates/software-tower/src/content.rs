//! The content service: encrypt-once publish and content-addressed fetch, plus
//! the HTTP handlers that wrap them. Both directions stream — a bank image
//! (hundreds of MB) is never held in memory in full.

use std::io::Write;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::StreamExt;
use wire::{ArtifactRef, ContentHash};

use crate::crypto::StreamEncryptor;
use crate::store::{ArtifactEntry, ArtifactIndex, BlobStore};

/// zstd compression level for published artifacts — matches `sumo-offboard`'s
/// producer default (`compress_firmware(_, 3, _)`), a good size/speed balance.
/// No window-log override: the device-side decompressor (a full host, not an
/// MCU) enforces no window cap, so zstd's default suffices.
const ZSTD_LEVEL: i32 = 3;

/// Shared state: the blob store, the artifact index, and the release/channel
/// database pool (`None` in unit tests, which exercise the content store with an
/// in-memory index).
#[derive(Clone)]
pub struct AppState {
    pub blobs: Arc<dyn BlobStore>,
    pub index: Arc<dyn ArtifactIndex>,
    pub pool: Option<sqlx::PgPool>,
    pub signer: Arc<crate::signer::Signer>,
}

impl AppState {
    /// The release/channel database pool, or an error if none is configured.
    pub fn pool(&self) -> Result<&sqlx::PgPool, AppError> {
        self.pool
            .as_ref()
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("no database configured")))
    }

    /// Compress-once, encrypt-once, store, and index a streamed artifact. The
    /// request body is read chunk by chunk; each chunk is hashed (plaintext →
    /// inner), zstd-compressed, encrypted, hashed again (ciphertext → outer), and
    /// written to the blob sink — so the artifact never sits in memory in full.
    /// The device sniffs the zstd frame magic in the first decrypted bytes and
    /// decompresses (no manifest flag), so the stored blob just has to *be*
    /// compressed; `inner`/`size` stay over the **plaintext** — the SUIT digest +
    /// size the device verifies after decompression. Idempotent on the plaintext
    /// (inner) hash: if the same bytes were already published, the freshly-built
    /// temp is dropped and the existing reference returned.
    pub async fn publish_stream(&self, body: Body) -> Result<ArtifactRef, AppError> {
        let mut enc = StreamEncryptor::new()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("encryptor init failed: {e}")))?;
        let cek = enc.cek;
        let nonce = enc.nonce;
        // Stream the plaintext through zstd before the encryptor. We drain the
        // encoder's output buffer each chunk so a 600 MB image never buffers in
        // full — the encoder holds at most its working window plus one block.
        let mut zenc = zstd::Encoder::new(Vec::new(), ZSTD_LEVEL)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("zstd init failed: {e}")))?;

        let mut inner_h = ContentHash::hasher();
        let mut outer_h = ContentHash::hasher();
        let mut sink = self.blobs.begin().await?;
        let mut size: u64 = 0;
        let mut ct = Vec::new();

        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| AppError::BadRequest(format!("upload aborted: {e}")))?;
            inner_h.update(&chunk);
            size += chunk.len() as u64;
            // Compress the plaintext, then encrypt only what zstd emitted this
            // round. Small chunks often buffer inside zstd and emit nothing until a
            // block completes — `compressed` is then empty and we skip the encrypt.
            zenc.write_all(&chunk)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("compress failed: {e}")))?;
            let compressed = std::mem::take(zenc.get_mut());
            if !compressed.is_empty() {
                enc.update(&compressed, &mut ct)
                    .map_err(|e| AppError::Internal(anyhow::anyhow!("encrypt failed: {e}")))?;
                outer_h.update(&ct);
                sink.write_all(&ct).await?;
            }
        }
        // Flush the zstd frame footer (and any buffered block), encrypt it, then
        // append the trailing GCM tag.
        let tail = zenc
            .finish()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("compress finalize failed: {e}")))?;
        if !tail.is_empty() {
            enc.update(&tail, &mut ct)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("encrypt failed: {e}")))?;
            outer_h.update(&ct);
            sink.write_all(&ct).await?;
        }
        let tag = enc
            .finish()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("encrypt finalize failed: {e}")))?;
        outer_h.update(&tag);
        sink.write_all(&tag).await?;

        let inner = inner_h.finalize();
        let outer = outer_h.finalize();

        // Idempotent on the plaintext hash: drop the temp (on `sink` drop) and
        // return the reference we already have.
        if let Some(existing) = self.index.get(&inner).await? {
            return Ok(ArtifactRef {
                inner: existing.inner,
                outer: existing.outer,
                size: existing.size,
            });
        }

        sink.commit(&outer).await?;
        let entry = ArtifactEntry {
            inner,
            outer,
            cek,
            nonce,
            size,
        };
        self.index.put(&entry).await?;

        Ok(ArtifactRef { inner, outer, size })
    }

    /// Publish a fully-buffered plaintext through the streaming path. For
    /// in-process callers and tests.
    #[cfg(test)]
    pub async fn publish_bytes(&self, plaintext: &[u8]) -> Result<ArtifactRef, AppError> {
        self.publish_stream(Body::from(plaintext.to_vec())).await
    }
}

// --- handlers --------------------------------------------------------------

/// `POST /admin/artifacts` — publish a raw plaintext artifact, streamed. Takes
/// the whole request so the body is consumed as a stream rather than buffered.
pub async fn publish(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<ArtifactRef>, AppError> {
    Ok(Json(state.publish_stream(request.into_body()).await?))
}

/// `GET /blobs/{outer}` — stream a ciphertext blob by its outer hash.
pub async fn get_blob(
    State(state): State<AppState>,
    Path(outer): Path<String>,
) -> Result<Response, AppError> {
    let outer: ContentHash = outer.parse().map_err(|_| AppError::BadHash)?;
    match state.blobs.open(&outer).await? {
        Some((size, reader)) => {
            let body = Body::from_stream(tokio_util::io::ReaderStream::new(reader));
            Ok((
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_LENGTH, size.to_string()),
                    (
                        header::CACHE_CONTROL,
                        "public, immutable, max-age=31536000".to_string(),
                    ),
                ],
                body,
            )
                .into_response())
        }
        None => Err(AppError::NotFound),
    }
}

// --- error -----------------------------------------------------------------

/// Errors surfaced by the content API.
#[derive(Debug)]
pub enum AppError {
    BadHash,
    BadRequest(String),
    NotFound,
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e)
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Internal(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::BadHash => (StatusCode::BAD_REQUEST, "invalid content hash".to_string()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            AppError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, msg).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::store::{BlobStore, FsBlobStore, MemIndex};

    /// Read a whole blob back through the streaming `open` API (test convenience).
    async fn read_blob(blobs: &dyn BlobStore, outer: &ContentHash) -> Option<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let (_size, mut reader) = blobs.open(outer).await.unwrap()?;
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        Some(buf)
    }

    fn state_with_tempdir() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState {
            blobs: Arc::new(FsBlobStore::new(dir.path())),
            index: Arc::new(MemIndex::default()),
            pool: None,
            signer: Arc::new(crate::signer::Signer::generate().unwrap()),
        };
        (state, dir)
    }

    #[tokio::test]
    async fn publish_fetch_decrypt_roundtrip() {
        let (state, _dir) = state_with_tempdir();
        let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(10);

        let aref = state.publish_bytes(&plaintext).await.unwrap();
        assert_eq!(aref.inner, ContentHash::of(&plaintext));
        assert_eq!(aref.size, plaintext.len() as u64);

        // the blob is the compressed ciphertext, content-addressed by the outer hash
        let cipher = read_blob(&*state.blobs, &aref.outer).await.unwrap();
        assert_eq!(ContentHash::of(&cipher), aref.outer);
        assert_ne!(cipher, plaintext);
        // compressed before encryption: the repetitive plaintext stores smaller
        // than its own length (pre-fix the blob was plaintext-sized + 16).
        assert!(
            cipher.len() < plaintext.len(),
            "blob ({} B) should compress below the {} B plaintext",
            cipher.len(),
            plaintext.len()
        );

        // it decrypts (indexed CEK) to the zstd frame, which decompresses to the original
        let entry = state.index.get(&aref.inner).await.unwrap().unwrap();
        let frame = crypto::decrypt(&entry.cek, &entry.nonce, &cipher).unwrap();
        let dec = zstd::decode_all(frame.as_slice()).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[tokio::test]
    async fn publish_is_idempotent() {
        let (state, _dir) = state_with_tempdir();
        let pt = b"same bytes twice";
        let a = state.publish_bytes(pt).await.unwrap();
        let b = state.publish_bytes(pt).await.unwrap();
        assert_eq!(a.inner, b.inner);
        assert_eq!(a.outer, b.outer); // existing ref returned; temp re-encrypt dropped
    }

    #[tokio::test]
    async fn missing_blob_is_none() {
        let (state, _dir) = state_with_tempdir();
        let absent = ContentHash::of(b"never stored");
        assert!(read_blob(&*state.blobs, &absent).await.is_none());
    }

    /// End-to-end through the real HTTP router: a body far larger than the old
    /// 2 MB buffered-extractor cap streams in (no body-limit rejection, no
    /// BrokenPipe), and streams back out content-addressed. This is the path the
    /// `seed.sh` publish exercises against the live tower.
    #[tokio::test]
    async fn http_publish_streams_large_body_and_fetches_back() {
        use axum::http::{Request, StatusCode};
        use axum::routing::{get, post};
        use axum::Router;
        use tower::ServiceExt;

        let (state, _dir) = state_with_tempdir();
        let app = Router::new()
            .route("/admin/artifacts", post(publish))
            .route("/blobs/{outer}", get(get_blob))
            .with_state(state);

        let plaintext = vec![0xABu8; 20 * 1024 * 1024]; // 20 MB
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/artifacts")
                    .body(Body::from(plaintext.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let aref: ArtifactRef = serde_json::from_slice(&body).unwrap();
        assert_eq!(aref.inner, ContentHash::of(&plaintext));
        assert_eq!(aref.size, plaintext.len() as u64);

        // Fetch the ciphertext back through the streaming GET and confirm it
        // content-addresses to the outer hash.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/blobs/{}", aref.outer.to_prefixed()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cipher = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(ContentHash::of(&cipher), aref.outer);
        // 20 MB of one repeated byte compresses to a tiny zstd frame — proof the
        // publish path compresses before encrypting (pre-fix the blob was
        // plaintext-sized: cipher.len() == aref.size + 16).
        assert!(
            (cipher.len() as u64) < aref.size / 100,
            "expected a compressed blob far below the {} B plaintext, got {} B",
            aref.size,
            cipher.len()
        );
    }
}
