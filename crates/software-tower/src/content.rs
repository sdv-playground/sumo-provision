//! The content service: encrypt-once publish and content-addressed fetch, plus
//! the HTTP handlers that wrap them.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use wire::{ArtifactRef, ContentHash};

use crate::crypto;
use crate::store::{ArtifactEntry, ArtifactIndex, BlobStore};

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

    /// Encrypt `plaintext` once, store the ciphertext, and index it. Idempotent
    /// on the plaintext (inner) hash: republishing the same bytes returns the
    /// existing reference without re-encrypting.
    pub async fn publish(&self, plaintext: &[u8]) -> anyhow::Result<ArtifactRef> {
        let inner = ContentHash::of(plaintext);
        if let Some(existing) = self.index.get(&inner).await? {
            return Ok(ArtifactRef {
                inner: existing.inner,
                outer: existing.outer,
                size: existing.size,
            });
        }

        let enc = crypto::encrypt_once(plaintext)
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
        let outer = ContentHash::of(&enc.ciphertext);
        self.blobs.put(&outer, &enc.ciphertext).await?;

        let entry = ArtifactEntry {
            inner,
            outer,
            cek: enc.cek,
            nonce: enc.nonce,
            size: plaintext.len() as u64,
        };
        self.index.put(&entry).await?;

        Ok(ArtifactRef {
            inner,
            outer,
            size: entry.size,
        })
    }
}

// --- handlers --------------------------------------------------------------

/// `POST /admin/artifacts` — publish raw plaintext bytes.
pub async fn publish(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<ArtifactRef>, AppError> {
    Ok(Json(state.publish(&body).await?))
}

/// `GET /blobs/{outer}` — fetch a ciphertext blob by its outer hash.
pub async fn get_blob(
    State(state): State<AppState>,
    Path(outer): Path<String>,
) -> Result<Response, AppError> {
    let outer: ContentHash = outer.parse().map_err(|_| AppError::BadHash)?;
    match state.blobs.get(&outer).await? {
        Some(bytes) => Ok((
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CACHE_CONTROL, "public, immutable, max-age=31536000"),
            ],
            bytes,
        )
            .into_response()),
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
    use crate::store::{FsBlobStore, MemIndex};

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

        let aref = state.publish(&plaintext).await.unwrap();
        assert_eq!(aref.inner, ContentHash::of(&plaintext));
        assert_eq!(aref.size, plaintext.len() as u64);

        // the blob is the ciphertext, content-addressed by the outer hash
        let cipher = state.blobs.get(&aref.outer).await.unwrap().unwrap();
        assert_eq!(ContentHash::of(&cipher), aref.outer);
        assert_ne!(cipher, plaintext);

        // and it decrypts back to the original using the indexed CEK
        let entry = state.index.get(&aref.inner).await.unwrap().unwrap();
        let dec = crypto::decrypt(&entry.cek, &entry.nonce, &cipher).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[tokio::test]
    async fn publish_is_idempotent() {
        let (state, _dir) = state_with_tempdir();
        let pt = b"same bytes twice";
        let a = state.publish(pt).await.unwrap();
        let b = state.publish(pt).await.unwrap();
        assert_eq!(a.inner, b.inner);
        assert_eq!(a.outer, b.outer); // not re-encrypted to a different ciphertext
    }

    #[tokio::test]
    async fn missing_blob_is_none() {
        let (state, _dir) = state_with_tempdir();
        let absent = ContentHash::of(b"never stored");
        assert!(state.blobs.get(&absent).await.unwrap().is_none());
    }
}
