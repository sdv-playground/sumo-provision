//! Typed HTTP clients for the sumo-provision towers.
//!
//! Reusable programmatic access for anything that drives the towers — the CLI,
//! the orchestrator, an onboard reconciler. [`TowerClient`] is the shared base
//! (health/version, against either tower); [`SoftwareClient`] (Tower 2) and
//! [`IdentityClient`] (Tower 1) add the per-tower operations, same pattern.

use serde::Deserialize;
use wire::{ArtifactRef, ContentHash, Tree};

/// Error talking to a tower.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("http transport error: {0}")]
    Http(#[from] reqwest::Error),
}

/// A tower's `/version` response.
#[derive(Debug, Deserialize)]
pub struct Version {
    pub service: String,
    pub version: String,
}

/// Shared base client: the endpoints every tower exposes.
#[derive(Clone)]
pub struct TowerClient {
    base: String,
    http: reqwest::Client,
}

impl TowerClient {
    /// Build a client for the tower at `base_url` (e.g. `http://localhost:8081`).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// The tower's base URL (no trailing slash).
    pub fn base(&self) -> &str {
        &self.base
    }

    /// `GET /healthz` — true when the tower reports `ok`.
    pub async fn healthy(&self) -> Result<bool, ClientError> {
        let body = self
            .http
            .get(format!("{}/healthz", self.base))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        Ok(body.trim() == "ok")
    }

    /// `GET /version`.
    pub async fn version(&self) -> Result<Version, ClientError> {
        Ok(self
            .http
            .get(format!("{}/version", self.base))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

/// Tower 2 (software) client: content publish + blob fetch, plus the base ops.
#[derive(Clone)]
pub struct SoftwareClient {
    tower: TowerClient,
}

impl SoftwareClient {
    /// Build a Tower 2 client for `base_url` (e.g. `http://localhost:8081`).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            tower: TowerClient::new(base_url),
        }
    }

    /// The shared base client (health / version).
    pub fn tower(&self) -> &TowerClient {
        &self.tower
    }

    /// `POST /admin/artifacts` — publish plaintext bytes. The tower encrypts,
    /// stores, and indexes them, returning the artifact's content identity.
    pub async fn publish_artifact(&self, plaintext: &[u8]) -> Result<ArtifactRef, ClientError> {
        Ok(self
            .tower
            .http
            .post(format!("{}/admin/artifacts", self.tower.base))
            .body(plaintext.to_vec())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// `GET /blobs/{outer}` — fetch a ciphertext blob; `None` if the tower has
    /// no such blob.
    pub async fn get_blob(&self, outer: &ContentHash) -> Result<Option<Vec<u8>>, ClientError> {
        let resp = self
            .tower
            .http
            .get(format!("{}/blobs/{}", self.tower.base, outer.to_prefixed()))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.bytes().await?.to_vec()))
    }

    /// `GET /admin/artifacts/{inner}` — the stored artifact ref for this plaintext
    /// content, or `None` if Tower 2 doesn't have it. A build step uses this to
    /// upload only genuinely-new content.
    pub async fn artifact_exists(
        &self,
        inner: &ContentHash,
    ) -> Result<Option<ArtifactRef>, ClientError> {
        let resp = self
            .tower
            .http
            .get(format!(
                "{}/admin/artifacts/{}",
                self.tower.base,
                inner.to_prefixed()
            ))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /// `GET /channels/{name}/tree` — resolve a channel to its desired
    /// [`wire::Tree`]; `None` if the channel is unset or unknown.
    pub async fn channel_tree(&self, name: &str) -> Result<Option<Tree>, ClientError> {
        let resp = self
            .tower
            .http
            .get(format!("{}/channels/{}/tree", self.tower.base, name))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }
}

/// Tower 1 (identity) client: the base ops today. Enrollment and keystore
/// minting land with Tower 1's endpoints (roadmap step 5), same pattern as
/// [`SoftwareClient`].
#[derive(Clone)]
pub struct IdentityClient {
    tower: TowerClient,
}

impl IdentityClient {
    /// Build a Tower 1 client for `base_url` (e.g. `http://localhost:8080`).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            tower: TowerClient::new(base_url),
        }
    }

    /// The shared base client (health / version).
    pub fn tower(&self) -> &TowerClient {
        &self.tower
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_trims_trailing_slash() {
        assert_eq!(
            TowerClient::new("http://localhost:8081/").base(),
            "http://localhost:8081"
        );
    }
}
