//! Typed HTTP clients for the sumo-provision towers.
//!
//! Reusable programmatic access for anything that drives the towers — the CLI,
//! the orchestrator, an onboard reconciler. [`TowerClient`] is the shared base
//! (health/version, against either tower); [`SoftwareClient`] (Tower 2) and
//! [`IdentityClient`] (Tower 1) add the per-tower operations, same pattern.

use serde::{Deserialize, Serialize};
use wire::{ArtifactRef, ContentHash, Device, EnrollResponse, RegisterDevice, Tree};

/// `POST /admin/devices/{id}/keystore` body.
#[derive(Serialize)]
struct MintKeystoreReq<'a> {
    sw_authority_pubkey: &'a str,
}

/// `POST /admin/envelope` request body (mirrors Tower 2's `NewEnvelope`).
#[derive(Serialize)]
struct EnvelopeReq<'a> {
    device_pubkey: &'a str,
    device_id: &'a str,
    component: &'a str,
    parts: Vec<EnvelopePartReq>,
    seq: u64,
}

#[derive(Serialize)]
struct EnvelopePartReq {
    id: String,
    content: ContentHash,
}

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

    /// `GET /channel-targets/tree?channel=` — resolve a channel to its desired
    /// [`wire::Tree`]; `None` if unknown. Resolves the channel's single target
    /// (the common case); pass `target_type`/`profile` to `channel_target_tree`
    /// when a channel serves several.
    pub async fn channel_tree(&self, name: &str) -> Result<Option<Tree>, ClientError> {
        self.channel_target_tree(name, None, None).await
    }

    /// `GET /channel-targets/tree?channel=&target_type=&profile=` — resolve a
    /// (channel, target_type, profile) tuple to its desired [`wire::Tree`];
    /// `None` if unknown. `target_type`/`profile` omitted resolves a channel
    /// with a single target.
    pub async fn channel_target_tree(
        &self,
        channel: &str,
        target_type: Option<&str>,
        profile: Option<&str>,
    ) -> Result<Option<Tree>, ClientError> {
        let mut q: Vec<(&str, &str)> = vec![("channel", channel)];
        if let Some(t) = target_type {
            q.push(("target_type", t));
        }
        if let Some(p) = profile {
            q.push(("profile", p));
        }
        let resp = self
            .tower
            .http
            .get(format!("{}/channel-targets/tree", self.tower.base))
            .query(&q)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /// `POST /admin/envelope` — build a signed SUIT envelope for `component`'s
    /// `parts` (id + inner-hash), with each part's CEK re-wrapped to the device.
    /// Returns the manifest bytes.
    pub async fn build_envelope(
        &self,
        device_pubkey: &str,
        device_id: &str,
        component: &str,
        parts: &[(String, ContentHash)],
        seq: u64,
    ) -> Result<Vec<u8>, ClientError> {
        let body = EnvelopeReq {
            device_pubkey,
            device_id,
            component,
            parts: parts
                .iter()
                .map(|(id, content)| EnvelopePartReq {
                    id: id.clone(),
                    content: *content,
                })
                .collect(),
            seq,
        };
        Ok(self
            .tower
            .http
            .post(format!("{}/admin/envelope", self.tower.base))
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec())
    }

    /// `GET /admin/signer/pubkey` — the sw-authority public key (COSE_Key CBOR).
    /// This is the SUIT trust anchor: an envelope built by [`build_envelope`] is
    /// signed by this key, so a verifier (e.g. the flash engine classifying the
    /// manifest) validates against these bytes.
    pub async fn signer_pubkey(&self) -> Result<Vec<u8>, ClientError> {
        Ok(self
            .tower
            .http
            .get(format!("{}/admin/signer/pubkey", self.tower.base))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec())
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

    /// `POST /admin/devices` — register (or update) a device in the roster.
    pub async fn register_device(&self, req: &RegisterDevice) -> Result<Device, ClientError> {
        Ok(self
            .tower
            .http
            .post(format!("{}/admin/devices", self.tower.base))
            .json(req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// `GET /devices` — the device roster.
    pub async fn list_devices(&self) -> Result<Vec<Device>, ClientError> {
        Ok(self
            .tower
            .http
            .get(format!("{}/devices", self.tower.base))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// `GET /devices/{id}` — one device; `None` if not registered.
    pub async fn get_device(&self, id: &str) -> Result<Option<Device>, ClientError> {
        let resp = self
            .tower
            .http
            .get(format!("{}/devices/{}", self.tower.base, id))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /// `POST /admin/devices/{id}/enroll?key_id=<slot>` — submit the slot's CSR
    /// (DER PKCS#10). For `device-decrypt` Tower 1 records the pubkey (no cert);
    /// for a cert-bearing slot (`tls-identity`, …) it issues + stores a leaf and
    /// returns it.
    pub async fn enroll(
        &self,
        id: &str,
        key_id: &str,
        csr_der: &[u8],
    ) -> Result<EnrollResponse, ClientError> {
        Ok(self
            .tower
            .http
            .post(format!(
                "{}/admin/devices/{}/enroll?key_id={}",
                self.tower.base, id, key_id
            ))
            .body(csr_der.to_vec())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// `POST /admin/devices/{id}/keystore` — mint the device's HSM trust-anchor
    /// keystore SUIT. `sw_authority_pubkey` is Tower 2's signer pubkey (hex of
    /// the COSE_Key CBOR). Returns the signed+encrypted SUIT bytes.
    pub async fn mint_keystore(
        &self,
        id: &str,
        sw_authority_pubkey: &str,
    ) -> Result<Vec<u8>, ClientError> {
        Ok(self
            .tower
            .http
            .post(format!("{}/admin/devices/{}/keystore", self.tower.base, id))
            .json(&MintKeystoreReq {
                sw_authority_pubkey,
            })
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec())
    }

    /// `GET /admin/ca/cert` — the identity-root CA certificate (PEM). This is the
    /// fleet trust anchor a node pins to verify a peer's `tls-identity` leaf in
    /// cross-node mTLS — a DISTINCT CA from `key-authority`/`sw-authority`. Ship
    /// it in the policy partition's `roots/` as `device-identity-root.pem`.
    pub async fn ca_cert(&self) -> Result<String, ClientError> {
        Ok(self
            .tower
            .http
            .get(format!("{}/admin/ca/cert", self.tower.base))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?)
    }
}

/// A client for `sovd-token-helper` — mints short-lived SOVD bearer JWTs that
/// SOVDd validates (the client→SOVD access token, distinct from UDS unlock).
#[derive(Clone)]
pub struct MinterClient {
    base: String,
    http: reqwest::Client,
    operator_token: String,
}

#[derive(serde::Serialize)]
struct MintReq<'a> {
    device_id: &'a str,
    components: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_secs: Option<u64>,
}

/// A minted SOVD token.
#[derive(Debug, Deserialize)]
pub struct MintedToken {
    pub token: String,
    pub expires_at: String,
}

impl MinterClient {
    /// Build a minter client for `base_url`, authenticating to `/mint` with the
    /// operator bearer token.
    pub fn new(base_url: impl Into<String>, operator_token: impl Into<String>) -> Self {
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            operator_token: operator_token.into(),
        }
    }

    /// `POST /mint` — mint a token bound to `device_id` (the `aud`, the replay
    /// guard) granting the given component scopes (`["*"]` for all). `boot_id`, when
    /// supplied, binds it to the device's current boot (§7.1 freshness).
    pub async fn mint(
        &self,
        device_id: &str,
        components: &[String],
        boot_id: Option<&str>,
        ttl_secs: Option<u64>,
    ) -> Result<MintedToken, ClientError> {
        Ok(self
            .http
            .post(format!("{}/mint", self.base))
            .bearer_auth(&self.operator_token)
            .json(&MintReq {
                device_id,
                components,
                boot_id,
                ttl_secs,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
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
