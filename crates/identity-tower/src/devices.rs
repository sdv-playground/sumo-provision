//! The device identity roster: register a device and read it back.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use sqlx::{PgPool, Row};
use wire::{Device, EnrollResponse, RegisterDevice, TrustBundle};

use crate::ca::{Ca, LeafUsage};

/// Shared state: the roster database pool + the device CA.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    /// Signs HSM key material (keystore envelopes); its public half is the
    /// `key-authority` anchor provisioned into each device.
    pub key_authority_ca: Arc<Ca>,
    /// Signs device TLS leaf certs — the identity root, a distinct CA whose root
    /// every node pins to verify a peer's leaf.
    pub identity_ca: Arc<Ca>,
    /// Signs delegated capability grants (the workshop reset minter's leaf) — the
    /// delegation root, a distinct CA again. Its root is provisioned into device
    /// keystores so the SOVD authorizer accepts a delegated token's `x5c` chain,
    /// keeping "who may grant a reset" off the node-identity trust domain.
    pub delegation_ca: Arc<Ca>,
}

/// The roster columns projected into a [`wire::Device`]. Leaf certs are
/// per-(device, key_id) in `device_certs`, not on the roster row.
const DEVICE_COLS: &str = "id, model, status, pubkey";

/// `POST /admin/devices` — register (or update) a device. Idempotent on `id`.
pub async fn register_device(
    State(s): State<AppState>,
    Json(req): Json<RegisterDevice>,
) -> Result<Json<Device>, AppError> {
    let row = sqlx::query(&format!(
        "INSERT INTO devices (id, model, pubkey) VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO UPDATE SET \
           model = COALESCE($2, devices.model), \
           pubkey = COALESCE($3, devices.pubkey) \
         RETURNING {DEVICE_COLS}"
    ))
    .bind(&req.id)
    .bind(&req.model)
    .bind(&req.pubkey)
    .fetch_one(&s.pool)
    .await
    .map_err(db)?;
    Ok(Json(device_from_row(&row)))
}

/// `?key_id=` selector for [`enroll_device`].
#[derive(Deserialize)]
pub struct EnrollParams {
    /// Which device key slot the CSR is for. Defaults to `device-decrypt` (the
    /// registration key) so existing callers keep working.
    #[serde(default = "default_enroll_key_id")]
    pub key_id: String,
}

fn default_enroll_key_id() -> String {
    "device-decrypt".to_string()
}

/// `POST /admin/devices/{id}/enroll?key_id=<slot>` — body is the slot's CSR (DER
/// PKCS#10; PEM accepted). Two shapes per slot:
///
/// - `device-decrypt` (default): a REGISTRATION, not a cert. Verify
///   proof-of-possession + record the decryption pubkey (the keystore-encryption
///   recipient). No certificate is issued for this slot.
/// - any cert-bearing slot (`tls-identity`, …): issue a leaf — `tls-identity`
///   gets the mTLS profile (clientAuth + serverAuth + SAN) — and store it
///   per-(device, key_id) in `device_certs`. The device must be registered
///   first (`404` otherwise).
pub async fn enroll_device(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<EnrollParams>,
    body: Bytes,
) -> Result<Json<EnrollResponse>, AppError> {
    let key_id = params.key_id;

    if key_id == "device-decrypt" {
        // Registration: PoP + record the decryption pubkey. No cert wanted.
        let pubkey_hex = s
            .identity_ca
            .verify_csr_pubkey(&body)
            .map_err(|e| AppError::BadRequest(format!("CSR rejected: {e}")))?;
        // Store as hex(COSE_Key) — the form Tower 2's build_envelope and the
        // keystore mint both consume (not the raw SEC1 point from the CSR).
        let sec1: [u8; 65] = hex::decode(&pubkey_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| AppError::BadRequest("CSR key is not a 65-byte P-256 point".into()))?;
        let pubkey_cose_hex = hex::encode(crate::keystore::sec1_to_cose(&sec1));
        let res = sqlx::query("UPDATE devices SET status='enrolled', pubkey=$2 WHERE id=$1")
            .bind(&id)
            .bind(&pubkey_cose_hex)
            .execute(&s.pool)
            .await
            .map_err(db)?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound); // register the device before enrolling it
        }
        return Ok(Json(EnrollResponse {
            id,
            key_id,
            certificate_pem: None,
            serial: None,
            not_after: None,
            fingerprint: None,
        }));
    }

    // A cert-bearing slot: issue the leaf with the right usage + store it.
    let usage = if key_id == "tls-identity" {
        LeafUsage::Mtls
    } else {
        LeafUsage::Client
    };
    let issued = s
        .identity_ca
        .issue_leaf(&id, &body, usage)
        .map_err(|e| AppError::BadRequest(format!("CSR rejected: {e}")))?;
    // The device must already be registered (its device-decrypt enrolled).
    let known = sqlx::query("SELECT 1 FROM devices WHERE id=$1")
        .bind(&id)
        .fetch_optional(&s.pool)
        .await
        .map_err(db)?;
    if known.is_none() {
        return Err(AppError::NotFound);
    }
    sqlx::query(
        "INSERT INTO device_certs \
           (device_id, key_id, cert_der, cert_serial, cert_not_after, cert_fingerprint) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (device_id, key_id) DO UPDATE SET \
           cert_der = $3, cert_serial = $4, cert_not_after = $5, \
           cert_fingerprint = $6, enrolled_at = now()",
    )
    .bind(&id)
    .bind(&key_id)
    .bind(&issued.der)
    .bind(&issued.serial_hex)
    .bind(&issued.not_after)
    .bind(&issued.fingerprint)
    .execute(&s.pool)
    .await
    .map_err(db)?;
    Ok(Json(EnrollResponse {
        id,
        key_id,
        certificate_pem: Some(issued.pem),
        serial: Some(issued.serial_hex),
        not_after: Some(issued.not_after),
        fingerprint: Some(issued.fingerprint),
    }))
}

/// `POST /admin/workshop/delegate-cert` request — which scopes to delegate and
/// (optionally) the leaf's CN.
#[derive(Deserialize)]
pub struct DelegateCertReq {
    /// Space-delimited capability scopes the minted delegate may grant, e.g.
    /// `"reset:execute"`. Ride in the leaf's delegated-rights extension.
    pub scopes: String,
    /// Subject CN for the delegate leaf. Defaults to `workshop-minter`.
    #[serde(default = "default_delegate_cn")]
    pub cn: String,
}

fn default_delegate_cn() -> String {
    "workshop-minter".to_string()
}

/// `POST /admin/workshop/delegate-cert` response — everything the caller needs to
/// stand up the delegate: its leaf cert + private key, plus the CA root to pin.
#[derive(serde::Serialize)]
pub struct DelegateCertResponse {
    /// The minted delegate leaf certificate (PEM). Present it leaf-first.
    pub cert_pem: String,
    /// The delegate's private key (PKCS#8 PEM). The minter signs tokens with this.
    pub key_pem: String,
    /// The **delegation root** (PEM) — the trust anchor a verifier pins; the
    /// delegate chains to it. Provisioned into devices via the HSM keystore.
    pub ca_root_pem: String,
}

/// `POST /admin/workshop/delegate-cert` — mint a workshop-delegate leaf granting
/// the requested `scopes` (e.g. `reset:execute`). Returns the leaf cert, its
/// private key, and the delegation root so the caller has the full leaf-first
/// chain plus the root to pin. Signed by the **delegation** CA — a distinct trust
/// domain from identity, so the authority to grant a reset never rides on the
/// node-identity root. The device pins this root from its HSM keystore.
pub async fn mint_delegate_cert(
    State(s): State<AppState>,
    Json(req): Json<DelegateCertReq>,
) -> Result<Json<DelegateCertResponse>, AppError> {
    let (cert_pem, key_pem) = s
        .delegation_ca
        .mint_delegate_leaf(&req.cn, &req.scopes)
        .map_err(AppError::Internal)?;
    let ca_root_pem = s
        .delegation_ca
        .root_cert_pem()
        .map_err(AppError::Internal)?;
    Ok(Json(DelegateCertResponse {
        cert_pem,
        key_pem,
        ca_root_pem,
    }))
}

/// `GET /admin/ca/cert` — the device **identity root** certificate (PEM). The
/// trust anchor a verifier pins to validate the device certs this tower issues
/// (a peer node's vHSM, an MQTT broker's client-cert trust store). Distinct from
/// the key-authority root, which is provisioned into the device keystore instead.
pub async fn ca_cert(State(s): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let pem = s.identity_ca.root_cert_pem().map_err(AppError::Internal)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/x-pem-file")],
        pem,
    ))
}

/// `GET /admin/ca/trust-bundle` — the tower's root **trust anchors** as named,
/// pinnable PEMs, so offboard tooling fetches-and-pins them once. Carries the two
/// anchors offboard parts need: `"identity"` (device-TLS — the root a node pins
/// to verify a peer's `tls-identity` leaf) and `"delegation"` (the
/// delegated-token / minter root the SOVD authorizer pins for a token's `x5c`
/// chain). A map, not fixed fields, so a third anchor is a one-line change here
/// with no wire break.
pub async fn trust_bundle(State(s): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let mut anchors = std::collections::BTreeMap::new();
    anchors.insert(
        "identity".to_string(),
        s.identity_ca.root_cert_pem().map_err(AppError::Internal)?,
    );
    anchors.insert(
        "delegation".to_string(),
        s.delegation_ca
            .root_cert_pem()
            .map_err(AppError::Internal)?,
    );
    Ok(Json(TrustBundle { anchors }))
}

/// `GET /devices` — the roster.
pub async fn list_devices(State(s): State<AppState>) -> Result<Json<Vec<Device>>, AppError> {
    let rows = sqlx::query(&format!("SELECT {DEVICE_COLS} FROM devices ORDER BY id"))
        .fetch_all(&s.pool)
        .await
        .map_err(db)?;
    Ok(Json(rows.iter().map(device_from_row).collect()))
}

/// `GET /devices/{id}` — one device, `404` if unknown.
pub async fn get_device(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Device>, AppError> {
    let row = sqlx::query(&format!("SELECT {DEVICE_COLS} FROM devices WHERE id = $1"))
        .bind(&id)
        .fetch_optional(&s.pool)
        .await
        .map_err(db)?;
    match row {
        Some(r) => Ok(Json(device_from_row(&r))),
        None => Err(AppError::NotFound),
    }
}

fn device_from_row(r: &sqlx::postgres::PgRow) -> Device {
    Device {
        id: r.get("id"),
        model: r.get("model"),
        status: r.get("status"),
        pubkey: r.get("pubkey"),
    }
}

// --- error -----------------------------------------------------------------

/// Errors surfaced by the roster API.
#[derive(Debug)]
pub enum AppError {
    NotFound,
    BadRequest(String),
    Internal(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()).into_response(),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m).into_response(),
            AppError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
                    .into_response()
            }
        }
    }
}

/// Map a database error into an `AppError`.
fn db(e: sqlx::Error) -> AppError {
    AppError::Internal(e.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::{Ca, DELEGATION_ROOT_DN, IDENTITY_ROOT_DN, KEY_AUTHORITY_ROOT_DN};
    use sqlx::postgres::PgPoolOptions;
    use x509_cert::der::DecodePem;
    use x509_cert::Certificate;

    /// An `AppState` with three distinct, freshly generated CA roots and a *lazy*
    /// pool — the trust-bundle handler never queries the DB, so the connection is
    /// never established and no live Postgres is needed.
    fn test_state() -> AppState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://sumo:dev-only@localhost:5432/sumo_ca_test")
            .expect("lazy pool parses");
        AppState {
            pool,
            key_authority_ca: Arc::new(Ca::generate(KEY_AUTHORITY_ROOT_DN).unwrap()),
            identity_ca: Arc::new(Ca::generate(IDENTITY_ROOT_DN).unwrap()),
            delegation_ca: Arc::new(Ca::generate(DELEGATION_ROOT_DN).unwrap()),
        }
    }

    #[tokio::test]
    async fn trust_bundle_returns_identity_and_delegation_pems() {
        let state = test_state();
        let identity_root = state.identity_ca.root_cert_pem().unwrap();
        let delegation_root = state.delegation_ca.root_cert_pem().unwrap();

        // Drive the real handler and decode its JSON wire body.
        let resp = trust_bundle(State(state)).await.expect("handler ok");
        let body = axum::body::to_bytes(resp.into_response().into_body(), usize::MAX)
            .await
            .unwrap();
        let bundle: TrustBundle = serde_json::from_slice(&body).unwrap();

        // Exactly the two anchors offboard parts need.
        assert_eq!(bundle.anchors.len(), 2);
        let identity = bundle.anchors.get("identity").expect("identity anchor");
        let delegation = bundle.anchors.get("delegation").expect("delegation anchor");

        // Each is a parseable PEM certificate...
        for pem in [identity, delegation] {
            assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
            assert!(pem.contains("-----END CERTIFICATE-----"));
            Certificate::from_pem(pem.as_bytes()).expect("anchor is a parseable X.509 PEM");
        }
        // ...the two anchors are distinct trust domains...
        assert_ne!(identity, delegation);
        // ...and they are exactly the tower's two roots.
        assert_eq!(identity, &identity_root);
        assert_eq!(delegation, &delegation_root);
    }
}
