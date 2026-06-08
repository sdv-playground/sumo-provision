//! The device identity roster: register a device and read it back.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use sqlx::{PgPool, Row};
use wire::{Device, EnrollResponse, RegisterDevice};

use crate::ca::Ca;

/// Shared state: the roster database pool + the device CA.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub ca: Arc<Ca>,
}

/// The roster columns projected into a [`wire::Device`].
const DEVICE_COLS: &str =
    "id, model, status, pubkey, cert_serial, cert_not_after, cert_fingerprint";

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

/// `POST /admin/devices/{id}/enroll` — body is the device CSR (raw DER PKCS#10;
/// PEM accepted). Verifies proof-of-possession, issues a `clientAuth` device
/// certificate (the CSR response), stores it, and returns it. The device must be
/// registered first (`404` otherwise).
pub async fn enroll_device(
    State(s): State<AppState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<EnrollResponse>, AppError> {
    let issued =
        s.ca.issue_leaf(&id, &body)
            .map_err(|e| AppError::BadRequest(format!("CSR rejected: {e}")))?;
    // Store the device pubkey as hex(COSE_Key) — the form Tower 2's build_envelope
    // and the keystore mint both consume (not the raw SEC1 point from the CSR).
    let sec1: [u8; 65] = hex::decode(&issued.pubkey_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| AppError::BadRequest("CSR key is not a 65-byte P-256 point".into()))?;
    let pubkey_cose_hex = hex::encode(crate::keystore::sec1_to_cose(&sec1));
    let res = sqlx::query(
        "UPDATE devices SET status='enrolled', pubkey=$2, cert_der=$3, \
           cert_serial=$4, cert_not_after=$5, cert_fingerprint=$6, enrolled_at=now() \
         WHERE id=$1",
    )
    .bind(&id)
    .bind(&pubkey_cose_hex)
    .bind(&issued.der)
    .bind(&issued.serial_hex)
    .bind(&issued.not_after)
    .bind(&issued.fingerprint)
    .execute(&s.pool)
    .await
    .map_err(db)?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound); // register the device before enrolling it
    }
    Ok(Json(EnrollResponse {
        id,
        certificate_pem: issued.pem,
        serial: issued.serial_hex,
        not_after: issued.not_after,
        fingerprint: issued.fingerprint,
    }))
}

/// `GET /admin/ca/cert` — the CA root certificate (PEM). The trust anchor a
/// verifier pins to validate the device certs this CA issues (e.g. an MQTT
/// broker's client-cert trust store).
pub async fn ca_cert(State(s): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let pem = s.ca.root_cert_pem().map_err(AppError::Internal)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/x-pem-file")],
        pem,
    ))
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
        cert_serial: r.get("cert_serial"),
        cert_not_after: r.get("cert_not_after"),
        cert_fingerprint: r.get("cert_fingerprint"),
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
