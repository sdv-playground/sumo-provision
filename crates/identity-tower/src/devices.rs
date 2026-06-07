//! The device identity roster: register a device and read it back.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use sqlx::{PgPool, Row};
use wire::{Device, RegisterDevice};

/// Shared state: the roster database pool.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
}

/// `POST /admin/devices` — register (or update) a device. Idempotent on `id`.
pub async fn register_device(
    State(s): State<AppState>,
    Json(req): Json<RegisterDevice>,
) -> Result<Json<Device>, AppError> {
    let row = sqlx::query(
        "INSERT INTO devices (id, model, pubkey) VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO UPDATE SET \
           model = COALESCE($2, devices.model), \
           pubkey = COALESCE($3, devices.pubkey) \
         RETURNING id, model, status, pubkey",
    )
    .bind(&req.id)
    .bind(&req.model)
    .bind(&req.pubkey)
    .fetch_one(&s.pool)
    .await
    .map_err(db)?;
    Ok(Json(device_from_row(&row)))
}

/// `GET /devices` — the roster.
pub async fn list_devices(State(s): State<AppState>) -> Result<Json<Vec<Device>>, AppError> {
    let rows = sqlx::query("SELECT id, model, status, pubkey FROM devices ORDER BY id")
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
    let row = sqlx::query("SELECT id, model, status, pubkey FROM devices WHERE id = $1")
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
    Internal(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found"),
            AppError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, msg).into_response()
    }
}

/// Map a database error into an `AppError`.
fn db(e: sqlx::Error) -> AppError {
    AppError::Internal(e.into())
}
