//! What ONE vehicle was given, validated against what its build declares.
//!
//! # The tower is passive
//!
//! Nothing in this module dials a rig. An assignment is an INTENTION recorded
//! offboard — authored at an end-of-line station, in a workshop or by fleet ops
//! — and the orchestrator is what carries it to a node, as it carries everything
//! else. A tower that pushed would be a tower that has to know where every
//! vehicle is and whether it is awake.
//!
//! # What is stored is what was sent
//!
//! The values go into the row exactly as they arrived, once the set's JSON
//! Schema has accepted them. Defaults are the declaration's business, not the
//! tower's: filling one in would mean understanding the fleet's grammar, and
//! this tower deliberately understands only JSON Schema.

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::blob::{self, Blob, Values};
use crate::{schemas, AppError};

/// What a client assigns: which declaration to check against, and the values.
#[derive(Deserialize)]
pub struct NewAssignment {
    pub model: String,
    pub version: String,
    pub values: Values,
}

/// One assignment as every route names it.
#[derive(Serialize)]
pub struct Summary {
    pub set_id: String,
    pub model: String,
    pub version: String,
    pub revision: i64,
    pub content_hash: String,
}

/// The summary and the values it is a summary of.
#[derive(Serialize)]
pub struct Detail {
    #[serde(flatten)]
    pub summary: Summary,
    pub values: Values,
}

/// One vehicle's assignment of one set.
///
/// The revision is the previous one plus one and is per `(vehicle, set)`: it
/// counts what this vehicle was told about this set, so two vehicles given the
/// same values are both at revision 1 and a vehicle told twice is at 2.
pub async fn put_assignment(
    State(pool): State<PgPool>,
    Path((vehicle_id, set_id)): Path<(String, String)>,
    Json(new): Json<NewAssignment>,
) -> Result<Json<Summary>, AppError> {
    let sets = schemas::fetch(&pool, &new.model, &new.version)
        .await?
        .ok_or(AppError::NotFound)?;
    // An unknown SET is a 404 like an unpublished declaration — the client
    // addressed something that is not there — and everything the set's schema
    // refuses is a 400 in the validator's own words, because that is a body the
    // client can fix.
    let schema = sets.get(&set_id).ok_or(AppError::NotFound)?;
    let validator = jsonschema::draft202012::new(schema).map_err(|e| {
        AppError::Internal(anyhow::anyhow!(
            "stored schema '{set_id}' no longer compiles: {e}"
        ))
    })?;
    let instance = serde_json::to_value(&new.values).map_err(|e| AppError::Internal(e.into()))?;
    if let Err(e) = validator.validate(&instance) {
        return Err(AppError::BadRequest(refusal(&e)));
    }

    let previous: Option<i64> = sqlx::query_scalar(
        "SELECT revision FROM assignments WHERE vehicle_id = $1 AND set_id = $2",
    )
    .bind(&vehicle_id)
    .bind(&set_id)
    .fetch_optional(&pool)
    .await?;
    let revision = previous.unwrap_or(0) + 1;
    let content_hash = blob::hash(&blob::render(&Blob {
        set: &set_id,
        model: &new.model,
        version: &new.version,
        revision,
        values: &new.values,
    }));

    sqlx::query(
        "INSERT INTO assignments \
             (vehicle_id, set_id, model, version, revision, content_hash, values_json, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now()) \
         ON CONFLICT (vehicle_id, set_id) DO UPDATE SET \
             model = EXCLUDED.model, version = EXCLUDED.version, \
             revision = EXCLUDED.revision, content_hash = EXCLUDED.content_hash, \
             values_json = EXCLUDED.values_json, updated_at = EXCLUDED.updated_at",
    )
    .bind(&vehicle_id)
    .bind(&set_id)
    .bind(&new.model)
    .bind(&new.version)
    .bind(revision)
    .bind(&content_hash)
    .bind(&instance)
    .execute(&pool)
    .await?;

    Ok(Json(Summary {
        set_id,
        model: new.model,
        version: new.version,
        revision,
        content_hash,
    }))
}

/// Everything one vehicle has been assigned.
pub async fn list_assignments(
    State(pool): State<PgPool>,
    Path(vehicle_id): Path<String>,
) -> Result<Json<Vec<Summary>>, AppError> {
    let rows: Vec<(String, String, String, i64, String)> = sqlx::query_as(
        "SELECT set_id, model, version, revision, content_hash FROM assignments \
         WHERE vehicle_id = $1 ORDER BY set_id",
    )
    .bind(&vehicle_id)
    .fetch_all(&pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(set_id, model, version, revision, content_hash)| Summary {
                set_id,
                model,
                version,
                revision,
                content_hash,
            })
            .collect(),
    ))
}

/// One assignment, values and all.
pub async fn get_assignment(
    State(pool): State<PgPool>,
    Path((vehicle_id, set_id)): Path<(String, String)>,
) -> Result<Json<Detail>, AppError> {
    let (summary, values) = fetch(&pool, &vehicle_id, &set_id).await?;
    Ok(Json(Detail { summary, values }))
}

/// The canonical blob, which is the document the hash is over.
///
/// Rendered rather than stored: `blob.rs` argues why these bytes are a function
/// of the row, and a second copy of them in a column would be a thing that can
/// disagree with the columns it was rendered from.
pub async fn get_blob(
    State(pool): State<PgPool>,
    Path((vehicle_id, set_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let (summary, values) = fetch(&pool, &vehicle_id, &set_id).await?;
    let bytes = blob::render(&Blob {
        set: &summary.set_id,
        model: &summary.model,
        version: &summary.version,
        revision: summary.revision,
        values: &values,
    });
    Ok(([(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}

/// One vehicle's assignment, withdrawn.
///
/// 204 whether there was a row or not: a DELETE says what the tower holds
/// afterwards, and afterwards it holds nothing either way. The next assignment
/// of that pair starts again at revision 1 — the history this tower keeps is one
/// row, and a revision counter outliving the row it counts would be a claim
/// about a history that is not there.
pub async fn delete_assignment(
    State(pool): State<PgPool>,
    Path((vehicle_id, set_id)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    sqlx::query("DELETE FROM assignments WHERE vehicle_id = $1 AND set_id = $2")
        .bind(&vehicle_id)
        .bind(&set_id)
        .execute(&pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// One row, as the two readers of it want it.
async fn fetch(
    pool: &PgPool,
    vehicle_id: &str,
    set_id: &str,
) -> Result<(Summary, Values), AppError> {
    let row: Option<(String, String, i64, String, serde_json::Value)> = sqlx::query_as(
        "SELECT model, version, revision, content_hash, values_json FROM assignments \
         WHERE vehicle_id = $1 AND set_id = $2",
    )
    .bind(vehicle_id)
    .bind(set_id)
    .fetch_optional(pool)
    .await?;
    let (model, version, revision, content_hash, values_json) = row.ok_or(AppError::NotFound)?;
    let values: Values = serde_json::from_value(values_json).map_err(|e| {
        AppError::Internal(anyhow::Error::new(e).context("stored values no longer parse"))
    })?;
    Ok((
        Summary {
            set_id: set_id.to_string(),
            model,
            version,
            revision,
            content_hash,
        },
        values,
    ))
}

/// The validator's refusal, on one line: the key it is about, then what it says.
///
/// `instance_path` is a JSON pointer (`/Vehicle.Chassis.AxleCount`); the leading
/// slash goes, so a client reads `Vehicle.Chassis.AxleCount: 9 is greater than
/// the maximum of 6`. An error about the set as a whole (a missing required key)
/// has an empty path and is reported as it stands.
fn refusal(e: &jsonschema::ValidationError<'_>) -> String {
    let path = e.instance_path().to_string();
    match path.strip_prefix('/') {
        Some(key) if !key.is_empty() => format!("{key}: {e}"),
        _ => e.to_string(),
    }
}
