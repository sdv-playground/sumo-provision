//! What a model version declares, published and read back.
//!
//! A declaration is a map of set id → **JSON Schema** (draft 2020-12), stored
//! against `(model, version)` because that is what a declaration belongs to. A
//! schema per vehicle would be a fleet in which two vehicles of one build can
//! disagree about what a key means.
//!
//! The tower is schema-AGNOSTIC: it compiles each set's schema and keeps it, and
//! that is the whole of what it understands about a fleet's parameters. Anything
//! a JSON Schema can say — types, ranges, required keys, `additionalProperties:
//! false` — is said by whoever publishes the declaration, not by this crate.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::AppError;

/// Set id → the JSON Schema its values must satisfy.
pub type Sets = BTreeMap<String, serde_json::Value>;

/// A declaration, as it is published and as it is read back.
#[derive(Deserialize, Serialize)]
pub struct SchemaBody {
    pub sets: Sets,
}

/// One published declaration, as the listing names it.
#[derive(Serialize)]
pub struct Published {
    pub model: String,
    pub version: String,
    /// The set ids, which is what a client needs before it can assign anything
    /// — the rest of the declaration is one request further on.
    pub sets: Vec<String>,
}

/// A model version's declaration, replaced whole.
///
/// Every set's schema is compiled HERE, at publish time: a schema that cannot be
/// compiled is refused now, in the pipeline that published it, rather than at
/// the first assignment that happens to hit it. Idempotent, and 204 says so —
/// publishing the same declaration twice is what a build pipeline does.
pub async fn put_schema(
    State(pool): State<PgPool>,
    Path((model, version)): Path<(String, String)>,
    Json(body): Json<SchemaBody>,
) -> Result<StatusCode, AppError> {
    for (set_id, schema) in &body.sets {
        jsonschema::draft202012::new(schema).map_err(|e| {
            AppError::BadRequest(format!("set '{set_id}' is not a JSON Schema: {e}"))
        })?;
    }
    let sets = serde_json::to_value(&body.sets).map_err(|e| AppError::Internal(e.into()))?;
    sqlx::query(
        "INSERT INTO schemas (model, version, sets) VALUES ($1, $2, $3) \
         ON CONFLICT (model, version) DO UPDATE SET sets = EXCLUDED.sets",
    )
    .bind(&model)
    .bind(&version)
    .bind(&sets)
    .execute(&pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Every declaration the tower holds.
pub async fn list_schemas(State(pool): State<PgPool>) -> Result<Json<Vec<Published>>, AppError> {
    let rows: Vec<(String, String, serde_json::Value)> =
        sqlx::query_as("SELECT model, version, sets FROM schemas ORDER BY model, version")
            .fetch_all(&pool)
            .await?;
    let mut published = Vec::with_capacity(rows.len());
    for (model, version, sets) in rows {
        published.push(Published {
            model,
            version,
            sets: parse(sets)?.into_keys().collect(),
        });
    }
    Ok(Json(published))
}

/// One declaration, as it was published.
pub async fn get_schema(
    State(pool): State<PgPool>,
    Path((model, version)): Path<(String, String)>,
) -> Result<Json<SchemaBody>, AppError> {
    let sets = fetch(&pool, &model, &version)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(SchemaBody { sets }))
}

/// The sets of a declaration, if it has been published.
pub async fn fetch(pool: &PgPool, model: &str, version: &str) -> Result<Option<Sets>, AppError> {
    let sets: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT sets FROM schemas WHERE model = $1 AND version = $2")
            .bind(model)
            .bind(version)
            .fetch_optional(pool)
            .await?;
    sets.map(parse).transpose()
}

/// A stored declaration, read back as what it is.
///
/// A failure here is the TOWER's: the value was a map of schemas before it was
/// stored, so a row that no longer parses is a database somebody has been
/// editing, and that is not a client's fault or a client's business.
fn parse(sets: serde_json::Value) -> Result<Sets, AppError> {
    serde_json::from_value(sets).map_err(|e| {
        AppError::Internal(anyhow::Error::new(e).context("a stored declaration no longer parses"))
    })
}
