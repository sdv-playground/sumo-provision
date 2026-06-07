//! Release & channel storage (Tower 2).
//!
//! L2 **component releases** (one entity's versioned parts), L1 **campaign
//! releases** (a tagged combination of component releases), and **channel**
//! pointers. Resolving a channel yields the desired [`wire::Tree`] the
//! orchestrator diffs against the rig.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use wire::{ArtifactRef, ContentHash, Entity, Part, Tree};

use crate::content::{AppError, AppState};

// --- request / response bodies ---------------------------------------------

/// `POST /admin/component-releases` body — one entity's versioned parts.
#[derive(Deserialize)]
pub struct NewComponentRelease {
    pub entity_path: String,
    pub entity_kind: String,
    pub version: String,
    pub parts: Vec<NewPart>,
}

#[derive(Deserialize)]
pub struct NewPart {
    pub id: String,
    pub kind: String,
    pub content: ContentHash,
}

/// `POST /admin/campaign-releases` body — a tagged combination of component
/// releases.
#[derive(Deserialize)]
pub struct NewCampaignRelease {
    pub tag: String,
    pub version: String,
    pub members: Vec<i64>,
}

/// `PUT /admin/channels/{name}` body.
#[derive(Deserialize)]
pub struct SetChannel {
    pub campaign_release_id: i64,
}

#[derive(Serialize)]
pub struct Created {
    pub id: i64,
}

// --- handlers --------------------------------------------------------------

/// `POST /admin/component-releases` — mint an L2 component release.
pub async fn create_component_release(
    State(s): State<AppState>,
    Json(req): Json<NewComponentRelease>,
) -> Result<Json<Created>, AppError> {
    let pool = s.pool()?;
    let id: i64 = sqlx::query(
        "INSERT INTO component_releases (entity_path, entity_kind, version) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(&req.entity_path)
    .bind(&req.entity_kind)
    .bind(&req.version)
    .fetch_one(pool)
    .await
    .map_err(db)?
    .get("id");

    for p in &req.parts {
        sqlx::query(
            "INSERT INTO component_release_parts (release_id, part_id, part_kind, content_hash) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(&p.id)
        .bind(&p.kind)
        .bind(p.content.to_prefixed())
        .execute(pool)
        .await
        .map_err(db)?;
    }
    Ok(Json(Created { id }))
}

/// `POST /admin/campaign-releases` — mint an L1 campaign release (combination).
pub async fn create_campaign_release(
    State(s): State<AppState>,
    Json(req): Json<NewCampaignRelease>,
) -> Result<Json<Created>, AppError> {
    let pool = s.pool()?;
    let id: i64 =
        sqlx::query("INSERT INTO campaign_releases (tag, version) VALUES ($1, $2) RETURNING id")
            .bind(&req.tag)
            .bind(&req.version)
            .fetch_one(pool)
            .await
            .map_err(db)?
            .get("id");

    for m in &req.members {
        sqlx::query(
            "INSERT INTO campaign_release_members (campaign_id, component_release_id) \
             VALUES ($1, $2)",
        )
        .bind(id)
        .bind(m)
        .execute(pool)
        .await
        .map_err(db)?;
    }
    Ok(Json(Created { id }))
}

/// `PUT /admin/channels/{name}` — point a channel at a campaign release.
pub async fn set_channel(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<SetChannel>,
) -> Result<(), AppError> {
    let pool = s.pool()?;
    sqlx::query(
        "INSERT INTO channels (name, campaign_release_id, updated_at) VALUES ($1, $2, now()) \
         ON CONFLICT (name) DO UPDATE SET campaign_release_id = $2, updated_at = now()",
    )
    .bind(&name)
    .bind(req.campaign_release_id)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

/// `GET /channels/{name}/tree` — resolve a channel to its desired tree.
pub async fn channel_tree(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Tree>, AppError> {
    let tree = resolve_channel(s.pool()?, &name)
        .await
        .map_err(db)?
        .ok_or(AppError::NotFound)?;
    Ok(Json(tree))
}

/// `GET /admin/artifacts/{inner}` — does Tower 2 already have this content?
/// `200` + the ref if stored, `404` if not — so a build step can skip the upload.
pub async fn artifact_exists(
    State(s): State<AppState>,
    Path(inner): Path<String>,
) -> Result<Json<ArtifactRef>, AppError> {
    let inner: ContentHash = inner.parse().map_err(|_| AppError::BadHash)?;
    match s.index.get(&inner).await? {
        Some(e) => Ok(Json(ArtifactRef {
            inner: e.inner,
            outer: e.outer,
            size: e.size,
        })),
        None => Err(AppError::NotFound),
    }
}

// --- resolution ------------------------------------------------------------

/// Resolve a channel to its desired [`wire::Tree`]: channel → campaign release →
/// member component releases → their entities + parts. `None` when the channel
/// is unset or unknown.
async fn resolve_channel(pool: &PgPool, name: &str) -> sqlx::Result<Option<Tree>> {
    let Some(campaign_id) = channel_campaign(pool, name).await? else {
        return Ok(None);
    };
    let members = sqlx::query(
        "SELECT component_release_id FROM campaign_release_members WHERE campaign_id = $1",
    )
    .bind(campaign_id)
    .fetch_all(pool)
    .await?;

    let mut tree = Tree::default();
    for m in members {
        let rid: i64 = m.get("component_release_id");
        let row = sqlx::query(
            "SELECT entity_path, entity_kind, version FROM component_releases WHERE id = $1",
        )
        .bind(rid)
        .fetch_one(pool)
        .await?;
        let path: String = row.get("entity_path");
        let mut entity = Entity {
            kind: row.get("entity_kind"),
            version: Some(row.get("version")),
            parts: Vec::new(),
        };
        let parts =
            sqlx::query("SELECT part_id, part_kind, content_hash FROM component_release_parts WHERE release_id = $1")
                .bind(rid)
                .fetch_all(pool)
                .await?;
        for p in parts {
            let content: String = p.get("content_hash");
            let Ok(content) = content.parse::<ContentHash>() else {
                continue;
            };
            entity.parts.push(Part {
                kind: p.get("part_kind"),
                id: p.get("part_id"),
                content,
            });
        }
        tree.entities.insert(path, entity);
    }
    Ok(Some(tree))
}

async fn channel_campaign(pool: &PgPool, name: &str) -> sqlx::Result<Option<i64>> {
    let row = sqlx::query("SELECT campaign_release_id FROM channels WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(|r| r.get::<Option<i64>, _>("campaign_release_id")))
}

/// Map a database error into an `AppError`.
fn db(e: sqlx::Error) -> AppError {
    AppError::Internal(e.into())
}
