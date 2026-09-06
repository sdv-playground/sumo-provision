//! **The tower as a client meets it**: the router, called.
//!
//! Through `oneshot` against the same `Router` the binary serves — the routes,
//! the extractors, the statuses and the SQL — with nothing stubbed and no socket
//! in the way.
//!
//! These tests need Postgres. `TEST_DATABASE_URL` names it, defaulting to the
//! `sumo_cfg_test` database on the `docker compose up -d postgres` this repo
//! ships (`createdb -U sumo sumo_cfg_test` once). When nothing answers there
//! every test SKIPS with a printed reason instead of failing: a workspace
//! `cargo test` on a machine with no database must not go red for a service that
//! was never asked for.
//!
//! The tests share one database, so each owns its own `(model, version)` and
//! vehicle ids, and each assignment test withdraws before it assigns — a
//! revision counts writes, so a suite that did not reset would assert different
//! numbers on its second run.

use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower::ServiceExt as _;

const DEFAULT_TEST_DATABASE_URL: &str =
    "postgres://sumo:dev-only-not-secret@localhost:5432/sumo_cfg_test";

/// A tower over the test database, or `None` when there isn't one.
///
/// The same two steps as `config_tower::open` — connect, then run the crate's
/// migrations — but with a single short attempt instead of the binary's retry
/// loop, so a machine without Postgres skips in seconds.
async fn tower() -> Option<Router> {
    let url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| DEFAULT_TEST_DATABASE_URL.to_string());
    let pool: PgPool = match PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("SKIP: no postgres at {url} ({e}) — set TEST_DATABASE_URL to run these");
            return None;
        }
    };
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations run");
    Some(config_tower::router(pool))
}

/// One request, and what came back.
async fn call(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Vec<u8>) {
    let request = Request::builder().method(method).uri(uri);
    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, bytes.to_vec())
}

/// The same, when the answer is JSON.
async fn json(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let (status, bytes) = call(app, method, uri, body).await;
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// Two sets, declared as JSON Schema — which is the only parameter grammar this
/// tower knows.
fn sets() -> Value {
    json!({
        "vehicle-attributes": {
            "type": "object",
            "properties": {
                "Vehicle.Chassis.AxleCount": { "type": "integer", "minimum": 2, "maximum": 6 },
                "Vehicle.Chassis.WheelbaseMm": { "type": "number" }
            },
            "required": ["Vehicle.Chassis.AxleCount"],
            "additionalProperties": false
        },
        "dashboard.params": {
            "type": "object",
            "properties": {
                "max_display_speed_kmh": { "type": "integer" },
                "display_brightness_pct": { "type": "number" }
            },
            "additionalProperties": false
        }
    })
}

/// A tower that already knows what `model`/`version` declares.
async fn published(model: &str, version: &str) -> Option<Router> {
    let app = tower().await?;
    let (status, _) = call(
        &app,
        "PUT",
        &format!("/admin/schemas/{model}/{version}"),
        Some(json!({ "sets": sets() })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    Some(app)
}

fn assign(model: &str, version: &str, values: Value) -> Value {
    json!({ "model": model, "version": version, "values": values })
}

#[tokio::test]
async fn a_declaration_is_published_listed_and_read_back() {
    const MODEL: &str = "cfg-test-schemas";
    const VERSION: &str = "0df1d79";
    let Some(app) = published(MODEL, VERSION).await else {
        return;
    };

    // Idempotent: a build pipeline publishes the same declaration every run.
    let (status, _) = call(
        &app,
        "PUT",
        &format!("/admin/schemas/{MODEL}/{VERSION}"),
        Some(json!({ "sets": sets() })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, listing) = json(&app, "GET", "/schemas", None).await;
    assert_eq!(status, StatusCode::OK);
    let mine = listing
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["model"] == MODEL && s["version"] == VERSION)
        .unwrap_or_else(|| panic!("{MODEL}/{VERSION} is in the listing: {listing}"));
    assert_eq!(
        mine["sets"],
        json!(["dashboard.params", "vehicle-attributes"])
    );

    let (status, read) = json(&app, "GET", &format!("/schemas/{MODEL}/{VERSION}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read, json!({ "sets": sets() }));

    let (status, _) = call(&app, "GET", &format!("/schemas/{MODEL}/nope"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A set whose declaration is not a JSON Schema is refused where it was
/// published, not at the first assignment that happens to hit it.
#[tokio::test]
async fn a_declaration_that_is_not_a_json_schema_is_refused() {
    let Some(app) = tower().await else { return };

    let (status, said) = call(
        &app,
        "PUT",
        "/admin/schemas/cfg-test-badschema/0df1d79",
        Some(json!({ "sets": { "broken": { "type": "not-a-json-type" } } })),
    )
    .await;
    let said = String::from_utf8(said).unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST, "{said}");
    assert!(said.contains("'broken'"), "{said}");

    let (status, _) = call(&app, "GET", "/schemas/cfg-test-badschema/0df1d79", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_assignment_is_validated_against_the_published_declaration() {
    const MODEL: &str = "cfg-test-assign";
    const VERSION: &str = "0df1d79";
    let Some(app) = published(MODEL, VERSION).await else {
        return;
    };
    let uri = "/admin/vehicles/CFG-ASSIGN-001/assignments/vehicle-attributes";
    let (status, _) = call(&app, "DELETE", uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, summary) = json(
        &app,
        "PUT",
        uri,
        Some(assign(
            MODEL,
            VERSION,
            json!({ "Vehicle.Chassis.AxleCount": 2, "Vehicle.Chassis.WheelbaseMm": 2900.0 }),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(summary["set_id"], "vehicle-attributes");
    assert_eq!(summary["model"], MODEL);
    assert_eq!(summary["version"], VERSION);
    assert_eq!(summary["revision"], 1);
    assert!(
        summary["content_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"),
        "{summary}"
    );

    // A second write of the same pair is the next revision of it.
    let (status, again) = json(
        &app,
        "PUT",
        uri,
        Some(assign(
            MODEL,
            VERSION,
            json!({ "Vehicle.Chassis.AxleCount": 3, "Vehicle.Chassis.WheelbaseMm": 2900.0 }),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["revision"], 2);
    assert_ne!(again["content_hash"], summary["content_hash"]);

    // Outside the declared range: refused in the validator's own words, naming
    // the key, and the assignment that stands is untouched.
    let (status, said) = call(
        &app,
        "PUT",
        uri,
        Some(assign(
            MODEL,
            VERSION,
            json!({ "Vehicle.Chassis.AxleCount": 9, "Vehicle.Chassis.WheelbaseMm": 2900.0 }),
        )),
    )
    .await;
    let said = String::from_utf8(said).unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST, "{said}");
    assert_eq!(
        said,
        "Vehicle.Chassis.AxleCount: 9 is greater than the maximum of 6"
    );

    let (_, standing) = json(&app, "GET", "/vehicles/CFG-ASSIGN-001/assignments", None).await;
    assert_eq!(standing[0]["revision"], 2);

    // A set the declaration does not declare, and a version nothing published:
    // both are things the client addressed that are not there.
    let (status, _) = call(
        &app,
        "PUT",
        "/admin/vehicles/CFG-ASSIGN-001/assignments/invented",
        Some(assign(MODEL, VERSION, json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = call(&app, "PUT", uri, Some(assign(MODEL, "nope", json!({})))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_blob_is_the_document_the_hash_is_over() {
    const MODEL: &str = "cfg-test-blob";
    const VERSION: &str = "0df1d79";
    let Some(app) = published(MODEL, VERSION).await else {
        return;
    };
    let admin = "/admin/vehicles/CFG-BLOB-001/assignments/dashboard.params";
    let read = "/vehicles/CFG-BLOB-001/assignments/dashboard.params";
    call(&app, "DELETE", admin, None).await;

    let (status, summary) = json(
        &app,
        "PUT",
        admin,
        Some(assign(
            MODEL,
            VERSION,
            json!({ "max_display_speed_kmh": 200, "display_brightness_pct": 80.0 }),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{summary}");

    // The values are stored as sent — this tower validates, it does not re-type
    // and it does not fill anything in.
    let (status, detail) = json(&app, "GET", read, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["revision"], 1);
    assert_eq!(detail["content_hash"], summary["content_hash"]);
    assert_eq!(detail["values"]["max_display_speed_kmh"], 200);
    assert_eq!(detail["values"]["display_brightness_pct"], 80.0);

    let (status, bytes) = call(&app, "GET", &format!("{read}/blob"), None).await;
    assert_eq!(status, StatusCode::OK);

    // THE HASH IS OVER EXACTLY THESE BYTES. Computed here from the response body
    // and from nothing the tower handed us but the body itself.
    let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    assert_eq!(digest, summary["content_hash"].as_str().unwrap());

    // And the bytes are the canonical document: five fields in this order, keys
    // sorted, no whitespace.
    let blob = String::from_utf8(bytes).unwrap();
    assert_eq!(
        blob,
        format!(
            r#"{{"set":"dashboard.params","model":"{MODEL}","version":"{VERSION}","revision":1,"values":{{"display_brightness_pct":80.0,"max_display_speed_kmh":200}}}}"#
        )
    );
}

#[tokio::test]
async fn an_assignment_is_withdrawn() {
    const MODEL: &str = "cfg-test-delete";
    const VERSION: &str = "0df1d79";
    let Some(app) = published(MODEL, VERSION).await else {
        return;
    };
    let admin = "/admin/vehicles/CFG-DELETE-001/assignments/vehicle-attributes";
    let read = "/vehicles/CFG-DELETE-001/assignments/vehicle-attributes";

    let (status, _) = call(
        &app,
        "PUT",
        admin,
        Some(assign(
            MODEL,
            VERSION,
            json!({ "Vehicle.Chassis.AxleCount": 2 }),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(&app, "DELETE", admin, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = call(&app, "GET", read, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (_, listing) = json(&app, "GET", "/vehicles/CFG-DELETE-001/assignments", None).await;
    assert_eq!(listing, json!([]));
}

#[tokio::test]
async fn the_tower_says_what_it_is() {
    let Some(app) = tower().await else { return };

    let (status, bytes) = call(&app, "GET", "/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(String::from_utf8(bytes).unwrap(), "ok");

    let (status, version) = json(&app, "GET", "/version", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(version["service"], "sumo-cfg");
    assert_eq!(version["version"], env!("CARGO_PKG_VERSION"));
}
