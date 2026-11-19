//! The node-resource reads (`x-update-state`, `x-boot-id`, `x-ecu-id`) against a
//! root-form device (several components, node resources at the entity root) and a
//! node-topology one (one node at `/components`, node resources on it, components
//! as its subcomponents, the root paths gone).

use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use orchestrator::{discover_node_topology, node_update_state, NodeTopology, RigToken};
use serde_json::{json, Value};
use sovd_client::testing::TestServer;
use sumo_sovd_flash_engine::TokenSource;

/// The device's update state, served at `{prefix}/data/{resource}`.
fn update_state(prefix: &str, resource: &str) -> Router {
    Router::new().route(
        &format!("{prefix}/data/{resource}"),
        get(|| async { Json(json!({ "phase": "Trial", "components": ["vm1"] })) }),
    )
}

/// A stub minter whose token echoes the `aud` and `boot_id` it was asked for.
fn minter() -> Router {
    Router::new().route(
        "/mint",
        post(|Json(req): Json<Value>| async move {
            Json(json!({
                "token": format!("{}|{}", req["device_id"].as_str().unwrap(), req["boot_id"].as_str().unwrap()),
                "expires_at": "never",
            }))
        }),
    )
}

/// A root-form device (sumo-machine-manager ≤ v0.1.21): two components.
fn root_device() -> Router {
    Router::new()
        .route(
            "/vehicle/v1/components",
            get(|| async { Json(json!({ "items": [{ "id": "host" }, { "id": "hsm" }] })) }),
        )
        .route(
            "/vehicle/v1/status/x-boot-id",
            get(|| async { "root-boot\n" }),
        )
        .route(
            "/vehicle/v1/components/hsm/x-ecu-id",
            get(|| async { "\"root-ecu\"" }),
        )
}

/// A node-topology device: one node `cvc`, whose document links its subcomponents.
fn node_device() -> Router {
    Router::new()
        .route(
            "/vehicle/v1/components",
            get(|| async { Json(json!({ "items": [{ "id": "cvc", "name": "CVC" }] })) }),
        )
        .route(
            "/vehicle/v1/components/cvc",
            get(|| async {
                Json(json!({
                    "id": "cvc",
                    "name": "CVC",
                    "subcomponents": "/vehicle/v1/components/cvc/subcomponents",
                }))
            }),
        )
        .route(
            "/vehicle/v1/components/cvc/data/x-boot-id",
            get(|| async { Json(json!({ "id": "x-boot-id", "data": "node-boot" })) }),
        )
        .route(
            "/vehicle/v1/components/cvc/subcomponents/hsm/x-ecu-id",
            get(|| async { "node-ecu" }),
        )
        // The removed root forms: a client still on them fails the test.
        .route(
            "/vehicle/v1/status/x-boot-id",
            get(|| async { StatusCode::NOT_FOUND }),
        )
        .route(
            "/vehicle/v1/data/x-update-state",
            get(|| async { StatusCode::NOT_FOUND }),
        )
}

/// A flat device with ONE component (`hsm`) and root node resources — a lone
/// component that is not a node (no `subcomponents` link, its subcomponents 404).
fn single_component_flat_device() -> Router {
    Router::new()
        .route(
            "/vehicle/v1/components",
            get(|| async { Json(json!({ "items": [{ "id": "hsm", "name": "HSM" }] })) }),
        )
        .route(
            "/vehicle/v1/components/hsm",
            get(|| async { Json(json!({ "id": "hsm", "name": "HSM" })) }),
        )
        .route(
            "/vehicle/v1/status/x-boot-id",
            get(|| async { "flat-boot" }),
        )
        .route(
            "/vehicle/v1/components/hsm/x-ecu-id",
            get(|| async { "flat-ecu" }),
        )
}

#[tokio::test]
async fn a_single_component_flat_device_is_not_a_node() {
    let server = TestServer::start(single_component_flat_device())
        .await
        .unwrap();
    let client = reqwest::Client::new();
    assert_eq!(
        discover_node_topology(&client, &server.base_url()).await,
        Some(NodeTopology::Root)
    );
}

#[tokio::test]
async fn a_lone_component_whose_subcomponents_answer_is_the_node() {
    // A node document without the link, but a served subcomponents collection.
    let server = TestServer::start(
        Router::new()
            .route(
                "/vehicle/v1/components",
                get(|| async { Json(json!({ "items": [{ "id": "cvc", "name": "CVC" }] })) }),
            )
            .route(
                "/vehicle/v1/components/cvc/subcomponents",
                get(|| async { Json(json!({ "items": [{ "id": "hsm", "name": "HSM" }] })) }),
            ),
    )
    .await
    .unwrap();
    let client = reqwest::Client::new();
    assert_eq!(
        discover_node_topology(&client, &server.base_url()).await,
        Some(NodeTopology::Node("cvc".into()))
    );
}

#[tokio::test]
async fn node_update_state_on_a_single_component_flat_device_stays_at_the_root() {
    let server = TestServer::start(
        single_component_flat_device().merge(update_state("/vehicle/v1", "x-update-state")),
    )
    .await
    .unwrap();
    let state = node_update_state(&server.base_url(), false, None)
        .await
        .unwrap();
    assert_eq!(state.phase, "Trial");
}

#[tokio::test]
async fn minted_token_on_a_single_component_flat_device_reads_the_root_forms() {
    let server = TestServer::start(single_component_flat_device().merge(minter()))
        .await
        .unwrap();
    let url = server.base_url();
    let token = RigToken::minting(&url, "op", &url, None, false, None);
    assert_eq!(token.token("hsm").await.unwrap(), "flat-ecu|flat-boot");
}

#[tokio::test]
async fn update_state_is_read_at_the_root_on_a_root_form_device() {
    let server =
        TestServer::start(root_device().merge(update_state("/vehicle/v1", "x-update-state")))
            .await
            .unwrap();
    let state = node_update_state(&server.base_url(), false, None)
        .await
        .unwrap();
    assert_eq!(state.phase, "Trial");
}

#[tokio::test]
async fn update_state_is_read_off_the_node_on_a_node_topology_device() {
    let server = TestServer::start(
        node_device().merge(update_state("/vehicle/v1/components/cvc", "x-update-state")),
    )
    .await
    .unwrap();
    let state = node_update_state(&server.base_url(), false, None)
        .await
        .unwrap();
    assert_eq!(state.phase, "Trial");
    assert_eq!(state.components, ["vm1"]);
}

#[tokio::test]
async fn update_state_falls_back_to_x_ota_update_state_on_the_node() {
    let server = TestServer::start(node_device().merge(update_state(
        "/vehicle/v1/components/cvc",
        "x-ota-update-state",
    )))
    .await
    .unwrap();
    let state = node_update_state(&server.base_url(), false, None)
        .await
        .unwrap();
    assert_eq!(state.phase, "Trial");
}

#[tokio::test]
async fn update_state_absent_on_the_node_is_idle() {
    let server = TestServer::start(node_device()).await.unwrap();
    let state = node_update_state(&server.base_url(), false, None)
        .await
        .unwrap();
    assert_eq!(state.phase, "Idle");
}

#[tokio::test]
async fn minted_token_binds_the_root_boot_id_on_a_root_form_device() {
    let server = TestServer::start(root_device().merge(minter()))
        .await
        .unwrap();
    let url = server.base_url();
    let token = RigToken::minting(&url, "op", &url, None, false, None);
    assert_eq!(token.token("vm1").await.unwrap(), "root-ecu|root-boot");
}

#[tokio::test]
async fn minted_token_binds_the_node_boot_id_on_a_node_topology_device() {
    let server = TestServer::start(node_device().merge(minter()))
        .await
        .unwrap();
    let url = server.base_url();
    let token = RigToken::minting(&url, "op", &url, None, false, None);
    assert_eq!(token.token("vm1").await.unwrap(), "node-ecu|node-boot");
    // Discovery is cached: the second call reuses the token for the same boot.
    assert_eq!(token.token("vm2").await.unwrap(), "node-ecu|node-boot");
}

#[test]
fn discovery_takes_one_component_as_the_node_candidate() {
    assert_eq!(
        NodeTopology::node_candidate(&json!({ "items": [{ "id": "cvc" }] })),
        Some("cvc".into())
    );
    for body in [
        json!({ "items": [{ "id": "host" }, { "id": "hsm" }] }),
        json!({ "items": [] }),
        json!({}),
    ] {
        assert_eq!(NodeTopology::node_candidate(&body), None, "{body}");
    }
    assert!(NodeTopology::is_node_document(&json!({
        "id": "cvc",
        "subcomponents": "/vehicle/v1/components/cvc/subcomponents",
    })));
    assert!(!NodeTopology::is_node_document(&json!({ "id": "hsm" })));
    assert!(!NodeTopology::is_node_document(
        &json!({ "id": "hsm", "subcomponents": null })
    ));
    let node = NodeTopology::Node("cvc".into());
    assert_eq!(node.node_path(), "/vehicle/v1/components/cvc");
    assert_eq!(
        node.component_path("hsm"),
        "/vehicle/v1/components/cvc/subcomponents/hsm"
    );
    assert_eq!(node.component_id("vm1"), "cvc/subcomponents/vm1");
    assert_eq!(NodeTopology::Root.component_id("vm1"), "vm1");
    assert_eq!(NodeTopology::Root.node_path(), "/vehicle/v1");
    assert_eq!(
        NodeTopology::Root.component_path("hsm"),
        "/vehicle/v1/components/hsm"
    );
}
