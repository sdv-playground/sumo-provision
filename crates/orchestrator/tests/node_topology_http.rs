//! The node-resource reads (`x-update-state`, `x-boot-id`, `x-ecu-id`) against a
//! root-form device (several components, node resources at the entity root) and a
//! node-topology one (one node at `/components`, node resources on it, components
//! as its subcomponents, the root paths gone).

use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use orchestrator::{node_update_state, NodeTopology, RigToken};
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

/// A node-topology device: one node `cvc`.
fn node_device() -> Router {
    Router::new()
        .route(
            "/vehicle/v1/components",
            get(|| async { Json(json!({ "items": [{ "id": "cvc", "name": "CVC" }] })) }),
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
fn discovery_classifies_one_component_as_the_node() {
    assert_eq!(
        NodeTopology::from_components_body(&json!({ "items": [{ "id": "cvc" }] })),
        NodeTopology::Node("cvc".into())
    );
    for body in [
        json!({ "items": [{ "id": "host" }, { "id": "hsm" }] }),
        json!({ "items": [] }),
        json!({}),
    ] {
        assert_eq!(
            NodeTopology::from_components_body(&body),
            NodeTopology::Root,
            "{body}"
        );
    }
    let node = NodeTopology::Node("cvc".into());
    assert_eq!(node.node_path(), "/vehicle/v1/components/cvc");
    assert_eq!(
        node.component_path("hsm"),
        "/vehicle/v1/components/cvc/subcomponents/hsm"
    );
    assert_eq!(NodeTopology::Root.node_path(), "/vehicle/v1");
    assert_eq!(
        NodeTopology::Root.component_path("hsm"),
        "/vehicle/v1/components/hsm"
    );
}
