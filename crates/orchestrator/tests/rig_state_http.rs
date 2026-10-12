//! Exercise the rig-state projection through the same SOVD HTTP client used in production.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use orchestrator::read_rig_state;
use serde_json::{json, Value};
use sovd_client::testing::TestServer;

#[derive(Clone, Copy)]
enum AdminObservation {
    Disabled,
    Enabled,
    Missing,
    Malformed,
    Failure,
}

#[derive(Clone, Copy)]
struct Fixture {
    admin: AdminObservation,
    include_vm2: bool,
}

async fn components(State(fixture): State<Fixture>) -> Json<Value> {
    let mut items = vec![json!({"id": "vm1", "name": "VM 1", "type": "vm"})];
    if fixture.include_vm2 {
        items.push(json!({"id": "vm2", "name": "VM 2", "type": "vm"}));
    }
    Json(json!({"items": items}))
}

async fn data(Path((component, param)): Path<(String, String)>) -> (StatusCode, Json<Value>) {
    match (component.as_str(), param.as_str()) {
        ("vm1", "x-ota-installed-manifest") => (
            StatusCode::OK,
            Json(json!({"did": null, "value": {
                "identity": {"name": "guest", "version": "1.2"},
                "files": [{"path": "/app.bin", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]
            }})),
        ),
        ("vm2", "x-ota-update-mode") => (
            StatusCode::OK,
            Json(json!({"did": null, "value": {
                "update_mode": "banked", "supports_rollback": true,
                "dual_bank": true, "reset_kind": "requires_ecu_reset"
            }})),
        ),
        _ => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))),
    }
}

async fn status(
    State(fixture): State<Fixture>,
    Path(component): Path<String>,
) -> (StatusCode, Json<Value>) {
    if component == "vm2" {
        return (StatusCode::OK, Json(json!({"status": "ready"})));
    }
    match fixture.admin {
        AdminObservation::Disabled => (
            StatusCode::OK,
            Json(json!({"status": "ready", "x-runtime": {"admin_state": "disabled"}})),
        ),
        AdminObservation::Enabled => (
            StatusCode::OK,
            Json(json!({"status": "ready", "x-runtime": {"admin_state": "enabled"}})),
        ),
        AdminObservation::Missing => (StatusCode::OK, Json(json!({"status": "ready"}))),
        AdminObservation::Malformed => (
            StatusCode::OK,
            Json(json!({"status": "ready", "x-runtime": {"admin_state": 42}})),
        ),
        AdminObservation::Failure => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "observation unavailable"})),
        ),
    }
}

async fn server(observation: AdminObservation) -> TestServer {
    server_with_fixture(Fixture {
        admin: observation,
        include_vm2: false,
    })
    .await
}

async fn server_with_fixture(fixture: Fixture) -> TestServer {
    let router = Router::new()
        .route("/vehicle/v1/components", get(components))
        .route("/vehicle/v1/components/{component}/data/{param}", get(data))
        .route("/vehicle/v1/components/{component}/status", get(status))
        .with_state(fixture);
    TestServer::start(router).await.expect("SOVD test server")
}

#[tokio::test]
async fn rig_state_keeps_advertised_component_without_installed_manifest() {
    let server = server_with_fixture(Fixture {
        admin: AdminObservation::Disabled,
        include_vm2: true,
    })
    .await;
    let tree = read_rig_state(&server.base_url(), false, None)
        .await
        .expect("read both components");
    assert_eq!(tree.entities.len(), 2);
    assert_eq!(tree.entities["vm1"].admin_disabled, Some(true));
    assert_eq!(tree.entities["vm1"].parts.len(), 1);
    let vm2 = &tree.entities["vm2"];
    assert!(vm2.parts.is_empty());
    assert!(vm2.version.is_none());
    assert_eq!(vm2.admin_disabled, None); // non-disableable component
    let mode = vm2.update_mode.as_ref().expect("reported capability");
    assert_eq!(mode.mode, "banked");
    assert!(mode.supports_rollback);
}

#[tokio::test]
async fn rig_state_preserves_installed_content_and_admin_state() {
    for (observation, expected_disabled) in [
        (AdminObservation::Disabled, Some(true)),
        (AdminObservation::Enabled, Some(false)),
        (AdminObservation::Missing, None),
    ] {
        let server = server(observation).await;
        let tree = read_rig_state(&server.base_url(), false, None)
            .await
            .expect("read rig state");
        let vm = &tree.entities["vm1"];
        assert_eq!(vm.kind, "vm");
        assert_eq!(vm.version.as_deref(), Some("guest 1.2"));
        assert_eq!(vm.admin_disabled, expected_disabled);
        assert_eq!(vm.parts.len(), 1);
        assert_eq!(vm.parts[0].id, "/app.bin");
        assert_eq!(
            vm.parts[0].content.to_string(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(vm.update_mode.is_none());
    }
}

#[tokio::test]
async fn malformed_or_failed_admin_observation_is_not_a_successful_read() {
    for observation in [AdminObservation::Malformed, AdminObservation::Failure] {
        let server = server(observation).await;
        let error = read_rig_state(&server.base_url(), false, None)
            .await
            .expect_err("invalid administrative observation must fail");
        let message = error.to_string();
        assert!(
            message.contains("admin_state") || message.contains("503"),
            "unexpected error: {message}"
        );
    }
}

#[tokio::test]
async fn rig_state_probes_http_after_https_transport_failure() {
    let server = server(AdminObservation::Disabled).await;
    let https_url = server.base_url().replacen("http://", "https://", 1);
    let tree = read_rig_state(&https_url, false, None)
        .await
        .expect("fall back to the live HTTP scheme");
    assert_eq!(tree.entities["vm1"].admin_disabled, Some(true));
}
