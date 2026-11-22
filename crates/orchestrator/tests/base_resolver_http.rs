//! A device that moves base across a node restart (http while unprovisioned,
//! https once the restart applied provisioning), played by two in-process fakes
//! on 127.0.0.1: A goes away on the restart, B answers with the rotated node boot.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    extract::{Path, Request, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use orchestrator::{
    flash_keystore, flash_keystore_activated, flash_keystore_with_resolver, BaseResolver,
    ProbingBaseResolver, RigToken,
};
use serde_json::{json, Value};
use sovd_client::testing::TestServer;
use sumo_sovd_flash_engine::TokenSource;

/// One base of the device. A and B share `node_boot` and `restarts` (it is one
/// node); only A goes away once restarted.
#[derive(Clone)]
struct Device {
    /// The hsm's declared `x-ota-update-mode` `reset_kind`; `None` = not declared.
    reset_kind: Option<&'static str>,
    node_boot: Arc<AtomicU32>,
    restarts: Arc<AtomicU32>,
    /// Set by the node restart; a base with `goes_away` drops every request after.
    restarted: Arc<AtomicBool>,
    goes_away: bool,
    /// Every request this base received, as `METHOD path`.
    seen: Arc<Mutex<Vec<String>>>,
    /// The `/updates` phase the last lifecycle verb reached.
    phase: Arc<Mutex<&'static str>>,
    /// The bearer the node restart demands (`None` = unauthenticated). Models
    /// the keystore's trust anchor making the device require one once installed;
    /// only the restart PUT is gated — whether supernova also gates status reads
    /// after the install is not knowable here, so the fake doesn't.
    restart_bearer: Option<&'static str>,
}

impl Device {
    fn new(reset_kind: Option<&'static str>) -> Self {
        Self {
            reset_kind,
            node_boot: Arc::new(AtomicU32::new(1)),
            restarts: Arc::new(AtomicU32::new(0)),
            restarted: Arc::new(AtomicBool::new(false)),
            goes_away: true,
            seen: Arc::new(Mutex::new(Vec::new())),
            phase: Arc::new(Mutex::new("prepare")),
            restart_bearer: None,
        }
    }

    /// The same node, answering on another base that stays up.
    fn other_base(&self) -> Self {
        Self {
            goes_away: false,
            seen: Arc::new(Mutex::new(Vec::new())),
            ..self.clone()
        }
    }
}

async fn record_or_drop(State(d): State<Device>, req: Request, next: Next) -> Response {
    if d.goes_away && d.restarted.load(Ordering::SeqCst) {
        // Unwinds this connection's task, so hyper drops the socket with no
        // reply — a connect-level failure to the client, as a dead base gives.
        panic!("simulated base gone after the node restart: connection dropped");
    }
    d.seen
        .lock()
        .unwrap()
        .push(format!("{} {}", req.method(), req.uri().path()));
    next.run(req).await
}

async fn components() -> Json<Value> {
    Json(json!({"items": [{"id": "hsm", "name": "HSM", "type": "hsm"}]}))
}

async fn update_mode(State(d): State<Device>) -> Json<Value> {
    let mut mode = json!({"update_mode": "singleshot", "supports_rollback": false});
    if let Some(kind) = d.reset_kind {
        mode["reset_kind"] = json!(kind);
    }
    Json(json!({"did": null, "value": mode}))
}

async fn open_update() -> (StatusCode, Json<Value>) {
    let base = "/vehicle/v1/components/hsm/updates/u1";
    (
        StatusCode::CREATED,
        Json(json!({
            "update_id": "u1",
            "href": base,
            "bulk_data_href": format!("{base}/bulk-data"),
            "executions_href": format!("{base}/executions"),
        })),
    )
}

async fn upload_part(Path((id, part)): Path<(String, String)>) -> Json<Value> {
    Json(json!({
        "part_id": part,
        "size": 0,
        "sha256": "",
        "href": format!("/vehicle/v1/components/hsm/updates/{id}/bulk-data/{part}"),
    }))
}

async fn prepare(State(d): State<Device>) -> StatusCode {
    *d.phase.lock().unwrap() = "prepare";
    StatusCode::ACCEPTED
}

async fn execute(State(d): State<Device>) -> StatusCode {
    *d.phase.lock().unwrap() = "execute";
    StatusCode::ACCEPTED
}

/// Singleshot: each verb completes at once, execute without awaiting a verdict.
async fn update_status(State(d): State<Device>) -> Json<Value> {
    Json(json!({"phase": *d.phase.lock().unwrap(), "status": "completed"}))
}

async fn component_status(State(d): State<Device>) -> Json<Value> {
    let boot = d.node_boot.load(Ordering::SeqCst);
    Json(json!({"status": "ready", "x-runtime": {"node_boot_id": format!("node-{boot}")}}))
}

async fn node_restart(State(d): State<Device>, headers: HeaderMap) -> Response {
    if let Some(want) = d.restart_bearer {
        let got = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
        if got != Some(&format!("Bearer {want}")) {
            let body = json!({
                "error_code": "insufficient-access-rights",
                "message": "missing or malformed bearer token",
            });
            return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
        }
    }
    d.restarts.fetch_add(1, Ordering::SeqCst);
    d.node_boot.fetch_add(1, Ordering::SeqCst);
    d.restarted.store(true, Ordering::SeqCst);
    StatusCode::ACCEPTED.into_response()
}

async fn boot_id(State(d): State<Device>) -> String {
    format!("\"boot-{}\"", d.node_boot.load(Ordering::SeqCst))
}

async fn ecu_id() -> &'static str {
    "ecu-thumbprint"
}

async fn serve(d: Device) -> TestServer {
    let hsm = "/vehicle/v1/components/hsm";
    let router = Router::new()
        .route("/vehicle/v1/components", get(components))
        .route(&format!("{hsm}/data/x-ota-update-mode"), get(update_mode))
        .route(&format!("{hsm}/updates"), post(open_update))
        .route(
            &format!("{hsm}/updates/{{id}}/bulk-data/{{part}}"),
            put(upload_part),
        )
        .route(&format!("{hsm}/updates/{{id}}/prepare"), put(prepare))
        .route(&format!("{hsm}/updates/{{id}}/execute"), put(execute))
        .route(&format!("{hsm}/updates/{{id}}/status"), get(update_status))
        .route(&format!("{hsm}/status"), get(component_status))
        .route(&format!("{hsm}/x-ecu-id"), get(ecu_id))
        .route("/vehicle/v1/status/restart", put(node_restart))
        .route("/vehicle/v1/status/x-boot-id", get(boot_id))
        .layer(middleware::from_fn_with_state(d.clone(), record_or_drop))
        .with_state(d);
    TestServer::start(router).await.expect("SOVD test server")
}

/// `before` until the node restart was issued, `after` from then on — where
/// the device answers, as the caller knows it.
struct MovesOnRestart {
    restarted: Arc<AtomicBool>,
    before: String,
    after: String,
    calls: Arc<AtomicU32>,
}

impl MovesOnRestart {
    fn new(dev: &Device, before: &TestServer, after: &TestServer) -> Self {
        Self {
            restarted: dev.restarted.clone(),
            before: before.base_url(),
            after: after.base_url(),
            calls: Arc::new(AtomicU32::new(0)),
        }
    }
}

#[async_trait]
impl BaseResolver for MovesOnRestart {
    async fn resolve(&self) -> Option<String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Some(if self.restarted.load(Ordering::SeqCst) {
            self.after.clone()
        } else {
            self.before.clone()
        })
    }
}

/// The engine only needs a well-formed COSE_Key; the opaque keystore never
/// validates against it.
fn dummy_trust_anchor() -> Vec<u8> {
    let mut key = vec![0xA3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20];
    key.extend_from_slice(&[0u8; 32]);
    key
}

#[tokio::test]
async fn keystore_requiring_ecu_reset_restarts_the_node_and_follows_the_device() {
    let dev = Device::new(Some("requires_ecu_reset"));
    let a = serve(dev.clone()).await;
    let b = serve(dev.other_base()).await;

    let result = flash_keystore_with_resolver(
        &a.base_url(),
        b"opaque keystore suit".to_vec(),
        dummy_trust_anchor(),
        RigToken::fixed(String::new()),
        false,
        None,
        Arc::new(MovesOnRestart::new(&dev, &a, &b)),
    )
    .await
    .expect("keystore installed and the node restart witnessed on the new base");

    assert_eq!(
        dev.restarts.load(Ordering::SeqCst),
        1,
        "exactly one node restart"
    );
    assert_eq!(
        result.base_url,
        b.base_url(),
        "the caller learns the new base"
    );
    assert_eq!(result.components.len(), 1);
    assert_eq!(result.components[0].entity, "hsm");
    assert_eq!(result.components[0].state, "Committed");
}

#[tokio::test]
async fn keystore_without_a_declared_reset_kind_is_not_restarted() {
    let dev = Device::new(None);
    let a = serve(dev.clone()).await;

    let result = flash_keystore(
        &a.base_url(),
        b"opaque keystore suit".to_vec(),
        dummy_trust_anchor(),
        RigToken::fixed(String::new()),
        false,
        None,
    )
    .await
    .expect("keystore installed");

    assert_eq!(dev.restarts.load(Ordering::SeqCst), 0, "no restart issued");
    assert!(
        !dev.seen
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.ends_with("/restart")),
        "no restart request of any kind"
    );
    assert_eq!(result.base_url, a.base_url());
    assert_eq!(result.components[0].state, "Committed");
}

/// A device whose keystore install is unauthenticated but whose activation
/// restart demands a bearer (the installed anchor now verifies one).
fn anchored_once_installed() -> Device {
    Device {
        restart_bearer: Some("activation-jwt"),
        ..Device::new(Some("requires_ecu_reset"))
    }
}

#[tokio::test]
async fn keystore_activation_with_the_install_token_is_refused() {
    let dev = anchored_once_installed();
    let a = serve(dev.clone()).await;
    let b = serve(dev.other_base()).await;

    let err = flash_keystore_with_resolver(
        &a.base_url(),
        b"opaque keystore suit".to_vec(),
        dummy_trust_anchor(),
        RigToken::fixed(String::new()),
        false,
        None,
        Arc::new(MovesOnRestart::new(&dev, &a, &b)),
    )
    .await
    .expect_err("the empty install token cannot issue the activation restart");

    let msg = err.to_string();
    assert!(msg.contains("401"), "{msg}");
    assert!(msg.contains("bearer token"), "{msg}");
    assert_eq!(dev.restarts.load(Ordering::SeqCst), 0, "restart refused");
}

#[tokio::test]
async fn keystore_activation_uses_the_activation_token() {
    let dev = anchored_once_installed();
    let a = serve(dev.clone()).await;
    let b = serve(dev.other_base()).await;

    let result = flash_keystore_activated(
        &a.base_url(),
        b"opaque keystore suit".to_vec(),
        dummy_trust_anchor(),
        RigToken::fixed(String::new()),
        RigToken::fixed("activation-jwt"),
        false,
        None,
        Arc::new(MovesOnRestart::new(&dev, &a, &b)),
    )
    .await
    .expect("installed unauthenticated, activated with the activation token");

    assert_eq!(
        dev.restarts.load(Ordering::SeqCst),
        1,
        "exactly one node restart"
    );
    assert_eq!(
        result.base_url,
        b.base_url(),
        "the caller learns the new base"
    );
    assert_eq!(result.components[0].state, "Committed");
}

async fn mint(Json(req): Json<Value>) -> Json<Value> {
    let boot = req["boot_id"].as_str().unwrap_or_default();
    Json(json!({"token": format!("tok-{boot}"), "expires_at": "never"}))
}

#[tokio::test]
async fn minting_token_follows_the_device_to_a_new_base() {
    let minter = TestServer::start(Router::new().route("/mint", post(mint)))
        .await
        .expect("minter");
    let dev = Device::new(None);
    let a = serve(dev.clone()).await;
    let b = serve(dev.other_base()).await;
    let resolver = Arc::new(MovesOnRestart::new(&dev, &a, &b));
    let calls = resolver.calls.clone();
    let token = RigToken::minting(minter.base_url(), "op", a.base_url(), None, false, None)
        .with_base_resolver(resolver);

    assert_eq!(token.token("hsm").await.expect("minted on A"), "tok-boot-1");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a live base is not re-resolved"
    );

    // The node restarts: A goes away, B answers with the rotated boot.
    dev.node_boot.fetch_add(1, Ordering::SeqCst);
    dev.restarted.store(true, Ordering::SeqCst);
    assert_eq!(
        token.token("hsm").await.expect("re-resolved to B"),
        "tok-boot-2"
    );
    assert_eq!(
        token.token("hsm").await.expect("B remembered"),
        "tok-boot-2"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "re-resolved once, then the remembered base is read directly"
    );
}

#[tokio::test]
async fn probing_resolver_answers_with_the_live_base_or_nowhere() {
    let a = serve(Device::new(None)).await;
    let live = ProbingBaseResolver::new(&a.base_url(), false, None);
    assert_eq!(live.resolve().await, Some(a.base_url()));

    // Nothing listens on port 1 on either scheme.
    let dead = ProbingBaseResolver::new("http://127.0.0.1:1", false, None);
    assert_eq!(dead.resolve().await, None);
}

#[tokio::test]
async fn probing_resolver_swaps_the_scheme() {
    let a = serve(Device::new(None)).await;
    let https = a.base_url().replacen("http://", "https://", 1);
    let swapped = ProbingBaseResolver::new(&https, false, None);
    assert_eq!(swapped.resolve().await, Some(a.base_url()));
}
