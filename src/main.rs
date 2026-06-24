//! ce-watch — the operator's security console for CE.
//!
//! A light axum service that lives beside the relay. It does two things:
//!
//!   1. Receives flag events from the hub's abuse detector over `POST /ingest`, gated by a shared
//!      secret header, and appends them to a durable, bounded, append-only log.
//!   2. Serves an admin-only single-page "security console" (gated by a separate admin token) that
//!      renders the flag log as a structured, filterable table with an unseen-count indicator.
//!
//! It deliberately holds NO libp2p / wasmtime / heavy deps — it is purely an HTTP sink + dashboard.
//! The node and hub stay the source of truth for the mesh; ce-watch is the operator's read model.

mod store;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::CorsLayer;

use store::{FlagEvent, Store};

const CONSOLE_HTML: &str = include_str!("console.html");

#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    ingest_token: Arc<Option<String>>,
    admin_token: Arc<Option<String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ce_watch=info,tower_http=warn".into()),
        )
        .init();

    let data_dir = store::default_data_dir();
    let store = Arc::new(Store::open(data_dir.clone())?);

    let ingest_token = env_token("CE_WATCH_INGEST_TOKEN");
    let admin_token = env_token("CE_WATCH_ADMIN_TOKEN");

    if ingest_token.is_none() {
        tracing::warn!("CE_WATCH_INGEST_TOKEN is unset — /ingest will reject all requests");
    }
    if admin_token.is_none() {
        tracing::warn!("CE_WATCH_ADMIN_TOKEN is unset — admin console will reject all requests");
    }

    let state = AppState {
        store,
        ingest_token: Arc::new(ingest_token),
        admin_token: Arc::new(admin_token),
    };

    let app = router(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8971);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%addr, data_dir = %data_dir.display(), "ce-watch listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_console))
        .route("/admin", get(serve_console))
        .route("/health", get(|| async { "ok" }))
        .route("/ingest", post(ingest))
        .route("/admin/flags", get(admin_flags))
        .route("/admin/unseen", get(admin_unseen))
        .route("/admin/seen", post(admin_seen))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

fn env_token(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Constant-ish header compare. Returns true only when a token is configured AND matches.
fn header_matches(headers: &HeaderMap, name: &str, expected: &Option<String>) -> bool {
    let expected = match expected {
        Some(e) => e,
        None => return false,
    };
    match headers.get(name).and_then(|v| v.to_str().ok()) {
        Some(got) => got == expected.as_str(),
        None => false,
    }
}

async fn serve_console() -> impl IntoResponse {
    // The HTML itself is public; the data behind it is token-gated. The page prompts for the admin
    // token and stores it in localStorage, sending it as x-ce-admin on every data call.
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::HeaderName::from_static("x-robots-tag"), "noindex"),
        ],
        Html(CONSOLE_HTML),
    )
}

async fn ingest(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(event): Json<FlagEvent>,
) -> impl IntoResponse {
    if !header_matches(&headers, "x-ce-watch-token", &st.ingest_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "bad token"}))).into_response();
    }
    match st.store.append(event) {
        Ok(seq) => (StatusCode::OK, Json(json!({"ok": true, "seq": seq}))).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "append failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "store"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct FlagsQuery {
    since: Option<u64>,
    heuristic: Option<String>,
    severity: Option<String>,
    node: Option<String>,
    limit: Option<usize>,
}

async fn admin_flags(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FlagsQuery>,
) -> impl IntoResponse {
    if !header_matches(&headers, "x-ce-admin", &st.admin_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response();
    }
    let limit = q.limit.unwrap_or(1000).min(5000);
    let flags = st.store.query(
        q.since,
        q.heuristic.as_deref().filter(|s| !s.is_empty()),
        q.severity.as_deref().filter(|s| !s.is_empty()),
        q.node.as_deref().filter(|s| !s.is_empty()),
        limit,
    );
    (
        StatusCode::OK,
        Json(json!({
            "head": st.store.head_seq(),
            "unseen": st.store.unseen(),
            "flags": flags,
        })),
    )
        .into_response()
}

async fn admin_unseen(State(st): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !header_matches(&headers, "x-ce-admin", &st.admin_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response();
    }
    (StatusCode::OK, Json(json!({"unseen": st.store.unseen(), "head": st.store.head_seq()}))).into_response()
}

async fn admin_seen(State(st): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !header_matches(&headers, "x-ce-admin", &st.admin_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response();
    }
    st.store.mark_seen();
    (StatusCode::OK, Json(json!({"ok": true, "unseen": 0}))).into_response()
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // oneshot

    fn temp_dir() -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        d.push(format!("ce-watch-test-{}-{}", std::process::id(), nanos));
        d
    }

    fn state_with(dir: std::path::PathBuf) -> AppState {
        AppState {
            store: Arc::new(Store::open(dir).expect("open store")),
            ingest_token: Arc::new(Some("ingest-secret".to_string())),
            admin_token: Arc::new(Some("admin-secret".to_string())),
        }
    }

    fn sample_flag() -> serde_json::Value {
        json!({
            "ts": 1_700_000_000u64,
            "node_id": "ip:203.0.113.7",
            "ip": "203.0.113.7",
            "heuristic": "H2",
            "reason": "repeat-signature: count_primes x47 in 5m — mining shape",
            "severity": "high",
            "sample": { "func": "count_primes", "endpoint": "/tasks" }
        })
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn ingest_rejects_bad_token() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let req = Request::builder()
            .method("POST")
            .uri("/ingest")
            .header("content-type", "application/json")
            .header("x-ce-watch-token", "WRONG")
            .body(Body::from(sample_flag().to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn ingest_accepts_good_token_and_stores() {
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let app = router(st.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/ingest")
            .header("content-type", "application/json")
            .header("x-ce-watch-token", "ingest-secret")
            .body(Body::from(sample_flag().to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // It is now queryable and the unseen counter incremented.
        assert_eq!(st.store.head_seq(), 1);
        assert_eq!(st.store.unseen(), 1);
        let flags = st.store.query(None, None, None, None, 10);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].event.heuristic, "H2");

        // The line was actually written to disk.
        let log = dir.join("flags.jsonl");
        let contents = std::fs::read_to_string(&log).unwrap();
        assert!(contents.contains("count_primes"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_flags_requires_token() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        // No header → 401.
        let req = Request::builder()
            .uri("/admin/flags")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong header → 401.
        let req = Request::builder()
            .uri("/admin/flags")
            .header("x-ce-admin", "nope")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Correct header → 200.
        let req = Request::builder()
            .uri("/admin/flags")
            .header("x-ce-admin", "admin-secret")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn seen_clears_unseen() {
        let dir = temp_dir();
        let st = state_with(dir.clone());
        for _ in 0..3 {
            let ev: FlagEvent = serde_json::from_value(sample_flag()).unwrap();
            st.store.append(ev).unwrap();
        }
        assert_eq!(st.store.unseen(), 3);

        let app = router(st.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/admin/seen")
            .header("x-ce-admin", "admin-secret")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(st.store.unseen(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn log_survives_restart() {
        let dir = temp_dir();
        {
            let st = state_with(dir.clone());
            for i in 0..5 {
                let mut v = sample_flag();
                v["ts"] = json!(1_700_000_000u64 + i);
                let ev: FlagEvent = serde_json::from_value(v).unwrap();
                st.store.append(ev).unwrap();
            }
            assert_eq!(st.store.head_seq(), 5);
        } // store dropped — simulate process exit

        // Reopen: the durable log is replayed.
        let st2 = state_with(dir.clone());
        assert_eq!(st2.store.head_seq(), 5);
        let flags = st2.store.query(None, None, None, None, 100);
        assert_eq!(flags.len(), 5);
        // Newest-first ordering preserved across restart.
        assert!(flags[0].seq > flags[1].seq);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn filters_apply() {
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let mut a = sample_flag();
        a["heuristic"] = json!("H1");
        a["severity"] = json!("low");
        let mut b = sample_flag();
        b["heuristic"] = json!("H5");
        b["severity"] = json!("high");
        st.store.append(serde_json::from_value(a).unwrap()).unwrap();
        st.store.append(serde_json::from_value(b).unwrap()).unwrap();

        let only_h5 = st.store.query(None, Some("H5"), None, None, 10);
        assert_eq!(only_h5.len(), 1);
        assert_eq!(only_h5[0].event.heuristic, "H5");

        let only_high = st.store.query(None, None, Some("high"), None, 10);
        assert_eq!(only_high.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
