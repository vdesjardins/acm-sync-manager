#![allow(unused_imports, unused_variables)]
use std::{net::SocketAddr, sync::Arc};

pub use acm_sync_manager::*;

use acm_sync_manager::manager::State;
use axum::{
    extract::Extension,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    AddExtensionLayer, Json, Router,
};
use prometheus::{Encoder, TextEncoder};
use serde_json::Value;
use tokio::signal::unix::{signal, SignalKind};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{prelude::*, EnvFilter, Registry};

async fn metrics(state: Extension<Manager>) -> (StatusCode, String) {
    let state_metrics = state.metrics();
    let encoder = TextEncoder::new();
    let mut buffer = vec![];
    encoder.encode(&state_metrics, &mut buffer).unwrap();
    (StatusCode::OK, String::from_utf8(buffer).unwrap())
}

async fn health() -> (StatusCode, Json<&'static str>) {
    (StatusCode::OK, Json("healthy"))
}

async fn index(state: Extension<Manager>) -> (StatusCode, Json<State>) {
    (StatusCode::OK, Json(state.state().await))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Setup tracing layers
    #[cfg(feature = "telemetry")]
    let telemetry = tracing_opentelemetry::layer().with_tracer(telemetry::init_tracer().await);
    let logger = tracing_subscriber::fmt::layer().json();
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    // Decide on layers
    #[cfg(feature = "telemetry")]
    let collector = Registry::default()
        .with(telemetry)
        .with(logger)
        .with(env_filter);
    #[cfg(not(feature = "telemetry"))]
    let collector = Registry::default().with(logger).with(env_filter);

    // Initialize tracing
    tracing::subscriber::set_global_default(collector).unwrap();

    // Start kubernetes controller
    let (manager, drainer) = Manager::new().await;

    // Start web server
    info!(message = "starting server on 0.0.0:8080");

    let app = Router::new()
        .route("/", get(index))
        .route("/metrics", get(metrics))
        .layer(AddExtensionLayer::new(manager.clone()))
        .layer(TraceLayer::new_for_http())
        // Reminder: routes added *after* TraceLayer are not subject to its logging behavior
        .route("/healthz", get(health))
        .route("/readyz", get(health));

    let mut shutdown = signal(SignalKind::terminate()).expect("could not monitor for SIGTERM");
    let server_axum = axum::Server::bind(&SocketAddr::from(([0, 0, 0, 0], 8080)))
        .serve(app.into_make_service())
        .with_graceful_shutdown(async move {
            shutdown.recv().await;
        });

    tokio::select! {
        _ = drainer => warn!("controller drained"),
        _ = server_axum => info!("actix exited"),
    }
    Ok(())
}
