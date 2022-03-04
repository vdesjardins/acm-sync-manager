#![allow(unused_imports, unused_variables)]
use std::{net::SocketAddr, sync::Arc};

pub use acm_sync_manager::*;

use acm_sync_manager::manager::State;
use axum::{
    extract::{self, Extension},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use prometheus::{Encoder, TextEncoder};
use serde_json::Value;
use tokio::signal::unix::{signal, SignalKind};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{prelude::*, EnvFilter, Registry};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// prometheus metric bind address
    #[clap(long, default_value = "127.0.0.1:8081")]
    metrics_bind_address: SocketAddr,

    /// health probe bind address
    #[clap(long, default_value = "0.0.0.0:8080")]
    health_probe_bind_address: SocketAddr,

    /// owner tag value set on ACM certificate
    #[clap(long, default_value = "acm-sync-manager")]
    owner_tag_value: String,
}

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
    let args = Args::parse();

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
    let (manager, drainer) = Manager::new(args.owner_tag_value).await;

    // Start web server
    info!("starting metrics server on {}", args.metrics_bind_address);
    let app_metrics = Router::new()
        .route("/metrics", get(metrics))
        .layer(extract::Extension(manager.clone()))
        .layer(TraceLayer::new_for_http());

    let mut shutdown = signal(SignalKind::terminate()).expect("could not monitor for SIGTERM");
    let server_metrics = axum::Server::bind(&args.metrics_bind_address)
        .serve(app_metrics.into_make_service())
        .with_graceful_shutdown(async move {
            shutdown.recv().await;
        });

    info!("starting server on {}", args.health_probe_bind_address);
    let app = Router::new()
        .route("/", get(index))
        .layer(extract::Extension(manager.clone()))
        .layer(TraceLayer::new_for_http())
        // Reminder: routes added *after* TraceLayer are not subject to its logging behavior
        .route("/healthz", get(health))
        .route("/readyz", get(health));

    let mut shutdown = signal(SignalKind::terminate()).expect("could not monitor for SIGTERM");
    let server_controller = axum::Server::bind(&args.health_probe_bind_address)
        .serve(app.into_make_service())
        .with_graceful_shutdown(async move {
            shutdown.recv().await;
        });

    tokio::select! {
        _ = drainer => warn!("controller drained"),
        _ = server_metrics => info!("metrics exited"),
        _ = server_controller => info!("controller exited"),
    }
    Ok(())
}
