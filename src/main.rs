#![allow(unused_imports, unused_variables)]
use std::{net::SocketAddr, sync::Arc};

pub use acm_sync_manager::*;

use acm_sync_manager::manager::State;
pub use acm_sync_manager::telemetry;
use actix_web::{
    get, middleware, web::Data, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
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

#[get("/metrics")]
async fn metrics(c: Data<State>, _req: HttpRequest) -> impl Responder {
    let metrics = c.metrics();
    HttpResponse::Ok()
        .content_type("application/openmetrics-text; version=1.0.0; charset=utf-8")
        .body(metrics)
}

#[get("/health")]
async fn health(_: HttpRequest) -> impl Responder {
    HttpResponse::Ok().json("healthy")
}

#[get("/")]
async fn index(c: Data<State>, _req: HttpRequest) -> impl Responder {
    let d = c.diagnostics().await;
    HttpResponse::Ok().json(&d)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    telemetry::init().await;

    let mut state = State::default();
    state.set_owner_tag_value(&args.owner_tag_value);

    // Start kubernetes controller
    let controller = Manager::run(state.clone());

    // Start web server
    let server = HttpServer::new(move || {
        App::new()
            .app_data(Data::new(state.clone()))
            .wrap(middleware::Logger::default().exclude("/health"))
            .service(index)
            .service(health)
            .service(metrics)
    })
    // TODO: use arg ports for health and metrics
    .bind("0.0.0.0:8080")?
    .shutdown_timeout(5);

    // Both runtimes implements graceful shutdown, so poll until both are done
    tokio::join!(controller, server.run()).1?;

    Ok(())
}
