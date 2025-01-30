#![warn(rust_2018_idioms)]
#![allow(unused_imports)]
#![allow(clippy::disallowed_names)]
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Kube Api Error: {0}")]
    KubeError(#[source] kube::Error),

    #[error("SerializationError: {0}")]
    SerializationError(#[source] serde_json::Error),

    #[error("ACMError: {0}")]
    SdkError(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("NotOwnerError")]
    NotOwnerError,

    #[error("Finalizer Error: {0}")]
    // NB: awkward type because finalizer::Error embeds the reconciler error (which is this)
    // so boxing this error to break cycles
    FinalizerError(#[source] Box<kube::runtime::finalizer::Error<Error>>),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn metric_label(&self) -> String {
        format!("{self:?}").to_lowercase()
    }
}

/// State machinery for kube
pub mod manager;
pub use manager::Manager;

/// Metrics
mod metrics;

/// Log and trace integrations
pub mod telemetry;
pub use metrics::Metrics;

/// aws acm
pub mod acm;
