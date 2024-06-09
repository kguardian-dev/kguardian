use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("SerializationError: {0}")]
    SerializationError(#[source] serde_json::Error),

    #[error("Kubernetes reported error: {source}")]
    KubeError {
        #[from]
        source: kube::Error,
    },
    #[error("Kubernetes Watcher runtime error: {source}")]
    KubeWatcherError {
        #[from]
        source: kube::runtime::watcher::Error,
    },
    #[error("Finalizer Error: {0}")]
    // NB: awkward type because finalizer::Error embeds the reconciler error (which is this)
    // so boxing this error to break cycles
    FinalizerError(#[source] Box<kube::runtime::finalizer::Error<Error>>),

    #[error("Ebpf Error: {source}")]
    BpfError {
        #[from]
        source: aya::EbpfError,
    },

    #[error("Ebpf Program Load Error: {source}")]
    BpfProgramError {
        #[from]
        source: aya::programs::ProgramError,
    },
    #[error("Ebpf Map  Error: {source}")]
    BpfMapError {
        #[from]
        source: aya::maps::MapError,
    },
    #[error("IO Error: {source}")]
    IOError {
        #[from]
        source: std::io::Error,
    },
    #[error("Perf Buffer Error: {source}")]
    PerfBufferError {
        #[from]
        source: aya::maps::perf::PerfBufferError,
    },

    #[error("Reqwest Error: {source}")]
    ReqwestError {
        #[from]
        source: reqwest::Error,
    },

    #[error("IllegalDocument")]
    IllegalDocument,

    #[error("CustomError {0}")]
    CustomError(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn metric_label(&self) -> String {
        format!("{self:?}").to_lowercase()
    }
}

pub use Error::*;

/// Log and trace integrations
pub mod telemetry;
pub use crate::telemetry::*;

pub mod trace;
pub mod container;
pub mod model;

pub use crate::model::*;

pub mod api;
pub(crate) use crate::api::api_post_call;
pub mod watch;
pub use watch::*;
