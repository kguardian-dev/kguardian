use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
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

    #[error("IO Error: {source}")]
    IOError {
        #[from]
        source: std::io::Error,
    },

    #[error("IllegalDocument")]
    IllegalDocument,

    #[error("ApiError - {0}")]
    ApiError(String),

    #[error("Tokio Join error: {source}")]
    JoinError {
        #[from]
        source: tokio::task::JoinError,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn metric_label(&self) -> String {
        format!("{self:?}").to_lowercase()
    }
}
