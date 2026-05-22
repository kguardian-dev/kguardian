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

    #[error("Custom error: {0}")]
    Custom(String),

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

#[cfg(test)]
mod tests {
    use super::*;

    // metric_label is intended for cardinality-stable metric labelling.
    // The lowercase Debug-derived form is consumed by Prometheus
    // dashboards / alert rules; even a small drift (case change,
    // variant rename) breaks downstream filters silently. Tests below
    // pin the contract.

    #[test]
    fn metric_label_for_string_variants() {
        // The string-bearing variants render as lowercase variant
        // name + the embedded payload.
        assert_eq!(
            Error::ApiError("Foo".into()).metric_label(),
            "apierror(\"foo\")"
        );
        assert_eq!(
            Error::Custom("Bar".into()).metric_label(),
            "custom(\"bar\")"
        );
    }

    #[test]
    fn metric_label_for_unit_variant() {
        assert_eq!(Error::IllegalDocument.metric_label(), "illegaldocument");
    }

    #[test]
    fn metric_label_is_lowercase() {
        // Whatever the variant — the contract is "always lowercase",
        // so any future variant added without re-checking this still
        // satisfies the cardinality-stable expectation.
        for e in [
            Error::IllegalDocument,
            Error::Custom("MixedCase".into()),
            Error::ApiError("UPPERCASE".into()),
        ] {
            let label = e.metric_label();
            assert_eq!(
                label,
                label.to_lowercase(),
                "label not all-lowercase: {label}"
            );
        }
    }
}
