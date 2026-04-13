use actix_web::error::BlockingError;
use actix_web::http::StatusCode;
use diesel::result::DatabaseErrorKind;

/// All errors possible to occur during reconciliation
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error in user input or typically missing fields.
    #[error("Invalid User Input: {0}")]
    UserInputError(String),

    /// Any error originating from the `diesel` crate
    #[error("DieselResult Error: {source}")]
    SQLError {
        #[from]
        source: diesel::result::Error,
    },

    /// Any error originating from the `actix` blocking thread pool
    #[error("BlockingError: {source}")]
    BlockingError {
        #[from]
        source: BlockingError,
    },

    /// Any error originating from the `r2d2` connection pool
    #[error("Connection pool error: {source}")]
    R2D2Error {
        #[from]
        source: r2d2::Error,
    },
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::UserInputError(s)
    }
}

impl actix_web::ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Error::UserInputError(_) => StatusCode::BAD_REQUEST,
            Error::SQLError { source } => match source {
                diesel::result::Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
                    StatusCode::CONFLICT
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            Error::R2D2Error { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Error::BlockingError { .. } => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse {
        let status = self.status_code();
        let body = serde_json::json!({ "error": self.to_string() });
        actix_web::HttpResponse::build(status).json(body)
    }
}
