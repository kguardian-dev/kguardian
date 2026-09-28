use actix_web::error::BlockingError;
use diesel::r2d2;

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
    /// Any error originating from the `actix` crate
    #[error("Actix Web Error: {source}")]
    ActixWebError {
        #[from]
        source: actix_web::Error,
    },

    /// Any error originating from the `kube-rs` crate
    #[error("BlockingError: {source}")]
    BlockingError {
        #[from]
        source: BlockingError,
    },
    /// Any error originating from the `diesel` crate
    #[error("SQL Error: {source}")]
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

/// `Retry-After` on the 503 for a statement Postgres cancelled. Longer than
/// the read-budget shed's 1 s: the statement ran to the statement timeout
/// under load, and a retry one second later mostly re-runs it.
pub const TRANSIENT_RETRY_AFTER_SECS: u64 = 5;

/// True for a database error a later retry can succeed on: a statement
/// Postgres cancelled (statement timeout, lock timeout, user cancel), a
/// deadlock or a serialization failure. Walks the `source()` chain so a
/// wrapped diesel error is found too.
pub fn is_transient_db_error(err: &(dyn std::error::Error + 'static)) -> bool {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(DieselError::DatabaseError(kind, info)) = e.downcast_ref::<DieselError>() {
            return match kind {
                DatabaseErrorKind::SerializationFailure => true,
                // diesel does not expose the SQLSTATE: 57014, 55P03 and 40P01
                // arrive as Unknown, told apart only by Postgres's message.
                DatabaseErrorKind::Unknown => {
                    let m = info.message();
                    m.starts_with("canceling statement due to") || m == "deadlock detected"
                }
                _ => false,
            };
        }
        cur = e.source();
    }
    false
}

/// The `actix_web::Error` for a failed database read or write: a 503 with
/// `Retry-After` when [`is_transient_db_error`], otherwise the same 500
/// `ErrorInternalServerError` produced before, body included.
pub fn db_error_response<E>(err: E) -> actix_web::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let err: Box<dyn std::error::Error + Send + Sync> = err.into();
    if is_transient_db_error(&*err) {
        let resp = actix_web::HttpResponse::ServiceUnavailable()
            .insert_header(("Retry-After", TRANSIENT_RETRY_AFTER_SECS.to_string()))
            .body(format!(
                "database busy: {err}; retry after {TRANSIENT_RETRY_AFTER_SECS} s"
            ));
        return actix_web::error::InternalError::from_response(err, resp).into();
    }
    actix_web::error::ErrorInternalServerError(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;
    use diesel::result::{DatabaseErrorKind, Error as DieselError};

    type DbError = Box<dyn std::error::Error + Send + Sync>;

    fn pg(kind: DatabaseErrorKind, message: &str) -> DbError {
        Box::new(DieselError::DatabaseError(
            kind,
            Box::new(message.to_string()),
        ))
    }

    /// Status, `Retry-After` and body of the one response actix renders for
    /// `err` (a response built by `from_response` is handed out once).
    async fn rendered(err: actix_web::Error) -> (StatusCode, Option<String>, String) {
        let resp = err.error_response();
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let b = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        (status, retry_after, String::from_utf8(b.to_vec()).unwrap())
    }

    #[actix_web::test]
    async fn statement_timeout_is_a_503_with_retry_after() {
        let err = db_error_response(pg(
            DatabaseErrorKind::Unknown,
            "canceling statement due to statement timeout",
        ));
        assert_eq!(
            err.as_response_error().status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let (status, retry_after, text) = rendered(err).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            retry_after.as_deref(),
            Some(TRANSIENT_RETRY_AFTER_SECS.to_string().as_str())
        );
        assert!(
            text.contains("canceling statement due to statement timeout"),
            "the client still sees why: {text}"
        );
        assert!(text.contains("retry after 5 s"), "{text}");
    }

    #[actix_web::test]
    async fn cancel_lock_and_serialization_class_errors_are_transient() {
        for (kind, message) in [
            (
                DatabaseErrorKind::Unknown,
                "canceling statement due to lock timeout",
            ),
            (
                DatabaseErrorKind::Unknown,
                "canceling statement due to user request",
            ),
            (DatabaseErrorKind::Unknown, "deadlock detected"),
            (
                DatabaseErrorKind::SerializationFailure,
                "could not serialize access",
            ),
        ] {
            let (status, retry_after, _) = rendered(db_error_response(pg(kind, message))).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{message}");
            assert!(retry_after.is_some(), "{message}");
        }
    }

    #[actix_web::test]
    async fn every_other_error_stays_the_same_500() {
        let cases: Vec<(DbError, &str)> = vec![
            (
                pg(DatabaseErrorKind::UniqueViolation, "duplicate key value"),
                "duplicate key value",
            ),
            (
                pg(
                    DatabaseErrorKind::Unknown,
                    "relation \"nope\" does not exist",
                ),
                "relation \"nope\" does not exist",
            ),
            (Box::new(DieselError::NotFound), "Record not found"),
            ("plain text failure".into(), "plain text failure"),
        ];
        for (raw, shown) in cases {
            let before = rendered(actix_web::error::ErrorInternalServerError(
                shown.to_string(),
            ))
            .await;
            let after = rendered(db_error_response(raw)).await;
            assert_eq!(after.0, StatusCode::INTERNAL_SERVER_ERROR, "{shown}");
            assert!(after.1.is_none(), "{shown}: no Retry-After on a 500");
            // Byte-identical to what the handlers produced before this helper.
            assert_eq!(after.2, before.2, "{shown}");
        }
    }

    #[test]
    fn a_pool_timeout_is_not_transient() {
        // `tests/read_budget_endpoints.rs` tells a budget shed (503) from a
        // request that reached an unreachable pool (500); that contrast must
        // hold.
        let pool_err: DbError = Box::new(diesel::r2d2::Error::ConnectionError(
            diesel::ConnectionError::BadConnection("refused".into()),
        ));
        assert!(!is_transient_db_error(&*pool_err));
    }

    #[test]
    fn a_wrapped_diesel_error_is_found_through_its_source_chain() {
        #[derive(Debug)]
        struct Wrapped(DieselError);
        impl std::fmt::Display for Wrapped {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "delete: {}", self.0)
            }
        }
        impl std::error::Error for Wrapped {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let inner = DieselError::DatabaseError(
            DatabaseErrorKind::Unknown,
            Box::new("canceling statement due to statement timeout".to_string()),
        );
        let wrapped: DbError = Box::new(Wrapped(inner));
        assert!(is_transient_db_error(&*wrapped));
    }
}
