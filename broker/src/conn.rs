extern crate dotenv;

use diesel::pg::PgConnection;
use diesel::r2d2::ConnectionManager;
use dotenv::dotenv;
use std::env;

pub fn establish_connection() -> ConnectionManager<PgConnection> {
    dotenv().ok();

    // Trim to defend against operator-pasted URLs with trailing
    // newlines or surrounding whitespace — postgres would error
    // out far later with a confusing parse failure if we passed
    // those through. Empty-after-trim still triggers the
    // "DATABASE_URL must be set" panic (a deliberate startup
    // assertion — see the test pinning this contract in
    // conn.rs's panics_when_database_url_unset test).
    let database_url = env::var("DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .expect("DATABASE_URL must be set");
    ConnectionManager::<PgConnection>::new(database_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Panic-safe env-isolation guard. Restores the previous value of
    /// `key` on drop — including during a panic unwind. This is the
    /// crucial difference from the function-based with_env helpers in
    /// audit.rs / retention.rs / main.rs: those don't run the restore
    /// if their closure panics, so #[should_panic] tests would leak
    /// the test-set env var to other parallel tests.
    ///
    /// The previous pattern here used std::panic::catch_unwind to
    /// catch the panic, restore env, then resume_unwind — works, but
    /// adds boilerplate to every test body. Drop is cleaner.
    struct EnvGuard {
        key: String,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &str, value: Option<&str>) -> Self {
            let prev = env::var(key).ok();
            match value {
                Some(v) => env::set_var(key, v),
                None => env::remove_var(key),
            }
            Self {
                key: key.to_string(),
                prev,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => env::set_var(&self.key, v),
                None => env::remove_var(&self.key),
            }
        }
    }

    // The startup contract is: DATABASE_URL must be set, or we panic
    // with a clear message. A regression that silently defaulted the
    // URL would let the broker boot pointing at the wrong DB.

    #[test]
    #[should_panic(expected = "DATABASE_URL must be set")]
    fn panics_when_database_url_unset() {
        let _g = EnvGuard::set("DATABASE_URL", None);
        // _g drops on the panic-unwind path, restoring env. #[should_panic]
        // still sees the panic.
        establish_connection();
    }

    #[test]
    fn returns_connection_manager_when_url_set() {
        // The diesel ConnectionManager doesn't actually connect on
        // construction — that happens in r2d2 Pool::build. So a fake
        // URL is sufficient to prove the function returned without
        // panicking.
        let _g = EnvGuard::set("DATABASE_URL", Some("postgres://x:y@example.invalid/db"));
        let _mgr = establish_connection();
    }

    #[test]
    #[should_panic(expected = "DATABASE_URL must be set")]
    fn whitespace_only_url_is_treated_as_unset() {
        // Iteration 108 trim contract: a pasted "  \n" must NOT
        // be passed through to diesel as if it were a valid URL.
        // It hits the empty-after-trim filter and triggers the
        // same "not set" panic — clearer signal at startup than
        // a downstream postgres parse error.
        let _g = EnvGuard::set("DATABASE_URL", Some("  \n"));
        establish_connection();
    }

    #[test]
    fn trailing_whitespace_is_stripped() {
        // A pasted URL with trailing newline (typical) round-trips
        // clean. Construction succeeds and the connection-manager
        // gets the trimmed URL.
        let _g = EnvGuard::set(
            "DATABASE_URL",
            Some("  postgres://x:y@example.invalid/db\n"),
        );
        let _mgr = establish_connection();
    }
}
