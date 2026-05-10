extern crate dotenv;

use diesel::pg::PgConnection;
use diesel::r2d2::ConnectionManager;
use dotenv::dotenv;
use std::env;

pub fn establish_connection() -> ConnectionManager<PgConnection> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    ConnectionManager::<PgConnection>::new(database_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The startup contract is: DATABASE_URL must be set, or we panic
    // with a clear message. A regression that silently defaulted the
    // URL would let the broker boot pointing at the wrong DB.

    #[test]
    #[should_panic(expected = "DATABASE_URL must be set")]
    fn panics_when_database_url_unset() {
        // Save and restore the env var to keep this test isolated from
        // other tests that may set it.
        let prev = env::var("DATABASE_URL").ok();
        env::remove_var("DATABASE_URL");

        // Wrap the call so the env always restores even on panic.
        let result = std::panic::catch_unwind(|| establish_connection());

        match prev {
            Some(v) => env::set_var("DATABASE_URL", v),
            None => env::remove_var("DATABASE_URL"),
        }

        // Re-raise the panic (or its absence) so #[should_panic] can
        // observe it. catch_unwind returns Err on panic.
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn returns_connection_manager_when_url_set() {
        // The diesel ConnectionManager doesn't actually connect on
        // construction — that happens in r2d2 Pool::build. So a fake
        // URL is sufficient to prove the function returned without
        // panicking.
        let prev = env::var("DATABASE_URL").ok();
        env::set_var("DATABASE_URL", "postgres://x:y@example.invalid/db");
        let _mgr = establish_connection();
        match prev {
            Some(v) => env::set_var("DATABASE_URL", v),
            None => env::remove_var("DATABASE_URL"),
        }
    }
}
