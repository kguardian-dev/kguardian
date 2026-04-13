extern crate dotenv;

use diesel::pg::PgConnection;
use diesel::r2d2::ConnectionManager;
use dotenv::dotenv;
use std::env;

/// Returns a connection manager for PostgreSQL, reading `DATABASE_URL` from the environment.
/// Returns an error string if `DATABASE_URL` is not set.
pub fn establish_connection() -> Result<ConnectionManager<PgConnection>, String> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set".to_string())?;
    Ok(ConnectionManager::<PgConnection>::new(database_url))
}
