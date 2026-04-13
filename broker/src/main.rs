use std::error::Error;
use std::env;
use std::time::Duration;

use actix_cors::Cors;
use actix_web::{get, web, App, HttpResponse, HttpServer};
use api::{
    add_pod_details, add_pods, add_pods_batch, add_pods_syscalls, add_svc_details,
    establish_connection, get_pod_by_ip, get_pod_by_name, get_pod_details, get_pod_syscall_name,
    get_pod_traffic, get_pod_traffic_name, get_pods_by_node, get_svc_by_ip, get_svc_details,
    mark_pod_dead,
};

use diesel::r2d2;
use telemetry::init_logging;
mod auth;
mod telemetry;

use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use tracing::{error, info, warn};
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./db/migrations");

type DB = diesel::pg::Pg;

fn run_migrations(
    connection: &mut impl MigrationHarness<DB>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    connection.run_pending_migrations(MIGRATIONS)?;
    Ok(())
}

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    init_logging();

    let manager = match establish_connection() {
        Ok(m) => m,
        Err(e) => {
            error!("{}", e);
            std::process::exit(1);
        }
    };

    let max_size = env::var("DB_POOL_MAX_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32u32);

    let pool = match r2d2::Pool::builder()
        .max_size(max_size)
        .min_idle(Some(4))
        .max_lifetime(Some(Duration::from_secs(1800)))
        .build(manager)
    {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to create connection pool: {}", e);
            std::process::exit(1);
        }
    };

    // RUN the migration schema with retries
    let max_retries = 5;
    for attempt in 1..=max_retries {
        match pool.get() {
            Ok(mut conn) => match run_migrations(&mut conn) {
                Ok(()) => {
                    info!("DB setup success");
                    break;
                }
                Err(e) => {
                    if attempt == max_retries {
                        error!("DB migration failed after {} attempts: {}", max_retries, e);
                        std::process::exit(1);
                    }
                    warn!(
                        "DB migration attempt {}/{} failed: {}. Retrying in 2s...",
                        attempt, max_retries, e
                    );
                }
            },
            Err(e) => {
                if attempt == max_retries {
                    error!(
                        "Failed to get DB connection after {} attempts: {}",
                        max_retries, e
                    );
                    std::process::exit(1);
                }
                warn!(
                    "DB connection attempt {}/{} failed: {}. Retrying in 2s...",
                    attempt, max_retries, e
                );
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    HttpServer::new(move || {
        let cors = build_cors();

        App::new()
            .wrap(auth::ApiKeyAuth)
            .wrap(cors)
            .app_data(
                web::JsonConfig::default()
                    .limit(1_048_576),
            )
            .app_data(web::Data::new(pool.clone()))
            .service(add_pods)
            .service(add_pods_batch)
            .service(add_pod_details)
            .service(add_pods_syscalls)
            .service(get_pod_traffic)
            .service(get_pod_details)
            .service(add_svc_details)
            .service(get_pod_by_ip)
            .service(get_pod_by_name)
            .service(get_svc_details)
            .service(get_svc_by_ip)
            .service(get_pod_traffic_name)
            .service(get_pod_syscall_name)
            .service(get_pods_by_node)
            .service(mark_pod_dead)
            .service(health_check)
    })
    .bind(("0.0.0.0", 9090))?
    .run()
    .await
}

/// Build a CORS configuration.
///
/// If `ALLOWED_ORIGINS` is set (comma-separated list), only those origins are allowed.
/// Otherwise, all origins are permitted with a warning.
fn build_cors() -> Cors {
    match env::var("ALLOWED_ORIGINS") {
        Ok(origins) if !origins.is_empty() => {
            let mut cors = Cors::default()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);
            for origin in origins.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                cors = cors.allowed_origin(origin);
            }
            cors
        }
        _ => {
            warn!("ALLOWED_ORIGINS env var is not set; CORS will allow any origin (set ALLOWED_ORIGINS to restrict)");
            Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600)
        }
    }
}

#[get("/health")]
pub async fn health_check(
    pool: web::Data<r2d2::Pool<r2d2::ConnectionManager<diesel::PgConnection>>>,
) -> HttpResponse {
    match pool.get() {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "healthy",
            "database": "connected",
            "version": env!("CARGO_PKG_VERSION"),
        })),
        Err(_) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "status": "unhealthy",
            "database": "disconnected",
        })),
    }
}
