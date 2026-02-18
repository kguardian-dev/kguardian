use std::error::Error;

use actix_cors::Cors;
use actix_web::{get, web, App, HttpResponse, HttpServer};
use api::{
    add_pod_details, add_pods, add_pods_batch, add_pods_syscalls, add_svc_details, mark_pod_dead,
    establish_connection, get_pod_by_ip, get_pod_by_name, get_pod_details, get_pod_syscall_name, get_pod_traffic,
    get_pod_traffic_name, get_pods_by_node, get_svc_by_ip,
};

use diesel::r2d2;
use telemetry::init_logging;
mod telemetry;

use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use tracing::{info, warn};
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
    let manager = establish_connection();
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");
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
                        panic!("DB migration failed after {} attempts: {}", max_retries, e);
                    }
                    warn!(
                        "DB migration attempt {}/{} failed: {}. Retrying in 2s...",
                        attempt, max_retries, e
                    );
                }
            },
            Err(e) => {
                if attempt == max_retries {
                    panic!(
                        "Failed to get DB connection after {} attempts: {}",
                        max_retries, e
                    );
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
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
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

#[get("/health")]
pub async fn health_check(
    pool: web::Data<r2d2::Pool<r2d2::ConnectionManager<diesel::PgConnection>>>,
) -> HttpResponse {
    match pool.get() {
        Ok(_) => HttpResponse::Ok()
            .content_type("application/json")
            .body("Healthy!"),
        Err(_) => HttpResponse::ServiceUnavailable()
            .content_type("application/json")
            .body("Database unavailable"),
    }
}
