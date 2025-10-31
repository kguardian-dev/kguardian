use std::error::Error;

use actix_web::{get, web, App, HttpResponse, HttpServer};
use api::{
    add_pod_details, add_pods, add_pods_syscalls, add_svc_details, establish_connection,
    get_pod_by_ip, get_pod_details, get_pod_syscall_name, get_pod_traffic, get_pod_traffic_name,
    get_svc_by_ip,add_drop_packets, get_pod_packet_drop_name, get_pod_packet_drop,
};

use diesel::r2d2;
use telemetry::init_logging;
mod telemetry;

use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use tracing::info;
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
    // RUN the migration schema
    let mut x = pool.get().unwrap();
    let r = run_migrations(&mut x);
    if let Err(e) = r {
        panic!("DB Set up failed {}", e);
    } else {
        info!("DB setup success");
    }
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(add_pods)
            .service(add_drop_packets)
            .service(add_pod_details)
            .service(add_pods_syscalls)
            .service(get_pod_traffic)
            .service(get_pod_details)
            .service(add_svc_details)
            .service(get_pod_by_ip)
            .service(get_svc_by_ip)
            .service(get_pod_packet_drop) 
            .service(get_pod_packet_drop_name)  
            .service(get_pod_traffic_name)
            .service(get_pod_syscall_name)
            .service(health_check)
    })
    .bind(("0.0.0.0", 9090))?
    .run()
    .await
}

#[get("/health")]
pub async fn health_check() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/json")
        .body("Healthy!")
}
