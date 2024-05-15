use crate::{schema, PodDetail, PodTraffic, SvcDetail};
use actix_web::{get, web, HttpResponse, Responder};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use tracing::info;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;
/// Inserts new user with name defined in form.
#[get("/netpol/traffic")]
pub async fn get_pod_traffic(pool: web::Data<DbPool>) -> actix_web::Result<impl Responder> {
    info!("select pod traffic table");

    let pod_traffic = web::block(move || {
        // note that obtaining a connection from the pool is also potentially blocking
        let mut conn = pool.get()?;

        pod_traffic(&mut conn)
    })
    .await?
    // map diesel query errors to a 500 error response
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match pod_traffic {
        // user was found; return 200 response with JSON formatted user object
        Some(p) => HttpResponse::Ok().json(p),

        // user was not found; return 404 response with error message
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_traffic(conn: &mut PgConnection) -> Result<Option<Vec<PodTraffic>>, DbError> {
    use schema::pod_traffic::dsl::*;

    let pod = pod_traffic.load::<PodTraffic>(conn).optional()?;

    Ok(pod)
}

#[get("/netpol/pod_info")]
pub async fn get_pod_details(pool: web::Data<DbPool>) -> actix_web::Result<impl Responder> {
    info!("select pod details table");

    let pod_detail = web::block(move || {
        // note that obtaining a connection from the pool is also potentially blocking
        let mut conn = pool.get()?;

        pod_details(&mut conn)
    })
    .await?
    // map diesel query errors to a 500 error response
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match pod_detail {
        // user was found; return 200 response with JSON formatted user object
        Some(p) => HttpResponse::Ok().json(p),

        // user was not found; return 404 response with error message
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_details(conn: &mut PgConnection) -> Result<Option<Vec<PodDetail>>, DbError> {
    use schema::pod_details::dsl::*;
    let pod = pod_details.load::<PodDetail>(conn).optional()?;
    Ok(pod)
}

#[get("/netpol/svc/{ip}")]
pub async fn get_svc_by_ip<'a>(
    pool: web::Data<DbPool>,
    ip: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    info!("select svc details by ip");
    let ip = ip.into_inner();
    let svc_detail = web::block(move || {
        let mut conn = pool.get()?;

        svc_ip(&mut conn, &ip)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match svc_detail {
        Some(p) => HttpResponse::Ok().json(p),
        // svc was not found; return 404 response with error message
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn svc_ip(conn: &mut PgConnection, ip: &str) -> Result<Option<SvcDetail>, DbError> {
    use schema::svc_details::dsl::*;
    let svc = svc_details
        .filter(svc_ip.eq(ip.to_string()))
        .first::<SvcDetail>(conn)
        .optional()?;
    Ok(svc)
}

// POD BY IP
#[get("/netpol/pod/{ip}")]
pub async fn get_pod_by_ip<'a>(
    pool: web::Data<DbPool>,
    ip: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    info!("select pod details by ip");
    let ip = ip.into_inner();
    let pod_detail = web::block(move || {
        let mut conn = pool.get()?;

        pod_ip(&mut conn, &ip)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match pod_detail {
        Some(p) => HttpResponse::Ok().json(p),
        // svc was not found; return 404 response with error message
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_ip(conn: &mut PgConnection, ip: &str) -> Result<Option<PodDetail>, DbError> {
    use schema::pod_details::dsl::*;
    let pod = pod_details
        .filter(pod_ip.eq(ip.to_string()))
        .first::<PodDetail>(conn)
        .optional()?;
    Ok(pod)
}

// POD TRAFFIC BY PODNAME
#[get("/podtraffic/pod/{name}")]
pub async fn get_pod_traffic_name<'a>(
    pool: web::Data<DbPool>,
    name: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    info!("select pod traffic for the pod name");
    let pod_name = name.into_inner();
    let pod_detail = web::block(move || {
        let mut conn = pool.get()?;

        pod_traffic_by_name(&mut conn, &pod_name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(match pod_detail {
        Some(p) => HttpResponse::Ok().json(p),
        // svc was not found; return 404 response with error message
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_traffic_by_name(
    conn: &mut PgConnection,
    name: &str,
) -> Result<Option<Vec<PodTraffic>>, DbError> {
    use schema::pod_traffic::dsl::*;
    let pod_tr = pod_traffic
        .filter(pod_name.eq(name.to_string()))
        .load::<PodTraffic>(conn)
        .optional()?;
    Ok(pod_tr)
}
