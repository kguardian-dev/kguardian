use crate::{schema, Error, PodDetail, PodSyscalls, PodTraffic, SvcDetail};
use actix_web::{get, web, HttpResponse, Responder};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::LazyLock;
use tracing::{debug, info};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// RFC 1123 DNS subdomain pattern for pod/node names.
static POD_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$").unwrap());

/// Validates a Kubernetes pod/node name against RFC 1123 DNS subdomain rules.
fn validate_pod_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".to_string());
    }
    if POD_NAME_RE.is_match(name) {
        Ok(())
    } else {
        Err(format!(
            "invalid name '{name}': must match RFC 1123 DNS subdomain (lowercase alphanumeric, '-', '.')"
        ))
    }
}

/// Validates that `ip` is a syntactically valid IPv4 or IPv6 address.
fn validate_ip(ip: &str) -> Result<(), String> {
    IpAddr::from_str(ip)
        .map(|_| ())
        .map_err(|_| format!("invalid IP address '{ip}'"))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[get("/pod/traffic")]
pub async fn get_pod_traffic(pool: web::Data<DbPool>) -> Result<impl Responder, Error> {
    debug!("select pod traffic table");
    let pod_traffic = web::block(move || {
        let mut conn = pool.get()?;
        pod_traffic_all(&mut conn)
    })
    .await??;

    Ok(match pod_traffic {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_traffic_all(conn: &mut PgConnection) -> Result<Option<Vec<PodTraffic>>, Error> {
    use schema::pod_traffic::dsl::*;

    let pod = pod_traffic.load::<PodTraffic>(conn).optional()?;

    Ok(pod)
}

#[get("/pod/info")]
pub async fn get_pod_details(pool: web::Data<DbPool>) -> Result<impl Responder, Error> {
    debug!("select pod details table");
    let pod_detail = web::block(move || {
        let mut conn = pool.get()?;
        pod_details_all(&mut conn)
    })
    .await??;

    Ok(match pod_detail {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_details_all(conn: &mut PgConnection) -> Result<Option<Vec<PodDetail>>, Error> {
    use schema::pod_details::dsl::*;
    let pod = pod_details.load::<PodDetail>(conn).optional()?;
    Ok(pod)
}

// New API: Get all pods for a specific node
#[get("/pod/list/{node}")]
pub async fn get_pods_by_node(
    pool: web::Data<DbPool>,
    node: web::Path<String>,
) -> Result<impl Responder, Error> {
    let node_name = node.into_inner();
    if let Err(msg) = validate_pod_name(&node_name) {
        return Err(Error::UserInputError(msg));
    }
    debug!("Getting pods for node: {}", node_name);
    let pods = web::block(move || {
        let mut conn = pool.get()?;
        pods_by_node(&mut conn, &node_name)
    })
    .await??;

    Ok(HttpResponse::Ok().json(pods))
}

pub fn pods_by_node(conn: &mut PgConnection, node: &str) -> Result<Vec<PodDetail>, Error> {
    use schema::pod_details::dsl::*;
    let pods = pod_details
        .filter(node_name.eq(node))
        .filter(is_dead.eq(false))
        .load::<PodDetail>(conn)?;
    Ok(pods)
}

#[get("/svc/info")]
pub async fn get_svc_details(pool: web::Data<DbPool>) -> Result<impl Responder, Error> {
    debug!("select svc details table");
    let svc_detail = web::block(move || {
        let mut conn = pool.get()?;
        svc_details_all(&mut conn)
    })
    .await??;

    Ok(match svc_detail {
        Some(s) => HttpResponse::Ok().json(s),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn svc_details_all(conn: &mut PgConnection) -> Result<Option<Vec<SvcDetail>>, Error> {
    use schema::svc_details::dsl::*;
    let svcs = svc_details.load::<SvcDetail>(conn).optional()?;
    Ok(svcs)
}

#[get("/svc/ip/{ip}")]
pub async fn get_svc_by_ip(
    pool: web::Data<DbPool>,
    ip: web::Path<String>,
) -> Result<impl Responder, Error> {
    let ip = ip.into_inner();
    if let Err(msg) = validate_ip(&ip) {
        return Err(Error::UserInputError(msg));
    }
    info!("select svc details by ip");
    let svc_detail = web::block(move || {
        let mut conn = pool.get()?;
        svc_ip(&mut conn, &ip)
    })
    .await??;

    Ok(match svc_detail {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn svc_ip(conn: &mut PgConnection, ip: &str) -> Result<Option<SvcDetail>, Error> {
    use schema::svc_details::dsl::*;
    let svc = svc_details
        .filter(svc_ip.eq(ip.to_string()))
        .first::<SvcDetail>(conn)
        .optional()?;
    Ok(svc)
}

// POD BY NAME
#[get("/pod/name/{name}")]
pub async fn get_pod_by_name(
    pool: web::Data<DbPool>,
    name: web::Path<String>,
) -> Result<impl Responder, Error> {
    let name = name.into_inner();
    if let Err(msg) = validate_pod_name(&name) {
        return Err(Error::UserInputError(msg));
    }
    info!("select pod details by name");
    let pod_detail = web::block(move || {
        let mut conn = pool.get()?;
        pod_name(&mut conn, &name)
    })
    .await??;

    Ok(match pod_detail {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_name(conn: &mut PgConnection, name: &str) -> Result<Option<PodDetail>, Error> {
    use schema::pod_details::dsl::*;
    let pod = pod_details
        .filter(pod_name.eq(name.to_string()))
        .first::<PodDetail>(conn)
        .optional()?;
    Ok(pod)
}

// POD BY IP
#[get("/pod/ip/{ip}")]
pub async fn get_pod_by_ip(
    pool: web::Data<DbPool>,
    ip: web::Path<String>,
) -> Result<impl Responder, Error> {
    let ip = ip.into_inner();
    if let Err(msg) = validate_ip(&ip) {
        return Err(Error::UserInputError(msg));
    }
    info!("select pod details by ip");
    let pod_detail = web::block(move || {
        let mut conn = pool.get()?;
        pod_ip(&mut conn, &ip)
    })
    .await??;

    Ok(match pod_detail {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_ip(conn: &mut PgConnection, ip: &str) -> Result<Option<PodDetail>, Error> {
    use schema::pod_details::dsl::*;
    let pod = pod_details
        .filter(pod_ip.eq(ip.to_string()))
        .first::<PodDetail>(conn)
        .optional()?;
    Ok(pod)
}

// POD TRAFFIC BY PODNAME
#[get("/pod/traffic/{name}")]
pub async fn get_pod_traffic_name(
    pool: web::Data<DbPool>,
    name: web::Path<String>,
) -> Result<impl Responder, Error> {
    let pod_name = name.into_inner();
    if let Err(msg) = validate_pod_name(&pod_name) {
        return Err(Error::UserInputError(msg));
    }
    info!("select pod traffic for the pod name");
    let pod_detail = web::block(move || {
        let mut conn = pool.get()?;
        pod_traffic_by_name(&mut conn, &pod_name)
    })
    .await??;

    Ok(match pod_detail {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_traffic_by_name(
    conn: &mut PgConnection,
    name: &str,
) -> Result<Option<Vec<PodTraffic>>, Error> {
    use schema::pod_traffic::dsl::*;
    let pod_tr = pod_traffic
        .filter(pod_name.eq(name.to_string()))
        .load::<PodTraffic>(conn)
        .optional()?;
    Ok(pod_tr)
}

// POD SYS CALLS BY PODNAME
#[get("/pod/syscalls/{name}")]
pub async fn get_pod_syscall_name(
    pool: web::Data<DbPool>,
    name: web::Path<String>,
) -> Result<impl Responder, Error> {
    let pod_name = name.into_inner();
    if let Err(msg) = validate_pod_name(&pod_name) {
        return Err(Error::UserInputError(msg));
    }
    info!("select pod syscall for the pod name");
    let pod_syscalls = web::block(move || {
        let mut conn = pool.get()?;
        pod_syscalls_by_name(&mut conn, &pod_name)
    })
    .await??;

    Ok(match pod_syscalls {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().body("No data found"),
    })
}

pub fn pod_syscalls_by_name(
    conn: &mut PgConnection,
    name: &str,
) -> Result<Option<Vec<PodSyscalls>>, Error> {
    use schema::pod_syscalls::dsl::*;
    let pod_tr = pod_syscalls
        .filter(pod_name.eq(name.to_string()))
        .load::<PodSyscalls>(conn)
        .optional()?;
    Ok(pod_tr)
}
