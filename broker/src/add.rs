use crate::{schema, PodDetail, PodInputSyscalls, PodSyscalls, PodTraffic, SvcDetail, HttpPodTraffic};
use actix_web::{post, web, Error, HttpResponse};
use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager};
use std::clone::Clone;

use diesel::prelude::*;
use tracing::{debug, info};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

#[post("/pod/traffic")]
pub async fn add_pods(
    pool: web::Data<DbPool>,
    form: web::Json<PodTraffic>,
) -> Result<HttpResponse, Error> {
    let pods = web::block(move || {
        let mut conn = pool.get()?;
        create_pod_traffic(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(pods))
}

pub fn create_pod_traffic(
    conn: &mut PgConnection,
    w: web::Json<PodTraffic>,
) -> Result<PodTraffic, DbError> {
    use schema::pod_traffic::dsl::*;
    debug!(
        "storing the pod details {:?} into pod_traffic table",
        w.uuid
    );
    if w.get_row(conn)?.is_none() {
        info!("Insert pod {:?}, in pod_traffic table", w.uuid);
        let _ = diesel::insert_into(pod_traffic)
            .values(&*w)
            .execute(conn)
            .expect("Error saving data into pod_traffic");

        debug!("Success: pod {:?} inserted in pod_traffic table", w.uuid);
    } else {
        debug!("Data already exists");
    }
    Ok(w.0)
}

impl PodTraffic {
    pub fn get_row(&self, conn: &mut PgConnection) -> Result<Option<PodTraffic>, DbError> {
        use schema::pod_traffic::dsl::*;
        if self.ip_protocol.eq(&Some("UDP".to_string())) {
            let out: Option<PodTraffic> = pod_traffic
                .filter(pod_ip.eq(&self.pod_ip))
                .filter(traffic_type.eq(&self.traffic_type))
                .filter(traffic_in_out_ip.eq(&self.traffic_in_out_ip))
                .filter(traffic_in_out_port.eq(&self.traffic_in_out_port))
                .first::<PodTraffic>(conn)
                .optional()?;
            if out.is_none() {
                let second: Option<PodTraffic> = pod_traffic
                    .filter(pod_ip.eq(&self.pod_ip))
                    .filter(pod_port.eq(&self.pod_port))
                    .filter(traffic_type.eq(&self.traffic_type))
                    .filter(traffic_in_out_ip.eq(&self.traffic_in_out_ip))
                    .first::<PodTraffic>(conn)
                    .optional()?;
                return Ok(second);
            }
            return Ok(out);
        }

        debug!("pod_ip {:?}\n pod_port {:?}\n pod_trafic_type {:?}\n traffic_in_out_ip {:?}\n traffic_in_out_port {:?}\n_", &self.pod_ip, &self.pod_port,&self.traffic_type,&self.traffic_in_out_ip,&self.traffic_in_out_port);
        let row = pod_traffic
            .filter(pod_ip.eq(&self.pod_ip))
            .filter(pod_port.eq(&self.pod_port))
            .filter(traffic_type.eq(&self.traffic_type))
            .filter(traffic_in_out_ip.eq(&self.traffic_in_out_ip))
            .filter(traffic_in_out_port.eq(&self.traffic_in_out_port))
            .first::<PodTraffic>(conn)
            .optional()?;
        Ok(row)
    }
}

#[post("/pod/l7traffic")]
pub async fn add_pod_http_traffic(
    pool: web::Data<DbPool>,
    form: web::Json<HttpPodTraffic>,
) -> Result<HttpResponse, Error> {
    let pods = web::block(move || {
        let mut conn = pool.get()?;
        create_pod_http_traffic(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(pods))
}

pub fn create_pod_http_traffic(
    conn: &mut PgConnection,
    w: web::Json<HttpPodTraffic>,
) -> Result<HttpPodTraffic, DbError> {
    use schema::pod_http_traffic::dsl::*;
    debug!(
        "storing the pod details {:?} into pod_http_traffic table",
        w.uuid
    );
    if w.get_row(conn)?.is_none() {
        info!("Insert pod {:?}, in pod_http_traffic table", w.uuid);
        let _ = diesel::insert_into(pod_http_traffic)
            .values(&*w)
            .execute(conn)
            .expect("Error saving data into pod_http_traffic");

        debug!("Success: pod {:?} inserted in pod_http_traffic table", w.uuid);
    } else {
        debug!("Data already exists");
    }
    Ok(w.0)
}
impl HttpPodTraffic {
    pub fn get_row(&self, conn: &mut PgConnection) -> Result<Option<HttpPodTraffic>, DbError> {
        use schema::pod_http_traffic::dsl::*;

        debug!(
            "pod_ip {:?}\n pod_port {:?}\n pod_trafic_type {:?}\n traffic_in_out_ip {:?}\n traffic_in_out_port {:?}\n http_path {:?}\n_",
            &self.pod_ip, &self.pod_port,&self.traffic_type,&self.traffic_in_out_ip,&self.traffic_in_out_port,&self.http_path
        );
        let row = pod_http_traffic
            .filter(pod_ip.eq(&self.pod_ip))
            .filter(pod_port.eq(&self.pod_port))
            .filter(traffic_type.eq(&self.traffic_type))
            .filter(traffic_in_out_ip.eq(&self.traffic_in_out_ip))
            .filter(traffic_in_out_port.eq(&self.traffic_in_out_port))
            .filter(http_path.eq(&self.http_path))
            .first::<HttpPodTraffic>(conn)
            .optional()?;
        Ok(row)
    }
}


#[post("/pod/spec")]
pub async fn add_pod_details(
    pool: web::Data<DbPool>,
    form: web::Json<PodDetail>,
) -> Result<HttpResponse, Error> {
    let pods = web::block(move || {
        let mut conn = pool.get()?;
        upsert_pod_details(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(pods))
}

pub fn upsert_pod_details(
    conn: &mut PgConnection,
    w: web::Json<PodDetail>,
) -> Result<PodDetail, DbError> {
    use schema::pod_details::dsl::*;
    debug!(
        "storing the pod details {:?} into pod_details table",
        w.pod_name,
    );
    let _ = diesel::insert_into(pod_details)
        .values(&*w)
        .on_conflict(pod_name)
        .do_update()
        .set(&*w)
        .execute(conn)
        .expect("Error saving data into pod_details");
    info!("Success: pod {:?} inserted in pod_details table", w.pod_ip);
    Ok(w.0)
}

#[post("/svc/spec")]
pub async fn add_svc_details(
    pool: web::Data<DbPool>,
    form: web::Json<SvcDetail>,
) -> Result<HttpResponse, Error> {
    info!("Insert Service details table");
    let pods = web::block(move || {
        let mut conn = pool.get()?;
        upsert_svc_details(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(pods))
}

pub fn upsert_svc_details(
    conn: &mut PgConnection,
    w: web::Json<SvcDetail>,
) -> Result<SvcDetail, DbError> {
    use schema::svc_details::dsl::*;
    debug!(
        "storing the service details {:?} into svc_details table",
        w.svc_ip,
    );
    let _ = diesel::insert_into(svc_details)
        .values(&*w)
        .on_conflict(svc_ip)
        .do_update()
        .set(&*w)
        .execute(conn)
        .expect("Error saving data into svc_details");
    info!("Success: svc {:?} inserted in svc_details table", w.svc_ip);
    Ok(w.0)
}

impl PodInputSyscalls {
    pub fn get_row(&self, conn: &mut PgConnection) -> Result<Option<PodSyscalls>, DbError> {
        use schema::pod_syscalls::dsl::*;

        debug!(
            "pod_name: {:?}, pod_namespace: {:?}, syscalls: {:?}, arch: {:?}",
            &self.pod_name, &self.pod_namespace, &self.syscalls, &self.arch
        );

        let row = pod_syscalls
            .filter(pod_name.eq(&self.pod_name))
            .filter(pod_namespace.eq(&self.pod_namespace))
            .filter(arch.eq(&self.arch))
            .first::<PodSyscalls>(conn)
            .optional()?;

        Ok(row)
    }
}

#[post("/pod/syscalls")]
pub async fn add_pods_syscalls(
    pool: web::Data<DbPool>,
    form: web::Json<Vec<PodInputSyscalls>>,
) -> Result<HttpResponse, Error> {
    debug!("Insert pod syscall details table");
    let pods = web::block(move || {
        let mut conn = pool.get()?;
        create_pod_syscalls(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(pods))
}

pub fn create_pod_syscalls(
    conn: &mut PgConnection,
    w: web::Json<Vec<PodInputSyscalls>>,
) -> Result<(), DbError> {
    use schema::pod_syscalls::dsl::*;

    for pod_syscall in w.iter() {
        debug!(
            "Storing pod details {:?} into pod_syscalls table",
            pod_syscall.pod_name
        );

        let existing_row = pod_syscall.get_row(conn)?;
        let new_syscall_number = pod_syscall.syscalls.join(",");

        if let Some(mut row) = existing_row {
            row.syscalls = new_syscall_number;

            diesel::update(pod_syscalls.filter(pod_name.eq(&row.pod_name)))
                .set(syscalls.eq(row.syscalls.clone()))
                .execute(conn)
                .expect("Error updating pod_syscalls");
        } else {
            let new_pod_syscall = PodSyscalls {
                syscalls: new_syscall_number,
                pod_name: pod_syscall.pod_name.clone(),
                pod_namespace: pod_syscall.pod_namespace.clone(),
                arch: pod_syscall.arch.clone(),
                time_stamp: pod_syscall.time_stamp,
            };

            diesel::insert_into(pod_syscalls)
                .values(&new_pod_syscall)
                .execute(conn)
                .expect("Error inserting data into pod_syscalls");
        }

        debug!(
            "Success: pod {:?} processed in pod_syscalls table",
            pod_syscall.pod_name
        );
    }

    Ok(())
}
