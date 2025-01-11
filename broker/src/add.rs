use crate::{schema, PodDetail, PodSyscalls, PodTraffic, SvcDetail};
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
    info!("Insert pod details table");
    // use web::block to offload blocking Diesel code without blocking server thread
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
    // check if row exists
    let row = w.get_row(conn)?;

    if w.get_row(conn)?.is_none() {
        info!("Insert pod {:?}, in pod_traffic table", w.uuid);
        let _ = diesel::insert_into(pod_traffic)
            .values(&*w)
            .execute(conn)
            .expect("Error saving data into pod_traffic");

        info!("Success: pod {:?} inserted in pod_traffic table", w.uuid);
    } else {
        info!("Data already exists");
    }

    Ok(w.0)
}

#[post("/pod/spec")]
pub async fn add_pod_details(
    pool: web::Data<DbPool>,
    form: web::Json<PodDetail>,
) -> Result<HttpResponse, Error> {
    info!("Insert pod details table");
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

    info!("Insert/Update pod {:?}, in pod_details table", w.pod_ip);

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
    // use web::block to offload blocking Diesel code without blocking server thread
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

    info!("Insert/Update svc {:?}, in svc_details table", w.svc_ip);

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

impl PodTraffic {
    pub fn get_row(&self, conn: &mut PgConnection) -> Result<Option<PodTraffic>, DbError> {
        use schema::pod_traffic::dsl::*;
        // check if its udp

        if self.ip_protocol.eq(&Some("UDP".to_string())) {
            //TODO implement join
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

        info!("pod_ip {:?}\n pod_port {:?}\n pod_trafic_type {:?}\n traffic_in_out_ip {:?}\n traffic_in_out_port {:?}\n_", &self.pod_ip, &self.pod_port,&self.traffic_type,&self.traffic_in_out_ip,&self.traffic_in_out_port);
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

impl PodSyscalls {
    pub fn get_row(&self, conn: &mut PgConnection) -> Result<Option<PodSyscalls>, DbError> {
        use schema::pod_syscalls::dsl::*;

        info!(
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
    form: web::Json<PodSyscalls>,
) -> Result<HttpResponse, Error> {
    info!("Insert pod syscall details table");

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
    w: web::Json<PodSyscalls>,
) -> Result<PodSyscalls, DbError> {
    use schema::pod_syscalls::dsl::*;

    debug!(
        "Storing pod details {:?} into pod_syscalls table",
        w.pod_name
    );

    let existing_row = w.get_row(conn)?;
    let new_syscall_number = &w.syscalls.clone();

    if let Some(mut row) = existing_row {
        let mut syscall_list: Vec<&str> =
            row.syscalls.split(',').collect();
        if !syscall_list.contains(&new_syscall_number.as_str()) {
            syscall_list.push(new_syscall_number);
            row.syscalls = syscall_list.join(",");

            diesel::update(pod_syscalls.filter(pod_name.eq(&row.pod_name)))
                .set(syscalls.eq(row.syscalls.clone()))
                .execute(conn)
                .expect("Error updating pod_syscalls");
        }
    } else {
        diesel::insert_into(pod_syscalls)
            .values(&*w)
            .execute(conn)
            .expect("Error inserting data into pod_syscalls");

        info!(
            "Success: pod {:?} inserted in pod_syscalls table",
            w.pod_name
        );
    }

    Ok(w.into_inner())
}
