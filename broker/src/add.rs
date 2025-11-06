use crate::{schema, PodDetail, PodInputSyscalls, PodSyscalls, PodTraffic, SvcDetail};
use actix_web::{post, web, Error, HttpResponse};
use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager};
use std::clone::Clone;

use diesel::prelude::*;
use tracing::{debug, info};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

#[post("/pod/traffic/batch")]
pub async fn add_pods_batch(
    pool: web::Data<DbPool>,
    form: web::Json<Vec<PodTraffic>>,
) -> Result<HttpResponse, Error> {
    let count = form.len();
    debug!("Received batch of {} network traffic events", count);

    let result = web::block(move || {
        let mut conn = pool.get()?;
        create_pod_traffic_batch(&mut conn, form)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    info!(
        "Successfully inserted batch of {} network traffic events",
        count
    );
    Ok(HttpResponse::Ok().json(result))
}

fn create_pod_traffic_batch(
    conn: &mut PgConnection,
    batch: web::Json<Vec<PodTraffic>>,
) -> Result<usize, DbError> {
    use schema::pod_traffic::dsl::*;

    if batch.is_empty() {
        return Ok(0);
    }

    debug!("Processing batch of {} network traffic events", batch.len());

    // Filter out duplicates by checking each event against existing records
    let mut events_to_insert = Vec::new();
    for event in batch.iter() {
        if event.get_row(conn)?.is_none() {
            events_to_insert.push(event.clone());
        } else {
            debug!(
                "Skipping duplicate traffic event for pod: {:?}",
                event.pod_name
            );
        }
    }

    if events_to_insert.is_empty() {
        debug!("All events in batch were duplicates, nothing to insert");
        return Ok(0);
    }

    debug!(
        "Inserting {} new network traffic events (filtered {} duplicates)",
        events_to_insert.len(),
        batch.len() - events_to_insert.len()
    );

    // Bulk insert only the new events
    let inserted = diesel::insert_into(pod_traffic)
        .values(&events_to_insert)
        .execute(conn)?;

    debug!("Successfully inserted {} network traffic events", inserted);
    Ok(inserted)
}

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

fn create_pod_traffic(
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
                .filter(decision.eq(&self.decision))
                .first::<PodTraffic>(conn)
                .optional()?;
            if out.is_none() {
                let second: Option<PodTraffic> = pod_traffic
                    .filter(pod_ip.eq(&self.pod_ip))
                    .filter(pod_port.eq(&self.pod_port))
                    .filter(traffic_type.eq(&self.traffic_type))
                    .filter(traffic_in_out_ip.eq(&self.traffic_in_out_ip))
                    .filter(decision.eq(&self.decision))
                    .first::<PodTraffic>(conn)
                    .optional()?;
                return Ok(second);
            }
            return Ok(out);
        }

        debug!("pod_ip {:?}\n pod_port {:?}\n pod_trafic_type {:?}\n traffic_in_out_ip {:?}\n traffic_in_out_port {:?}\n decision {:?}\n_", &self.pod_ip, &self.pod_port,&self.traffic_type,&self.traffic_in_out_ip,&self.traffic_in_out_port,&self.decision);
        let row = pod_traffic
            .filter(pod_ip.eq(&self.pod_ip))
            .filter(pod_port.eq(&self.pod_port))
            .filter(traffic_type.eq(&self.traffic_type))
            .filter(traffic_in_out_ip.eq(&self.traffic_in_out_ip))
            .filter(traffic_in_out_port.eq(&self.traffic_in_out_port))
            .filter(decision.eq(&self.decision))
            .first::<PodTraffic>(conn)
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

// New API: Mark pod as dead
#[derive(serde::Deserialize)]
pub struct MarkDeadRequest {
    pub pod_name: String,
}

#[post("/pod/mark_dead")]
pub async fn mark_pod_dead(
    pool: web::Data<DbPool>,
    form: web::Json<MarkDeadRequest>,
) -> Result<HttpResponse, Error> {
    debug!("Marking pod {} as dead", form.pod_name);
    let result = web::block(move || {
        let mut conn = pool.get()?;
        mark_pod_as_dead(&mut conn, &form.pod_name)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(result))
}

fn mark_pod_as_dead(conn: &mut PgConnection, pod: &str) -> Result<usize, DbError> {
    use schema::pod_details::dsl::*;

    let updated = diesel::update(pod_details)
        .filter(pod_name.eq(pod))
        .set(is_dead.eq(true))
        .execute(conn)?;

    info!("Marked pod {} as dead", pod);
    Ok(updated)
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
