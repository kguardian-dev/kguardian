use crate::{schema, PodDetail, PodTraffic, SvcDetail};
use actix_web::{post, web, Error, HttpResponse};
use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager};

use diesel::prelude::*;
use tracing::{debug, info};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;
/// Inserts new user with name defined in form.
///

#[post("/netpol/pods")]
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

#[post("/netpol/podspec")]
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

#[post("/netpol/svc")]
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
