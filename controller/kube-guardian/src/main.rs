use actix_web::{get, HttpRequest, HttpResponse, Responder};
use kube_guardian::trace::TracedAddrRecord;
use kube_guardian::{trace::EbpfPgm, telemetry, watch_pods, watch_service, PodInspect};
use std::collections::HashSet;
use std::env;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

// TODO enable State

// #[get("/")]
// async fn index(c: Data<State>, _req: HttpRequest) -> impl Responder {
//     let d = c.diagnostics().await;
//     HttpResponse::Ok().json(&d)
// }

#[get("/health")]
async fn health(_: HttpRequest) -> impl Responder {
    HttpResponse::Ok().json("healthy")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init_logger();

    let c: Arc<Mutex<BTreeMap<u64, PodInspect>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let rc_map: Arc<Mutex<BTreeMap<u32, u64>>> = Arc::new(Mutex::new(BTreeMap::new()));

    let traced_addresses_cache: Arc<Mutex<HashSet<TracedAddrRecord>>> =
        Arc::new(Mutex::new(HashSet::new()));

    // load ebpf
    let bpf = EbpfPgm::load_ebpf(Arc::clone(&c), Arc::clone(&rc_map),Arc::clone(&traced_addresses_cache))?;

    let node_name = env::var("CURRENT_NODE").expect("cannot find node name: CURRENT_NODE ");
    let pods = watch_pods( bpf,c,rc_map, node_name);

    // Start web server,
    // let server = HttpServer::new(move || {
    //     App::new()
    //         .app_data(Data::new(state.clone()))
    //         .wrap(middleware::Logger::default().exclude("/health"))
    //         .service(index)
    //         .service(health)
    //     // .service(metrics)
    // })
    // .bind("0.0.0.0:8080")?
    // .shutdown_timeout(5);

    let service = watch_service();
    _ = tokio::join!(pods, service);
    Ok(())
}
