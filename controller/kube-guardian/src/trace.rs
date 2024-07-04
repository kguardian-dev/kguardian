use crate::{api::api_post_call, Error, PodInfo, PodInspect, Result, Traffic};
use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{
        cgroup_skb::CgroupSkbLinkId, CgroupSkb, CgroupSkbAttachType, Program, ProgramError,
        TracePoint,
    },
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use chrono::{NaiveDateTime, Utc};
use kube_guardian_common::TrafficLog;
use procfs::process::Process;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use std::{collections::BTreeMap, env};
use std::{collections::HashSet, net::Ipv4Addr};
use tokio::fs::File;
use tokio::{sync::Mutex, task};
use tracing::{debug, error, info};
use uuid::Uuid;

pub type TracedAddrRecord = (String, String, u16, String, u16);

#[derive(Debug, Default, Serialize)]
pub struct PodTraffic {
    pub uuid: String,
    pub pod_name: String,
    pub pod_namespace: Option<String>,
    pub pod_ip: String,
    pub pod_port: Option<String>,
    pub traffic_type: Option<String>,
    pub traffic_in_out_ip: Option<String>,
    pub traffic_in_out_port: Option<String>,
    pub ip_protocol: Option<String>,
    pub time_stamp: NaiveDateTime,
}
pub struct EbpfPgm {
    pub bpf: Ebpf,
}

impl EbpfPgm {
    pub fn load_ebpf(
        container_map: Arc<Mutex<BTreeMap<u32, PodInspect>>>,
        traced_address: Arc<Mutex<HashSet<TracedAddrRecord>>>,
    ) -> Result<EbpfPgm, crate::Error> {
        #[cfg(debug_assertions)]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/kube-guardian"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/kube-guardian"
        ))?;

        // let program: &mut TracePoint = bpf.program_mut("kube_guardian_egress").unwrap().try_into()?;

        // if let Err(e) = program.load(){
        //     error!("Failed to load  kube_guardian_egress {}", e);
        //     return Err(Error::BpfProgramError { source: e })
        // };
        // if let Err(e) = program.attach("net", "net_dev_xmit") { // EGRESS 0
        //     error!("Failed to attach net_dev_xmit {}", e);
        //     return Err(Error::BpfProgramError { source: e })

        // };

        let program_ingress: &mut TracePoint = bpf
            .program_mut("kube_guardian_ingress")
            .unwrap()
            .try_into()?;

        if let Err(e) = program_ingress.load() {
            error!("Failed to load  kube_guardian_ingress {}", e);
            return Err(Error::BpfProgramError { source: e });
        };

        if let Err(e) = program_ingress.attach("net", "netif_receive_skb") {
            // INGRESS 1
            error!("Failed to attach netif_receive_skb {}", e);
            return Err(Error::BpfProgramError { source: e });
        };

        let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
        for cpu_id in online_cpus()? {
            let container_map = Arc::clone(&container_map);
            let traced_address_cache = Arc::clone(&traced_address);

            let mut perf_buffer = perf_array.open(cpu_id, None)?;

            task::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();

                loop {
                    let events = perf_buffer.read_events(&mut buffers).await.unwrap();
                    for buf in buffers.iter_mut().take(events.read) {
                        process_buffer(buf, &container_map, &traced_address_cache)
                            .await
                            .unwrap();
                    }
                }
            });
        }

        Ok(Self { bpf })
    }
}

async fn process_buffer(
    buf: &mut BytesMut,
    container_map: &Arc<Mutex<BTreeMap<u32, PodInspect>>>,
    traced_address_cache: &Arc<Mutex<HashSet<(String, String, u16, String, u16)>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ptr = UserObj(buf.as_ptr() as *const TrafficLog);
    let data = unsafe { ptr.as_ptr().read_unaligned() };

    let tracker = container_map.lock().await;
    if let Some(valid_pod) = tracker.get(&(data.if_index as u32)) {
        let mut t = Traffic {
            src_addr: Ipv4Addr::from(data.saddr.to_be()).to_string(),
            dst_addr: Ipv4Addr::from(data.daddr.to_be()).to_string(),
            src_port: data.sport,
            dst_port: data.dport,
            ..Default::default()
        };

        if t.src_addr == valid_pod.status.pod_ip {
            info!(
                "source {}:{}, port {}:{}, syn {}, ack {}, inum {} ifindex {} traffic_type {}",
                Ipv4Addr::from(data.saddr.to_be()),
                data.sport,
                Ipv4Addr::from(data.daddr.to_be()),
                data.dport,
                data.syn,
                data.ack,
                data.inum,
                data.if_index,
                data.traffic_type,
            );

            if data.syn == 1 && data.ack == 0 {
                // Egress when the traffic is iniated from
                t.ip_protocol = String::from("TCP");
                t.traffic_type = 0;
            } else if data.syn == 1 && data.ack == 1 {
                // Ingress succeed at Destination
                // The inode num points to the client
                t.ip_protocol = String::from("TCP");
                t.traffic_type = 1;
            } else if data.syn == 2 && data.ack == 2 {
                // Egress
                t.ip_protocol = String::from("UDP");
                t.traffic_type = 0;
            } else {
                return Ok(());
            }

            let mut cache = traced_address_cache.lock().await;
            let traced_traffic = t.define_traffic();
            if !cache.contains(&traced_traffic) {
                match t.parse_message(&valid_pod.status).await {
                    Ok(_) => {
                        cache.insert(traced_traffic);
                    }
                    Err(e) => {
                        error!("{}", e);
                    }
                }
            } else {
                info!("Record exists");
            }
        }
    }

    Ok(())
}

struct UserObj(*const TrafficLog);
// SAFETY: Any user data object must be safe to send between threads.
unsafe impl Send for UserObj {}

impl UserObj {
    fn as_ptr(&self) -> *const TrafficLog {
        self.0
    }
}

impl Traffic {
    pub fn define_traffic(&self) -> (String, String, u16, String, u16) {
        return if self.traffic_type == 1 {
            // DERIVE INGRESS
            if self.ip_protocol.eq(&"TCP") {
                (
                    "INGRESS".to_string(),
                    self.src_addr.to_string(),
                    self.src_port,
                    self.dst_addr.to_string(),
                    0,
                )
            } else {
                //UDP
                (
                    "INGRESS".to_string(),
                    self.src_addr.to_string(),
                    self.src_port,
                    self.dst_addr.to_string(),
                    0,
                )
            }
        } else {
            // DERIVE EGRESS
            if self.ip_protocol.eq(&"TCP") {
                (
                    "EGRESS".to_string(),
                    self.src_addr.to_string(),
                    0,
                    self.dst_addr.to_string(),
                    self.dst_port,
                )
            } else {
                // UDP
                (
                    "EGRESS".to_string(),
                    self.src_addr.to_string(),
                    0,
                    self.dst_addr.to_string(),
                    self.dst_port,
                )
            }
        };
    }
    pub async fn parse_message(&self, pod_data: &PodInfo) -> Result<(), Error> {
        let pod_name = pod_data.pod_name.to_string();
        let pod_namespace = pod_data.pod_namespace.to_owned();
        let pod_ip = &pod_data.pod_ip;
        let (traffic_type, pod_ip, pod_port, traffic_in_out_ip, traffic_in_out_port) =
            self.define_traffic();
        let z = json!(PodTraffic {
            uuid: Uuid::new_v4().to_string(),
            pod_name: pod_name.to_string(),
            pod_namespace: pod_namespace,
            pod_ip,
            pod_port: Some(pod_port.to_string()),
            traffic_in_out_ip: Some(traffic_in_out_ip.to_string()),
            traffic_in_out_port: Some(traffic_in_out_port.to_string()),
            traffic_type: Some(traffic_type.to_string()),
            ip_protocol: Some(self.ip_protocol.to_string()),
            // example: 2007-04-05T14:30:30
            time_stamp: Utc::now().naive_utc() // .format("%Y-%m-%dT%H:%M:%S.%fZ")
                                               // .to_string(),
        });

        debug!("Record to be inserted {}", z.to_string());
        api_post_call(z, "netpol/pods").await?;
        Ok(())
    }
}
