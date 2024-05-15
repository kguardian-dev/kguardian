use crate::{api::api_post_call, Error, PodInfo, PodInspect, Result, Traffic};
use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{
        cgroup_skb::CgroupSkbLinkId, CgroupSkb, CgroupSkbAttachType, Program, ProgramError,
    },
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use chrono::{NaiveDateTime, Utc};
use kube_guardian_common::TrafficLog;
use serde::Serialize;
use serde_json::json;
use tracing_subscriber::fmt::format::debug_fn;
use std::{collections::HashSet, net::Ipv4Addr};
use std::sync::Arc;
use std::{collections::BTreeMap, env};
use tokio::fs::File;
use tokio::{sync::Mutex, task};
use tracing::{debug, error, info};
use uuid::Uuid;

pub type TracedAddrRecord = (String,String, u16, String, u16);

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
    bpf: Bpf,
}



pub async fn attach_cgroup(cgroup_path: &str, bpf: Arc<Mutex<EbpfPgm>>) -> Result<()> {
    let cgroup_file = tokio::fs::File::open(cgroup_path).await?;
    let cgroup_path = cgroup_file;
    let mut ebpf_pgm = bpf.lock().await;
    let prog = ebpf_pgm.bpf.program_mut("kube_guardian_egress").unwrap();
    let _egress = attach_cgroup_path(
        prog,
        CgroupSkbAttachType::Egress,
        cgroup_path.try_clone().await.unwrap(),
    );
    let prog = ebpf_pgm.bpf.program_mut("kube_guardian_ingress").unwrap();
    let _ingress = attach_cgroup_path(prog, CgroupSkbAttachType::Ingress, cgroup_path);
    // info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await?;
    // info!("Exiting...");

    Ok(())
}

fn attach_cgroup_path(
    prog: &mut Program,
    attach_type: CgroupSkbAttachType,
    cgroup_path: File,
) -> Option<CgroupSkbLinkId> {
    if let Program::CgroupSkb(cgrp) = prog {
        info!(
            "Attaching cgroup {:?} filer to {:?}",
            attach_type, cgroup_path
        );
        let cgroup_attach = cgrp.attach(cgroup_path, attach_type);
        if let Err(e) = cgroup_attach {
            match e {
                ProgramError::AlreadyAttached => {
                    info!("Program is already attached to cgroup path")
                }
                _ => error!("Error during attach to cgroup path  {}", e),
            }
            return None;
        } else {
            info!("LinkID for cgroup filter {:?}", cgroup_attach);
            return Some(cgroup_attach.unwrap());
        }
    }
    None
}

impl EbpfPgm {
    pub fn load_ebpf(
        container_map: Arc<Mutex<BTreeMap<u32, PodInspect>>>,traced_address:Arc<Mutex<HashSet<TracedAddrRecord>>> ,
    ) -> Result<EbpfPgm, crate::Error> {
        #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/kube-guardian"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/kube-guardian"
        ))?;

        let program_ingress: &mut CgroupSkb = bpf
            .program_mut("kube_guardian_ingress")
            .unwrap()
            .try_into()?;
        program_ingress.load()?;

        let program_egress: &mut CgroupSkb = bpf
            .program_mut("kube_guardian_egress")
            .unwrap()
            .try_into()?;
        program_egress.load()?;

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
                        let ptr = UserObj(buf.as_ptr() as *const TrafficLog);
                        let data = unsafe { ptr.as_ptr().read_unaligned() };
                        let ip_protocol = if data.syn.eq(&2) { "UDP" } else { "TCP" };
                        debug!(
                            "src {}, srcport {}, dst {},dstport{}, syn{} ack {} traffic_type {} if_index {}",
                            Ipv4Addr::from(data.source_addr),
                            data.src_port,
                            Ipv4Addr::from(data.dest_addr),
                            data.dst_port,
                            data.syn,
                            data.ack,
                            data.traffic,
                            data.if_index,
                        );

                        let tracker = container_map.lock().await;
                        let key_value = tracker.get(&data.if_index);
                        if let Some(pod_info) = key_value {
                            let pod_ip = pod_info.status.pod_ip.to_string();
                            let p = PodInfo {
                                pod_name: pod_info.status.pod_name.to_string(),
                                pod_namespace: pod_info.status.pod_namespace.to_owned(),
                                pod_ip: pod_info.status.pod_ip.to_string(),
                            };

                        
                            let t = Traffic {
                                pod_data: p,
                                src_addr: Ipv4Addr::from(data.source_addr).to_string(),
                                dst_addr: Ipv4Addr::from(data.dest_addr).to_string(),
                                src_port: data.src_port,
                                dst_port: data.dst_port,
                                traffic_type: data.traffic,
                                ip_protocol: ip_protocol.to_string(),
                            };
                            // check if data exists in cache
                            let mut cache = traced_address_cache.lock().await;
                            let traced_traffic= t.define_traffic(&pod_ip);
                            if !cache.contains(&traced_traffic) {

                            let parse = t.parse_message(&pod_ip).await;
                            cache.insert(traced_traffic);
                            if let Err(e) = parse {
                                error!("{}", e);
                            }
                            drop(cache)
                        }else{
                            info!("Record exists");
                        }
                        
                        } else {
                            debug!(
                                "Couldn't find the pods details for the if_index {}, but src add {}:{} dest add {}:{}, traffic {}, protocol {}",
                                &data.if_index,Ipv4Addr::from(data.source_addr).to_string(),data.src_port,Ipv4Addr::from(data.dest_addr).to_string(),data.dst_port,data.traffic,ip_protocol
                            )
                        }
                    }
                }
            });
        }

        Ok(Self { bpf })
    }
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
    pub  fn define_traffic(&self, pod_ip: &str) -> (String,String, u16,String,u16) {
        // compare the src ip == pod_ip
        // TCP: if ingress and src_ip != pod_ip then
        // pod_ip= pod_ip and pod_port=dst_port and traffic_in_out_ip = src_ip and traffic_in_out_port = 0
        // TCP: if egress and src_ip == pod_ip then
        // pod_ip = pod_ip and pod_port=0 and traffic_in_out_ip =  dst_ip and traffic_in_out_port = dst_port
        // UDP: if ingress and src_ip != pod_ip then
        // pod_ip = pod_ip and pod_port=0 and traffic_in_out_ip = src_ip and traffic_in_out_port = src_port
        // UDP: if egress and src_ip == pod_ip then
        // pod_ip = pod_ip and pod_port=0 and traffic_in_out_ip = dst_ip and traffic_in_out_port = dst_port
        let pod_ip = pod_ip.to_string();
        return 
         if self.traffic_type == 1 {
            // DERIVE INGRESS
            if self.ip_protocol.eq(&"TCP") {
                (
                    "INGRESS".to_string(),
                    pod_ip,
                    self.src_port,
                    self.dst_addr.to_string(),
                    self.dst_port,
                )
            } else {
                //UDP
                (
                    "EGRESS".to_string(),
                    pod_ip,
                    0,
                    self.dst_addr.to_string(),
                    self.dst_port,
                )
            }
        } else {
            // DERIVE INGRESS
            if self.ip_protocol.eq(&"TCP") {
                (
                    "EGRESS".to_string(),
                    pod_ip,
                    self.dst_port,
                    self.src_addr.to_string(),
                    self.src_port,
                )
            } else {
                // UDP
                (
                    "INGRESS".to_string(),
                    pod_ip,
                    self.dst_port,
                    self.src_addr.to_string(),
                    0,
                )
            }
        };


    }
    pub async fn parse_message(&self,pod_ip:&str) -> Result<(), Error> {
        let pod_namespace = &self.pod_data.pod_namespace;
        let pod_name = &self.pod_data.pod_name;
        let (traffic_type, pod_ip, pod_port, traffic_in_out_ip, traffic_in_out_port) =
            self.define_traffic(pod_ip);
        let z = json!(PodTraffic {
            uuid: Uuid::new_v4().to_string(),
            pod_name: pod_name.to_string(),
            pod_namespace: pod_namespace.to_owned(),
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
