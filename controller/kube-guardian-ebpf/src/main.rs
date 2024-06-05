#![no_std]
#![no_main]

const IPV4_PROTOCOL_NUMBER: u16 = 8u16;
const IPV6_PROTOCOL_NUMBER: u16 = 41u16;
const TCP_PROTOCOL_NUMBER: u16 = 6u16;
const UDP_PROTOCOL_NUMBER: u16 = 17u16;

type TaskStructPtr = *mut task_struct;

use aya_ebpf::{ 
 cty::c_long, helpers::{ bpf_get_current_task, bpf_probe_read, bpf_probe_read_kernel}, macros::{map, tracepoint}, maps::PerfEventArray, programs::TracePointContext
};
use aya_log_ebpf::{debug, info};
use kube_guardian_common::TrafficLog;

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)] 
mod bindings;

use bindings::{iphdr, ns_common, nsproxy, pid_namespace, sk_buff, task_struct, tcphdr, udphdr};


#[map]
pub static EVENTS: PerfEventArray<TrafficLog> = PerfEventArray::new(0);



#[tracepoint]
pub fn kube_guardian(ctx: TracePointContext) -> u32 {
    match unsafe { try_kube_guardian(ctx) } {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_kube_guardian(ctx: TracePointContext) -> Result<c_long, c_long> {

    let tp: *const sk_buff = ctx.read_at(8)?;
    let eth_proto = bpf_probe_read(&(*tp).__bindgen_anon_5.headers.as_ref().protocol as *const u16).map_err(|_| 100u32)?;

    if eth_proto != IPV4_PROTOCOL_NUMBER && eth_proto != IPV6_PROTOCOL_NUMBER {
        return Ok(0);
    }

    // For now let's only handle IPv4
    if eth_proto == IPV6_PROTOCOL_NUMBER {
        return Ok(0);
    }

    let head = bpf_probe_read(&(*tp).head as *const *mut u8).map_err(|_| 100u8)?;

      // Calculate the network header position
      let network_header_offset = bpf_probe_read(&(*tp).__bindgen_anon_5.__bindgen_anon_1.as_ref().network_header  as *const u16).map_err(|_| 100u16)?;

      // Read IPv4 header
      let nw_hdr_ptr = head.add(network_header_offset as usize);

      let nw_hdr = bpf_probe_read(nw_hdr_ptr as *const iphdr).map_err(|_| 101u8)?;
  
    //   // Check the protocol in the IPv4 header
    //   if ipv4_hdr.protocol != TCP_PROTOCOL_NUMBER && ipv4_hdr.protocol != UDP_PROTOCOL_NUMBER {
    //       return Ok(0);
    //   }
    let proto = nw_hdr.protocol as u16;
    let saddr = nw_hdr.__bindgen_anon_1.addrs.saddr as u32;
    let daddr = nw_hdr.__bindgen_anon_1.addrs.daddr as u32;

    if proto != UDP_PROTOCOL_NUMBER && proto != TCP_PROTOCOL_NUMBER {
        return Ok(0);
    }

    let mut sport: u16 = 0;
    let mut dport: u16 = 0;
    let mut syn : u16 = 0;
    let mut ack: u16= 0 ;

    match proto {
        TCP_PROTOCOL_NUMBER => {
            let transport_header_offset =
                bpf_probe_read(&(*tp).__bindgen_anon_5.headers.as_ref().transport_header as *const u16).map_err(|_| 100u16)?;

            let trans_hdr_ptr = head.add(transport_header_offset as usize);
            let trans_hdr = bpf_probe_read(trans_hdr_ptr as *const tcphdr).map_err(|_| 101u8)?;
            sport = u16::from_be(trans_hdr.source);
            dport = u16::from_be(trans_hdr.dest);
            syn = trans_hdr.syn();
            ack = trans_hdr.ack()
        },
        UDP_PROTOCOL_NUMBER => {
            let transport_header_offset =
                bpf_probe_read(&(*tp).__bindgen_anon_5.headers.as_ref().transport_header as *const u16).map_err(|_| 100u16)?;

            let trans_hdr_ptr = head.add(transport_header_offset as usize);
            let trans_hdr = bpf_probe_read(trans_hdr_ptr as *const udphdr).map_err(|_| 101u8)?;
            sport = u16::from_be(trans_hdr.source);
            dport = u16::from_be(trans_hdr.dest);
            syn = 2;
            ack = 2;
        },
        _ => (),
    };

  let task: TaskStructPtr = bpf_get_current_task() as TaskStructPtr;
        let inum = match get_ns_proxy(task){
        Ok(i)=> i,
        Err(_)=> return Ok(1)
    };
    
    // info!(&ctx, " common_type {}:{} -> {}:{}", saddr,sport,daddr);
    let log_entry = TrafficLog {
       saddr,
       daddr,
       sport,
       dport,
        inum,
        syn,
        ack,
        };
        EVENTS.output(&ctx, &log_entry, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

unsafe fn get_ns_proxy(task: TaskStructPtr) -> Result<u32, i64> {
    let nsproxy: *mut nsproxy =  bpf_probe_read_kernel(&(*task).nsproxy)?;
    let net_ns: *mut pid_namespace =  bpf_probe_read_kernel(&(*nsproxy).pid_ns_for_children)?;
    let nsc: ns_common = bpf_probe_read_kernel(&(*net_ns).ns)?;
    let ns: u32 = nsc.inum;
    Ok(ns)
}
