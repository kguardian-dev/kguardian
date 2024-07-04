#![no_std]
#![no_main]

const IPV4_PROTOCOL_NUMBER: u16 = 8u16;
const IPV6_PROTOCOL_NUMBER: u16 = 41u16;
const TCP_PROTOCOL_NUMBER: u16 = 6u16;
const UDP_PROTOCOL_NUMBER: u16 = 17u16;



type TaskStructPtr = *mut task_struct;

use aya_ebpf::{ 
 cty::c_long, helpers::{ bpf_get_current_task, bpf_probe_read, bpf_probe_read_kernel}, macros::{map, tracepoint}, maps::{HashMap, PerfEventArray}, programs::TracePointContext
};


use kube_guardian_common::{TrafficLog, BPF_MAPS_CAPACITY};


#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)] 
mod bindings;

use bindings::{iphdr, net_device, ns_common, nsproxy, pid_namespace, sk_buff, task_struct, tcphdr, udphdr};


#[map]
pub static EVENTS: PerfEventArray<TrafficLog> = PerfEventArray::new(0);

#[map(name = "IFINDEX_MAP")]
static mut IFINDEX_MAP: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(BPF_MAPS_CAPACITY, 0);


#[tracepoint]
pub fn kube_guardian_egress(ctx: TracePointContext) -> u32 {
    match unsafe { try_kube_guardian(ctx,0) } {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn kube_guardian_ingress(ctx: TracePointContext) -> u32 {
    match unsafe { try_kube_guardian(ctx,1) } {
        Ok(ret) => ret as u32,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_kube_guardian(ctx: TracePointContext, traffic_type: i32) -> Result<c_long, c_long> {
    
    ///sys/kernel/debug/tracing/events/net/net_*
    let tp: *const sk_buff = ctx.read_at(8)?;
    let dev_ptr = bpf_probe_read(&(*tp).__bindgen_anon_1.__bindgen_anon_1.__bindgen_anon_1.dev as *const *mut net_device).map_err(|_| 100u32)?;
  
    let if_index= bpf_probe_read(&(*dev_ptr).ifindex as *const i32).map_err(|_|100i32)?;

    let if_index_map = unsafe { IFINDEX_MAP.get(&(if_index as u32)) }.ok_or(0)?;

    if if_index_map.eq(&1){

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
            if let Ok((s, d, sy, a)) = process_tcp(tp, head) {
                sport = s;
                dport = d;
                syn = sy;
                ack = a;
            }
        },
        UDP_PROTOCOL_NUMBER => {
            if let Ok((s, d, sy, a)) = process_udp(tp, head) {
                sport = s;
                dport = d;
                syn = sy;
                ack = a;
            }
        },
        _ => (),
    }

  let task: TaskStructPtr = bpf_get_current_task() as TaskStructPtr;
        let inum = match get_ns_proxy(task){
        Ok(i)=> i,
        Err(_)=> return Ok(1)
    };
    
    let log_entry = TrafficLog {
       saddr,
       daddr,
       sport,
       dport,
        inum,
        syn,
        ack,
        if_index,
        traffic_type,
        };
        EVENTS.output(&ctx, &log_entry, 0);
    }
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

unsafe fn get_transport_header_ptr(tp: *const sk_buff , head: *const u8) -> Result<*const u8, u16> {
    let transport_header_offset =
        bpf_probe_read(&(*tp).__bindgen_anon_5.headers.as_ref().transport_header as *const u16).map_err(|_| 100u16)?;
    
    let trans_hdr_ptr = head.add(transport_header_offset as usize);
    Ok(trans_hdr_ptr)
}

unsafe fn process_tcp(tp: *const sk_buff, head: *const u8) -> Result<(u16, u16, u16, u16), u16> {
    let trans_hdr_ptr = get_transport_header_ptr(tp, head)?;
    let trans_hdr = bpf_probe_read(trans_hdr_ptr as *const tcphdr).map_err(|_| 101u8)?;
    
    let sport = u16::from_be(trans_hdr.source);
    let dport = u16::from_be(trans_hdr.dest);
    let syn = trans_hdr.syn();
    let ack = trans_hdr.ack();
    
    Ok((sport, dport, syn, ack))
}

unsafe fn process_udp(tp: *const sk_buff , head: *const u8) -> Result<(u16, u16, u16, u16), u16> {
    let trans_hdr_ptr = get_transport_header_ptr(tp, head)?;
    let trans_hdr = bpf_probe_read(trans_hdr_ptr as *const udphdr).map_err(|_| 101u8)?;
    
    let sport = u16::from_be(trans_hdr.source);
    let dport = u16::from_be(trans_hdr.dest);
    let syn = 2;
    let ack = 2;
    
    Ok((sport, dport, syn, ack))
}

