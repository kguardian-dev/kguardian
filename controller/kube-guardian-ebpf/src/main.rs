#![no_std]
#![no_main]


use aya_bpf::{
    bindings::__sk_buff, cty::c_long, helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid}, macros::{map, tracepoint}, maps::{HashMap, PerfEventArray}, programs::{sk_buff, SkBuffContext, TracePointContext}
};


use kube_guardian_common::TrafficLog;
use network_types::{
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use aya_bpf::BpfContext;

#[map]
pub static EVENTS: PerfEventArray<TrafficLog> = PerfEventArray::new(0);

// // traffic_type 1
// #[cgroup_skb{name="egress"}]
// pub fn kube_guardian_egress(ctx: TracePointContext) -> i32 {
//     match unsafe{try_kube_guardian(ctx, 1) }{
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }

// traffic_type 0
#[tracepoint(name="net_dev_queue")]
pub fn kube_guardian(ctx: TracePointContext) -> c_long {
    match unsafe{ try_kube_guardian(ctx, 0)} {
        Ok(ret) => ret,
        Err(ret) => ret,
    }

}



const ETH_P_IP: u32 = 8;

unsafe fn try_kube_guardian(mut ctx: TracePointContext, traffic: u32) -> Result<c_long, c_long> {
    //let skb_ctx = SkBuffContext::new(ctx.as_ptr() as *mut __sk_buff);
    // let protocol = unsafe { (*ctx.skb.skb).protocol };
    // let if_index = unsafe {(*ctx.skb.skb).ifindex};
    // let local_ip4 =  unsafe {(*ctx.skb.skb).local_ip4};
    let cgroup_id = ctx.pid();
    let thread_id = ctx.tgid();
    
    // if protocol != ETH_P_IP {
    //     return Ok(1);
    // }

    // let ip = match ctx.load::<Ipv4Hdr>(0).map_err(|_| ()) {
    //     Ok(iphdr) => iphdr,
    //     Err(_) => return Ok(1),
    // };
    // let src_ip = u32::from_be(ip.src_addr);
    // let dest_ip = u32::from_be(ip.dst_addr);

    // let (src_port, dst_port, syn, ack) = match ip.proto {
    //     IpProto::Tcp => {
    //         let tcp_hdr = match ctx.load::<TcpHdr>(Ipv4Hdr::LEN).map_err(|_| ()) {
    //             Ok(tcp_hrd) => tcp_hrd,
    //             Err(_) => return Ok(1),
    //         };

    //         (u16::from_be(unsafe { tcp_hdr.source}), u16::from_be(unsafe { tcp_hdr.dest}), tcp_hdr.syn(), tcp_hdr.ack())
    //     }
    //     IpProto::Udp => {
    //         let udp_hdr = match ctx.load::<UdpHdr>(Ipv4Hdr::LEN).map_err(|_| ()) {
    //             Ok(udp_hdr) => udp_hdr, 
    //             Err(_) => return Ok(1),
    //         };
            
    //     // if the traffic is ingress for the first time
    //     let mark = unsafe { (*ctx.skb.skb).mark };
    //     if !mark.eq(&99) {
    //         // first time ingress, 
    //         // track the src_ip, dest_ip, dest_port and set the mark as 99
    //         ctx.set_mark(99);
    //         (0, u16::from_be(unsafe { udp_hdr.dest}), 2, 2)

    //     }else{
    //         return Ok(1)
    //     }
        
    //     }
    //     _ => return Ok(1),
    // };

    // if syn.eq(&1) && ack.eq(&1) && traffic.eq(&0) {
    //     // Egress of the intiator
    //     let log_entry = TrafficLog {
    //         source_addr: src_ip,
    //         dest_addr: dest_ip,
    //         syn,
    //         ack,
    //         traffic,
    //         if_index,
    //         local_ip4,
    //         src_port,
    //         dst_port:0,
    //         cgroup_id,
    //     };
    //     EVENTS.output(&ctx, &log_entry, 0);
    // }else if syn.eq(&1) && ack.eq(&1) && traffic.eq(&1) {
    //     // Ingress of receiver
    //     let log_entry = TrafficLog {
    //         source_addr: src_ip,
    //         dest_addr: dest_ip,
    //         syn,
    //         ack,
    //         traffic,
    //         if_index,
    //         local_ip4,
    //         src_port,
    //         dst_port:0,
    //         cgroup_id,
    //     };
    //     EVENTS.output(&ctx, &log_entry, 0);
    // } else if syn.eq(&2) && ack.eq(&2) {
    //     // udp
    //     let log_entry = TrafficLog {
    //         source_addr: src_ip,
    //         dest_addr: dest_ip,
    //         syn,
    //         ack,
    //         traffic,
    //         if_index,
    //         local_ip4,
    //         src_port,
    //         dst_port,
    //         cgroup_id,
    //     };
    //     EVENTS.output(&ctx, &log_entry, 0);

    // }
    let log_entry = TrafficLog {
        // source_addr: src_ip,
        // dest_addr: dest_ip,
        // syn,
        // ack,
        // traffic,
        // if_index,
        // local_ip4,
        // src_port,
        // dst_port,
        cgroup_id,
        thread_id,
    };
    EVENTS.output(&ctx, &log_entry, 0);

    Ok(0)
    
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}



