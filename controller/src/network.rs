use crate::{api_post_call, Error, PodInspect, PodTraffic};
use chrono::Utc;
use dashmap::DashMap;
use moka::future::Cache;
use serde_json::json;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use tracing::{debug, error};
use uuid::Uuid;

// Network event kind constants (from eBPF program). The eBPF probe in
// network_probe.bpf.c emits these values; userspace must agree on the
// numeric → (direction, protocol) mapping.
//
// Known gap: there is NO kind for INGRESS UDP. The eBPF probe traces
// `udp_sendmsg` and emits kind=3, treated here as EGRESS UDP. Inbound
// UDP (e.g. CoreDNS receiving queries, syslog, NTP) is not tracked.
// Adding it requires a new udp_recvmsg-side tracepoint in the eBPF
// program — out of scope for this comment, but pin the gap so a
// future contributor doesnt assume INGRESS_UDP exists silently.
const KIND_EGRESS_TCP: u16 = 1;
const KIND_INGRESS_TCP: u16 = 2;
const KIND_EGRESS_UDP: u16 = 3;

lazy_static::lazy_static! {
    static ref TRAFFIC_CACHE: Arc<Cache<TrafficKey, ()>> = Arc::new(Cache::new(10000));
}

pub mod network_probe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/network_probe.skel.rs"
    ));
}

pub mod netpolicy_drop {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/netpolicy_drop.skel.rs"
    ));
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct TrafficKey {
    pod_name: String,
    pod_ip: String,
    pod_port: String,
    traffic_in_out_ip: String,
    traffic_in_out_port: String,
    traffic_type: String,
    ip_protocol: String,
    decision: String,
}

/// Wire length of an address as the eBPF probes emit it. IPv4 travels
/// v4-mapped (::ffff:a.b.c.d) inside these 16 bytes — see
/// `wire_addr_to_ip`.
pub const WIRE_ADDR_LEN: usize = 16;

/// Mirror of `struct network_event_data` in
/// controller/src/bpf/network_probe.bpf.c.
///
/// The ring-buffer callback in bpf.rs reinterprets raw ring-buffer bytes
/// as this type with a pointer cast, so field order, width AND padding
/// must match the C struct exactly — a mismatch is silent memory
/// corruption, not a compile error. Both sides carry static assertions
/// on the same offsets (`_Static_assert` in the .bpf.c, the
/// `wire_layout_*` tests below); change one and you must change both.
///
/// C layout (48 bytes):
///   0  u64 inum | 8  u8 saddr[16] | 24 u8 daddr[16]
///   40 u16 sport | 42 u16 dport | 44 u16 kind | 46 u16 _pad
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEventData {
    pub inum: u64,
    saddr: [u8; WIRE_ADDR_LEN],
    daddr: [u8; WIRE_ADDR_LEN],
    sport: u16,
    dport: u16,
    pub kind: u16,
    _pad: u16,
}

/// Mirror of `struct policy_drop_event` in
/// controller/src/bpf/netpolicy_drop.bpf.c. Same pointer-cast contract
/// as `NetworkEventData` above.
///
/// C layout (64 bytes):
///   0  u64 timestamp | 8  u64 inum | 16 u8 saddr[16] | 32 u8 daddr[16]
///   48 u16 sport | 50 u16 dport | 52 u32 syn_retries | 56 u8 protocol
///   57 u8 _pad[7]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PolicyDropEvent {
    pub timestamp: u64,
    pub inum: u64,
    pub saddr: [u8; WIRE_ADDR_LEN],
    pub daddr: [u8; WIRE_ADDR_LEN],
    pub sport: u16,
    pub dport: u16,
    pub syn_retries: u32,
    pub protocol: u8,
    pub _pad: [u8; 7],
}

/// Turn the 16-byte wire address the eBPF probes emit into an `IpAddr`,
/// un-mapping v4-mapped addresses (::ffff:a.b.c.d) back to a real
/// `Ipv4Addr`.
///
/// THIS IS THE ONLY PLACE THAT UN-MAPS, AND IT MUST RUN EXACTLY ONCE PER
/// ADDRESS. The kernel side deliberately has a single representation —
/// 16 bytes, IPv4 carried v4-mapped — so there is one code path in BPF
/// and no family discriminator on the wire. Everything downstream of
/// here (the broker's pod/service correlation, the advisor's policy
/// generation) matches addresses as strings against `pod_ip` /
/// `svc_ip`, which are plain dotted quads for IPv4. An address that
/// escapes still spelled "::ffff:10.0.0.1" matches no pod anywhere and
/// silently degrades that flow's generated rule to an ipBlock — no
/// error, no log, just worse policy. Do not add a second un-mapping
/// step, and do not remove this one.
///
/// Note `to_ipv4_mapped` (not `to_ipv4`): the latter also converts
/// IPv4-*compatible* addresses (::a.b.c.d) and would turn `::1` into
/// `0.0.0.1`.
pub fn wire_addr_to_ip(addr: [u8; WIRE_ADDR_LEN]) -> IpAddr {
    let v6 = Ipv6Addr::from(addr);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// Inverse of `wire_addr_to_ip`: render an `IpAddr` in the 16-byte
/// v4-mapped wire form the eBPF maps are keyed on. Used to write the
/// `ignore_ips` map key from bpf.rs; the kernel compares that key
/// byte-for-byte against what `read_sock_addrs` produced, so the two
/// representations must agree exactly.
pub fn ip_to_wire_addr(ip: IpAddr) -> [u8; WIRE_ADDR_LEN] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Canonical string form for every IP that leaves the controller.
///
/// Cross-component contract: the broker canonicalises inbound lookups
/// the same way, so both sides must agree on spelling — lowercase,
/// `::`-compressed for IPv6, plain dotted quad for IPv4. That is
/// exactly `IpAddr::to_string()`, so parse and re-render rather than
/// forwarding whatever text the Kubernetes API happened to hand us
/// ("2001:DB8:0:0::1" and "2001:db8::1" are the same address but not
/// the same map key).
///
/// Deliberately routed through the same wire round-trip the eBPF path
/// uses, so a v4-mapped spelling ("::ffff:10.0.0.1") collapses to the
/// dotted quad here exactly as it does in `wire_addr_to_ip`. One
/// address must have one spelling no matter which side produced it.
///
/// Anything unparseable is passed through untouched — it is not this
/// function's job to drop data it doesn't understand, and the callers
/// already filter non-addresses like the literal "None" clusterIP.
pub fn canonicalize_ip(s: &str) -> String {
    match s.parse::<IpAddr>() {
        Ok(ip) => wire_addr_to_ip(ip_to_wire_addr(ip)).to_string(),
        Err(_) => s.to_string(),
    }
}

pub async fn handle_network_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<NetworkEventData>,
    container_map: Arc<DashMap<u64, PodInspect>>,
) -> Result<(), Error> {
    // Batching configuration
    const BATCH_SIZE: usize = 100;
    const BATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut last_flush = tokio::time::Instant::now();

    loop {
        // Use timeout to ensure we flush even if batch not full
        let event = tokio::time::timeout(BATCH_TIMEOUT, event_receiver.recv()).await;

        match event {
            Ok(Some(event)) => {
                // DashMap provides lock-free reads - no need for explicit locking!
                if let Some(pod_inspect) = container_map.get(&event.inum) {
                    if let Some(traffic) = build_traffic_event(&event, &pod_inspect).await {
                        batch.push(traffic);
                    }
                }

                // Flush when (a) batch is full OR (b) BATCH_TIMEOUT
                // has passed since the last flush. Pre-fix, only the
                // batch-full path was checked here — events arriving
                // every <BATCH_TIMEOUT with sub-batch-size volume kept
                // resetting the tokio::time::timeout window, so the
                // Err(_) branch never fired and the batch sat
                // unflushed indefinitely. Steady-state low-volume
                // traffic (typical for a pod doing periodic checks)
                // would never make it to the broker.
                if should_flush(batch.len(), last_flush.elapsed(), BATCH_SIZE, BATCH_TIMEOUT) {
                    flush_network_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
            Ok(None) => {
                // Channel closed, flush remaining and exit
                if !batch.is_empty() {
                    flush_network_batch(&mut batch).await;
                }
                break;
            }
            Err(_) => {
                // Timeout reached, flush if we have any events
                if !batch.is_empty() {
                    flush_network_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
        }
    }
    Ok(())
}

/// Decide whether to flush the current batch. Pure function so the
/// rate-shaping policy can be unit-tested without async runtime
/// scaffolding. Flush when:
///
/// - batch reached BATCH_SIZE, OR
/// - BATCH_TIMEOUT has passed since the last flush AND we have at
///   least one event to send (no point flushing an empty batch).
pub(crate) fn should_flush(
    batch_len: usize,
    elapsed_since_last_flush: std::time::Duration,
    batch_size: usize,
    batch_timeout: std::time::Duration,
) -> bool {
    if batch_len == 0 {
        return false;
    }
    batch_len >= batch_size || elapsed_since_last_flush >= batch_timeout
}

/// Cap the in-memory pending batch to this many events. On a
/// prolonged broker outage, batch.clear() would have dropped every
/// failed flush — but the previous code (pre-iteration-68) silently
/// swallowed 5xx as success, so the clear-on-failure was effectively
/// a no-op. Now that errors are visible (iteration 68 promoted
/// non-2xx to errors), holding the batch lets us retry on the next
/// successful flush. The cap prevents unbounded memory growth if the
/// broker stays down indefinitely.
const MAX_PENDING_EVENTS: usize = 1000; // 10× BATCH_SIZE

/// Drop oldest entries from `batch` until `batch.len() <= max`.
/// Returns the number of entries dropped (0 if no drop needed).
/// Pure helper so the policy is unit-testable without async runtime.
pub(crate) fn cap_batch(batch: &mut Vec<PodTraffic>, max: usize) -> usize {
    if batch.len() <= max {
        return 0;
    }
    let drop = batch.len() - max;
    batch.drain(..drop);
    drop
}

async fn flush_network_batch(batch: &mut Vec<PodTraffic>) {
    if batch.is_empty() {
        return;
    }

    debug!("Flushing network event batch of {} events", batch.len());

    match api_post_call(json!(batch), "pod/traffic/batch").await {
        Ok(()) => {
            batch.clear();
        }
        Err(e) => {
            // Hold the batch for retry on the next flush. Pre-fix this
            // path also cleared, losing every event on a transient
            // broker failure (the pre-iteration-68 swallow-of-5xx
            // masked the bug). Now we retain, but cap to prevent OOM.
            error!(
                "Failed to post network event batch of {} events: {}; will retry next flush",
                batch.len(),
                e
            );
            let dropped = cap_batch(batch, MAX_PENDING_EVENTS);
            if dropped > 0 {
                error!(
                    "Pending event queue overflow during broker outage; dropped {} oldest events (cap = {})",
                    dropped, MAX_PENDING_EVENTS
                );
            }
        }
    }
}

async fn build_traffic_event(data: &NetworkEventData, pod_data: &PodInspect) -> Option<PodTraffic> {
    let src = wire_addr_to_ip(data.saddr);
    let dst = wire_addr_to_ip(data.daddr);
    let sport = data.sport;
    let dport = data.dport;

    // Use pattern matching for cleaner event kind handling
    let (traffic_type, protocol, pod_port, traffic_in_out_port) = match data.kind {
        KIND_INGRESS_TCP => ("INGRESS", "TCP", sport, 0),
        KIND_EGRESS_TCP => ("EGRESS", "TCP", 0, dport),
        KIND_EGRESS_UDP => ("EGRESS", "UDP", 0, dport),
        _ => {
            debug!("Unknown network event kind: {}", data.kind);
            return None;
        }
    };

    let traffic_in_out_ip = dst.to_string();

    debug!(
        "Inum : {} src {}:{},dst {}:{}, traffic type {:?} kind {:?}",
        data.inum, src, sport, dst, dport, traffic_type, data.kind
    );

    // Skip if source and destination are the same (early return before allocations)
    if pod_data.status.pod_ip.eq(&traffic_in_out_ip) {
        return None;
    }

    // Build cache key with minimal allocations to check duplicates first
    let cache_key = TrafficKey {
        pod_name: pod_data.status.pod_name.to_string(),
        pod_ip: pod_data.status.pod_ip.to_string(),
        pod_port: pod_port.to_string(),
        traffic_in_out_ip: traffic_in_out_ip.clone(),
        traffic_in_out_port: traffic_in_out_port.to_string(),
        traffic_type: traffic_type.to_string(),
        ip_protocol: protocol.to_string(),
        decision: "ALLOW".to_string(),
    };

    // Check cache to avoid duplicates - return early if duplicate
    if TRAFFIC_CACHE.contains_key(&cache_key) {
        debug!(
            "Skipping duplicate network event for pod: {}",
            pod_data.status.pod_name
        );
        return None;
    }

    // Only allocate traffic struct if not in cache
    let traffic = PodTraffic {
        uuid: Uuid::new_v4().to_string(),
        pod_name: pod_data.status.pod_name.to_string(),
        pod_namespace: pod_data.status.pod_namespace.to_owned(),
        pod_ip: pod_data.status.pod_ip.to_string(),
        pod_port: Some(pod_port.to_string()),
        traffic_in_out_ip: Some(traffic_in_out_ip),
        traffic_in_out_port: Some(traffic_in_out_port.to_string()),
        traffic_type: Some(traffic_type.to_string()),
        ip_protocol: Some(protocol.to_string()),
        decision: Some("ALLOW".to_string()),
        time_stamp: Utc::now().naive_utc(),
    };

    debug!("Adding traffic event to batch: {:?}", cache_key);

    // Insert into cache immediately to prevent duplicates in same batch
    TRAFFIC_CACHE.insert(cache_key, ()).await;

    Some(traffic)
}

fn proto_to_string(proto: u8) -> String {
    match proto {
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        1 => "ICMP".to_string(),
        58 => "ICMPv6".to_string(),
        _ => format!("UNKNOWN({})", proto),
    }
}

pub async fn handle_policy_drop_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<PolicyDropEvent>,
    container_map: Arc<DashMap<u64, PodInspect>>,
) -> Result<(), Error> {
    // Batching configuration
    const BATCH_SIZE: usize = 100;
    const BATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut last_flush = tokio::time::Instant::now();

    debug!("Network policy drop event handler started");

    loop {
        // Use timeout to ensure we flush even if batch not full
        let event = tokio::time::timeout(BATCH_TIMEOUT, event_receiver.recv()).await;

        match event {
            Ok(Some(event)) => {
                if let Some(pod_inspect) = container_map.get(&event.inum) {
                    if let Some(drop_event) = build_policy_drop_event(&event, &pod_inspect).await {
                        batch.push(drop_event);
                    }
                } else {
                    debug!("No pod found for network namespace inode: {}", event.inum);
                }

                // Same fix as handle_network_events: also flush on
                // BATCH_TIMEOUT elapsed in the success branch, not
                // only in the timeout branch. See should_flush.
                if should_flush(batch.len(), last_flush.elapsed(), BATCH_SIZE, BATCH_TIMEOUT) {
                    flush_network_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
            Ok(None) => {
                // Channel closed, flush remaining and exit
                if !batch.is_empty() {
                    flush_network_batch(&mut batch).await;
                }
                debug!("Network policy drop event receiver closed");
                break;
            }
            Err(_) => {
                // Timeout reached, flush if we have any events
                if !batch.is_empty() {
                    flush_network_batch(&mut batch).await;
                    last_flush = tokio::time::Instant::now();
                }
            }
        }
    }
    Ok(())
}

async fn build_policy_drop_event(
    data: &PolicyDropEvent,
    pod_data: &PodInspect,
) -> Option<PodTraffic> {
    let s_ip = wire_addr_to_ip(data.saddr);
    let d_ip = wire_addr_to_ip(data.daddr);
    let s_port = 0;
    let d_port = data.dport;
    let protocol_str = proto_to_string(data.protocol);

    debug!(
        "Network Policy Drop: Pod: {}, Namespace: {:?}, Src: {}:{}, Dst: {}:{}, Protocol: {}, SYN Retries: {}",
        pod_data.status.pod_name,
        pod_data.status.pod_namespace,
        s_ip,
        s_port,
        d_ip,
        d_port,
        protocol_str,
        data.syn_retries
    );

    let d_ip_str = d_ip.to_string();

    // Skip if source and destination are the same (early return before allocations)
    if pod_data.status.pod_ip.eq(&d_ip_str) {
        return None;
    }

    // Build cache key with minimal allocations to check duplicates first
    let cache_key = TrafficKey {
        pod_name: pod_data.status.pod_name.to_string(),
        pod_ip: pod_data.status.pod_ip.to_string(),
        pod_port: s_port.to_string(),
        traffic_in_out_ip: d_ip_str.clone(),
        traffic_in_out_port: d_port.to_string(),
        traffic_type: "EGRESS".to_string(),
        ip_protocol: protocol_str.clone(),
        decision: "DROP".to_string(),
    };

    // Check cache to avoid duplicates - return early if duplicate
    if TRAFFIC_CACHE.contains_key(&cache_key) {
        debug!(
            "Skipping duplicate network policy drop event for pod: {}",
            pod_data.status.pod_name
        );
        return None;
    }

    // Only allocate drop event if not in cache
    let drop_event = PodTraffic {
        uuid: Uuid::new_v4().to_string(),
        pod_name: pod_data.status.pod_name.to_string(),
        pod_namespace: pod_data.status.pod_namespace.to_owned(),
        pod_ip: pod_data.status.pod_ip.to_string(),
        pod_port: Some(s_port.to_string()),
        traffic_in_out_ip: Some(d_ip_str),
        traffic_in_out_port: Some(d_port.to_string()),
        traffic_type: Some("EGRESS".to_string()),
        ip_protocol: Some(protocol_str),
        decision: Some("DROP".to_string()),
        time_stamp: Utc::now().naive_utc(),
    };

    // Insert into cache immediately to prevent duplicates in same batch
    TRAFFIC_CACHE.insert(cache_key, ()).await;

    Some(drop_event)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- wire layout ----------------------------------------------
    //
    // These pin the Rust mirrors to the byte layout of the C structs in
    // src/bpf/*.bpf.c, which carry matching _Static_asserts. bpf.rs
    // reinterprets raw ring-buffer bytes as these types with a pointer
    // cast, so a divergence is not a compile error — it is silently
    // reading the wrong bytes (ports out of an address, an address out
    // of a timestamp) with no diagnostic anywhere.

    #[test]
    fn wire_layout_network_event_data() {
        use std::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<NetworkEventData>(), 48);
        assert_eq!(align_of::<NetworkEventData>(), 8);
        assert_eq!(offset_of!(NetworkEventData, inum), 0);
        assert_eq!(offset_of!(NetworkEventData, saddr), 8);
        assert_eq!(offset_of!(NetworkEventData, daddr), 24);
        assert_eq!(offset_of!(NetworkEventData, sport), 40);
        assert_eq!(offset_of!(NetworkEventData, dport), 42);
        assert_eq!(offset_of!(NetworkEventData, kind), 44);
        assert_eq!(offset_of!(NetworkEventData, _pad), 46);
    }

    #[test]
    fn wire_layout_policy_drop_event() {
        use std::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<PolicyDropEvent>(), 64);
        assert_eq!(align_of::<PolicyDropEvent>(), 8);
        assert_eq!(offset_of!(PolicyDropEvent, timestamp), 0);
        assert_eq!(offset_of!(PolicyDropEvent, inum), 8);
        assert_eq!(offset_of!(PolicyDropEvent, saddr), 16);
        assert_eq!(offset_of!(PolicyDropEvent, daddr), 32);
        assert_eq!(offset_of!(PolicyDropEvent, sport), 48);
        assert_eq!(offset_of!(PolicyDropEvent, dport), 50);
        assert_eq!(offset_of!(PolicyDropEvent, syn_retries), 52);
        assert_eq!(offset_of!(PolicyDropEvent, protocol), 56);
        assert_eq!(offset_of!(PolicyDropEvent, _pad), 57);
    }

    /// Decode a wire event the way bpf.rs does — raw bytes straight out
    /// of the ring buffer through a pointer cast — using a byte string
    /// laid out by hand from the C struct definition. If the Rust mirror
    /// ever drifts from the C one, this reads garbage and fails.
    #[test]
    fn wire_bytes_decode_as_the_c_struct_laid_them_out() {
        let mut raw = [0u8; 48];
        raw[0..8].copy_from_slice(&4026531840u64.to_ne_bytes()); // inum

        // saddr = ::ffff:10.0.0.1
        raw[8 + 10] = 0xff;
        raw[8 + 11] = 0xff;
        raw[8 + 12..8 + 16].copy_from_slice(&[10, 0, 0, 1]);
        // daddr = 2001:db8::53
        raw[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x53,
        ]);
        raw[40..42].copy_from_slice(&45678u16.to_ne_bytes()); // sport
        raw[42..44].copy_from_slice(&53u16.to_ne_bytes()); // dport
        raw[44..46].copy_from_slice(&KIND_EGRESS_UDP.to_ne_bytes()); // kind

        let ev: NetworkEventData = unsafe { *(raw.as_ptr() as *const NetworkEventData) };
        assert_eq!(ev.inum, 4026531840);
        assert_eq!(wire_addr_to_ip(ev.saddr).to_string(), "10.0.0.1");
        assert_eq!(wire_addr_to_ip(ev.daddr).to_string(), "2001:db8::53");
        assert_eq!(ev.sport, 45678);
        assert_eq!(ev.dport, 53);
        assert_eq!(ev.kind, KIND_EGRESS_UDP);
    }

    // ---- address conversion ---------------------------------------
    //
    // wire_addr_to_ip is the single un-mapping point for every address
    // the eBPF layer produces. If a v4 flow escapes as "::ffff:10.0.0.1"
    // instead of "10.0.0.1" it matches no pod_ip string downstream and
    // every existing pod correlation silently regresses to an ipBlock.

    fn v4_mapped(a: u8, b: u8, c: u8, d: u8) -> [u8; WIRE_ADDR_LEN] {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d]
    }

    #[test]
    fn wire_addr_v4_mapped_unmaps_to_ipv4() {
        let ip = wire_addr_to_ip(v4_mapped(10, 42, 0, 7));
        assert!(ip.is_ipv4(), "v4-mapped must come back as IpAddr::V4");
        // The exact string a pod_ip column holds — no "::ffff:" prefix.
        assert_eq!(ip.to_string(), "10.42.0.7");
    }

    #[test]
    fn wire_addr_native_v6_stays_v6() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1).octets();
        let ip = wire_addr_to_ip(addr);
        assert!(ip.is_ipv6());
        // Canonical form: lowercase hex, :: compression.
        assert_eq!(ip.to_string(), "2001:db8::1");
    }

    #[test]
    fn wire_addr_loopback_v6_is_not_mistaken_for_ipv4() {
        // ::1 is an IPv4-*compatible* address, so Ipv6Addr::to_ipv4()
        // would turn it into 0.0.0.1. to_ipv4_mapped() must not.
        let ip = wire_addr_to_ip(Ipv6Addr::LOCALHOST.octets());
        assert_eq!(ip.to_string(), "::1");
    }

    #[test]
    fn wire_addr_v4_mapped_loopback_unmaps() {
        assert_eq!(
            wire_addr_to_ip(v4_mapped(127, 0, 0, 1)).to_string(),
            "127.0.0.1"
        );
    }

    #[test]
    fn wire_addr_unspecified_both_families() {
        // :: stays ::; ::ffff:0.0.0.0 un-maps to 0.0.0.0. The eBPF side
        // filters both, so neither should reach userspace — but the
        // mapping must still be unambiguous if one ever does.
        assert_eq!(wire_addr_to_ip([0u8; WIRE_ADDR_LEN]).to_string(), "::");
        assert_eq!(
            wire_addr_to_ip(v4_mapped(0, 0, 0, 0)).to_string(),
            "0.0.0.0"
        );
    }

    #[test]
    fn wire_addr_v4_compatible_is_not_unmapped() {
        // ::0.0.0.2 (IPv4-compatible, deprecated) is NOT v4-mapped and
        // must not be silently turned into 0.0.0.2.
        let mut addr = [0u8; WIRE_ADDR_LEN];
        addr[15] = 2;
        assert!(wire_addr_to_ip(addr).is_ipv6());
    }

    #[test]
    fn ip_to_wire_addr_round_trips() {
        for s in [
            "10.0.0.1",
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "2001:db8::53",
            "fe80::1ff:fe23:4567:890a",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert_eq!(
                wire_addr_to_ip(ip_to_wire_addr(ip)),
                ip,
                "round trip failed for {s}"
            );
        }
    }

    #[test]
    fn ip_to_wire_addr_writes_v4_mapped_for_ipv4() {
        // The eBPF side compares this byte-for-byte against what
        // read_sock_addrs built, so the ::ffff: prefix is mandatory —
        // a bare 4-byte-in-16 key would never match.
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(ip_to_wire_addr(ip), v4_mapped(10, 0, 0, 1));
    }

    #[test]
    fn canonicalize_ip_normalises_v6_spelling() {
        assert_eq!(
            canonicalize_ip("2001:0DB8:0000:0000:0000:0000:0000:0001"),
            "2001:db8::1"
        );
        assert_eq!(canonicalize_ip("::FFFF:10.0.0.1"), "10.0.0.1");
        assert_eq!(canonicalize_ip("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn canonicalize_ip_passes_through_non_addresses() {
        // Headless Services carry the literal "None"; callers filter it,
        // but this helper must not mangle or panic on it.
        assert_eq!(canonicalize_ip("None"), "None");
        assert_eq!(canonicalize_ip(""), "");
    }

    #[test]
    fn proto_to_string_known_protocols() {
        // IANA protocol numbers we surface to operators. Drift here
        // would silently mislabel network-policy drop events.
        assert_eq!(proto_to_string(6), "TCP");
        assert_eq!(proto_to_string(17), "UDP");
        assert_eq!(proto_to_string(1), "ICMP");
        assert_eq!(proto_to_string(58), "ICMPv6");
    }

    #[test]
    fn proto_to_string_unknown_carries_value() {
        // Unknown protocol numbers must round-trip the value into the
        // log string so operators can grep for `UNKNOWN(132)` etc.
        assert_eq!(proto_to_string(132), "UNKNOWN(132)");
        assert_eq!(proto_to_string(0), "UNKNOWN(0)");
        assert_eq!(proto_to_string(255), "UNKNOWN(255)");
    }

    // should_flush is the rate-shaping policy for the network event
    // batcher. The pre-fix bug: under steady sub-batch-rate traffic
    // (events arriving every <BATCH_TIMEOUT), `tokio::time::timeout`
    // resets on each recv so the timeout-branch flush never fires —
    // and the success branch only flushed on batch-full. Steady-state
    // light traffic was never reaching the broker. Pinning the policy
    // here so a future refactor can't silently regress it.

    use std::time::Duration;

    #[test]
    fn should_flush_empty_batch_never_flushes() {
        // Flushing an empty batch is wasted work; the helper must
        // gate on at least one event regardless of elapsed time.
        assert!(!should_flush(
            0,
            Duration::from_secs(60),
            100,
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn should_flush_full_batch_flushes_immediately() {
        // batch-full path — flush regardless of elapsed time.
        assert!(should_flush(
            100,
            Duration::from_millis(0),
            100,
            Duration::from_secs(1)
        ));
        assert!(should_flush(
            150,
            Duration::from_millis(0),
            100,
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn should_flush_under_size_under_timeout_holds() {
        // Common case: 50 events in the batch, 500ms since last flush,
        // limits 100 / 1s. Don't flush yet.
        assert!(!should_flush(
            50,
            Duration::from_millis(500),
            100,
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn should_flush_under_size_over_timeout_flushes() {
        // The bug case made concrete: 1 event in batch, 1.5 seconds
        // since last flush, limits 100 / 1s. Pre-fix this was
        // unreachable from the success branch and the timeout
        // branch never fired due to recv resetting the window. Now
        // it MUST flush.
        assert!(should_flush(
            1,
            Duration::from_millis(1500),
            100,
            Duration::from_secs(1)
        ));
        assert!(should_flush(
            50,
            Duration::from_secs(2),
            100,
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn should_flush_at_exact_timeout_boundary() {
        // Exact-equal elapsed should flush — `>=` semantics, not `>`.
        // Otherwise a perfectly-paced 1-event-per-second source
        // would always be one tick behind.
        assert!(should_flush(
            1,
            Duration::from_secs(1),
            100,
            Duration::from_secs(1)
        ));
    }

    // cap_batch enforces the in-memory queue limit during broker
    // outage. The previous "clear-on-failure" lost events; now we
    // hold for retry but must not grow unbounded.

    fn make_traffic(uuid: &str) -> PodTraffic {
        PodTraffic {
            uuid: uuid.to_string(),
            pod_name: String::new(),
            pod_namespace: None,
            pod_ip: String::new(),
            pod_port: None,
            ip_protocol: None,
            traffic_type: None,
            traffic_in_out_ip: None,
            traffic_in_out_port: None,
            decision: None,
            time_stamp: chrono::NaiveDateTime::default(),
        }
    }

    #[test]
    fn cap_batch_under_max_no_drop() {
        let mut batch = vec![make_traffic("a"), make_traffic("b")];
        let dropped = cap_batch(&mut batch, 1000);
        assert_eq!(dropped, 0);
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn cap_batch_at_exact_max_no_drop() {
        let mut batch: Vec<_> = (0..10).map(|i| make_traffic(&i.to_string())).collect();
        let dropped = cap_batch(&mut batch, 10);
        assert_eq!(dropped, 0);
        assert_eq!(batch.len(), 10);
    }

    #[test]
    fn cap_batch_over_max_drops_oldest() {
        // 15 events, cap 10 → drop 5 oldest. Verify the 10 newest
        // remain. Drop-oldest preserves recent observations — what
        // operators most likely care about during outage triage.
        let mut batch: Vec<_> = (0..15).map(|i| make_traffic(&format!("e{}", i))).collect();
        let dropped = cap_batch(&mut batch, 10);
        assert_eq!(dropped, 5);
        assert_eq!(batch.len(), 10);
        // Oldest dropped → first surviving should be e5
        assert_eq!(batch[0].uuid, "e5");
        assert_eq!(batch[9].uuid, "e14");
    }

    #[test]
    fn cap_batch_max_one_keeps_only_newest() {
        let mut batch: Vec<_> = (0..5).map(|i| make_traffic(&format!("e{}", i))).collect();
        let dropped = cap_batch(&mut batch, 1);
        assert_eq!(dropped, 4);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].uuid, "e4");
    }

    #[test]
    fn cap_batch_max_zero_drops_all() {
        // Degenerate but defensible — caller can pass max=0 to fully
        // drain. Shouldn't panic.
        let mut batch = vec![make_traffic("a"), make_traffic("b")];
        let dropped = cap_batch(&mut batch, 0);
        assert_eq!(dropped, 2);
        assert!(batch.is_empty());
    }
}
