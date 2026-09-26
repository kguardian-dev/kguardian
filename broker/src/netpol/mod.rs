//! NetworkPolicy / CiliumNetworkPolicy generation, ported from the advisor
//! Go reference (`advisor/pkg/network`: generator.go, types.go, peer.go,
//! standard_policy.go, cilium_policy.go, cilium_types.go, hostnetwork.go and
//! `advisor/pkg/common.HostCIDR`).
//!
//! The advisor is the source of truth. Its output for every scenario is pinned
//! by the language-neutral goldens in `test/fixtures/generators/networkpolicy`
//! (see the README there), and `tests.rs` rebuilds every one of them. Any
//! behaviour change belongs in the advisor first, then here, the llm-bridge and
//! the frontend.
//!
//! The generator is pure: every broker read goes through [`BrokerData`], so the
//! caller decides whether that is Postgres, an HTTP client or a test stub.
//!
//! ## Peer attribution (peer.go)
//!
//! Pod IPs are recycled, so a row's peer IP is never simply looked up against
//! today's pod table:
//!
//! - a row with a stored `peer_kind` (resolved by the broker at ingest) is used
//!   verbatim — `pod`/`node` by namespace + name (+ uid), `service` only while
//!   the ClusterIP is still that Service. An identity that no longer exists is
//!   *unattributed*; the IP is never re-resolved.
//! - a row without one is resolved by IP: Service first, then every pod record
//!   holding the IP under the start-time guard ([`excluded_by_guard`]).
//!
//! Rules are keyed by `(peer IP, identity)`, so one IP held by two different
//! peers over the retention window yields two rules.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

#[cfg(test)]
mod tests;

/// Which resource to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    /// `networking.k8s.io/v1` NetworkPolicy.
    Standard,
    /// `cilium.io/v2` CiliumNetworkPolicy.
    Cilium,
}

/// `null` on the wire deserialises to the type's default, like a missing key.
/// The broker serialises unset `Option`s as `null`, and every field here uses
/// `""` / empty / `false` as "unknown", exactly as the advisor's Go zero values.
fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// One observed flow of the target pod — advisor `api.PodTraffic`.
///
/// Field names are the broker's `pod_traffic` wire names. The advisor calls
/// the `pod_*` fields `Src*` (they describe the TARGET pod) and the
/// `traffic_in_out_*` fields `Dst*` (they describe the PEER).
///
/// Timestamps are strings, compared after parsing and quoted **verbatim** in
/// the unattributed-peer comment. To match what the advisor sees over HTTP,
/// format a `NaiveDateTime` the way chrono's serde does:
/// `ts.format("%Y-%m-%dT%H:%M:%S%.f")`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PodTraffic {
    /// Target pod IP (advisor `SrcIP`). Not read by the generator.
    #[serde(deserialize_with = "null_default")]
    pub pod_ip: String,
    /// Port on the target pod — the port an INGRESS rule allows (`SrcPodPort`).
    #[serde(deserialize_with = "null_default")]
    pub pod_port: String,
    /// `INGRESS` | `EGRESS`, case-insensitive; anything else is skipped.
    #[serde(deserialize_with = "null_default")]
    pub traffic_type: String,
    /// The peer's IP (`DstIP`).
    #[serde(deserialize_with = "null_default")]
    pub traffic_in_out_ip: String,
    /// Port on the peer — the port an EGRESS rule allows (`DstPort`).
    #[serde(deserialize_with = "null_default")]
    pub traffic_in_out_port: String,
    /// `TCP` | `UDP` | `SCTP`; anything else (including lowercase) is TCP.
    #[serde(deserialize_with = "null_default")]
    pub ip_protocol: String,
    /// When the flow was first observed; "" = unknown (the guard then keeps
    /// every candidate — pre-v4 behaviour).
    #[serde(deserialize_with = "null_default")]
    pub time_stamp: String,
    /// Ingest-time peer identity: `pod` | `node` | `service` | "" (unresolved).
    #[serde(deserialize_with = "null_default")]
    pub peer_kind: String,
    #[serde(deserialize_with = "null_default")]
    pub peer_namespace: String,
    #[serde(deserialize_with = "null_default")]
    pub peer_name: String,
    #[serde(deserialize_with = "null_default")]
    pub peer_uid: String,
    /// Carried for completeness; the reference does not render it.
    #[serde(deserialize_with = "null_default")]
    pub peer_workload_kind: String,
    /// Carried for completeness; the reference does not render it.
    #[serde(deserialize_with = "null_default")]
    pub peer_workload_name: String,
}

/// A pod record — the subset of advisor `api.PodDetail` (a `pod_details` row
/// plus `pod_obj`) the generator reads.
///
/// `labels`, `uid` and `spec_node_name` live inside `pod_obj` on the wire;
/// [`PodDetail::apply_pod_obj`] fills them from it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PodDetail {
    #[serde(deserialize_with = "null_default")]
    pub pod_name: String,
    #[serde(deserialize_with = "null_default")]
    pub pod_namespace: String,
    /// Primary IP. Also the target's own IP for the self-traffic skip.
    #[serde(deserialize_with = "null_default")]
    pub pod_ip: String,
    /// Every address the pod holds (dual-stack); a peer lookup matches either.
    #[serde(deserialize_with = "null_default")]
    pub pod_ips: Vec<String>,
    /// `pod_obj.metadata.labels`.
    #[serde(deserialize_with = "null_default")]
    pub labels: BTreeMap<String, String>,
    /// `pod_obj.metadata.uid`; "" = unknown (never fails a uid match).
    #[serde(deserialize_with = "null_default")]
    pub uid: String,
    /// `pod_obj.spec.nodeName` — fallback for `node_name` in comments.
    #[serde(deserialize_with = "null_default")]
    pub spec_node_name: String,
    #[serde(deserialize_with = "null_default")]
    pub node_name: String,
    /// Owning workload; names a host-network peer in comments.
    #[serde(deserialize_with = "null_default")]
    pub workload_name: String,
    /// `Some(true)` only when the broker positively knows; `None`/`false` =
    /// an ordinary pod-network pod.
    pub host_network: Option<bool>,
    #[serde(deserialize_with = "null_default")]
    pub is_dead: bool,
    /// `status.startTime`, naive UTC; "" = unknown (excluded by the guard).
    #[serde(deserialize_with = "null_default")]
    pub started_at: String,
    /// When the broker last wrote the record (last seen alive / marked dead).
    #[serde(deserialize_with = "null_default")]
    pub time_stamp: String,
}

impl PodDetail {
    /// Fill `labels`, `uid` and `spec_node_name` from a stored `pod_obj`
    /// manifest. Missing or ill-typed fields leave the current value.
    pub fn apply_pod_obj(&mut self, pod_obj: &Value) {
        if let Some(labels) = pod_obj.pointer("/metadata/labels").and_then(string_map) {
            self.labels = labels;
        }
        if let Some(uid) = pod_obj.pointer("/metadata/uid").and_then(Value::as_str) {
            self.uid = uid.to_string();
        }
        if let Some(node) = pod_obj.pointer("/spec/nodeName").and_then(Value::as_str) {
            self.spec_node_name = node.to_string();
        }
    }
}

/// A Service record — the subset of advisor `api.SvcDetail` the generator
/// reads. `selector` is `service_spec.spec.selector` on the wire; see
/// [`SvcDetail::selector_from_service_spec`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SvcDetail {
    #[serde(deserialize_with = "null_default")]
    pub svc_ip: String,
    #[serde(deserialize_with = "null_default")]
    pub svc_name: String,
    #[serde(deserialize_with = "null_default")]
    pub svc_namespace: String,
    /// Empty = a selector-less Service, which is never used as a peer.
    #[serde(deserialize_with = "null_default")]
    pub selector: BTreeMap<String, String>,
}

impl SvcDetail {
    /// `spec.selector` of a stored `service_spec` (empty when absent).
    pub fn selector_from_service_spec(service_spec: &Value) -> BTreeMap<String, String> {
        service_spec
            .pointer("/spec/selector")
            .and_then(string_map)
            .unwrap_or_default()
    }
}

fn string_map(v: &Value) -> Option<BTreeMap<String, String>> {
    v.as_object().map(|m| {
        m.iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect()
    })
}

/// The broker reads peer attribution needs — advisor `BrokerData` minus the
/// traffic fetch (the caller passes the rows in).
///
/// Infallible on purpose: the reference logs every read error and carries on
/// as if the record did not exist (a failed listing is an empty listing), so an
/// implementation maps its errors to `None` / empty and logs them.
///
/// Only the first three methods are required. The others are narrowed views of
/// [`BrokerData::pods`] that the resolver actually calls; override them with
/// indexed queries (the full listing is large) but keep the documented
/// semantics — the defaults are the reference behaviour.
pub trait BrokerData {
    /// The broker's by-IP pod record (advisor `GetPodSpec` / `GET /pod/ip`):
    /// the current holder of the IP, if any.
    fn pod_by_ip(&self, ip: &str) -> Option<PodDetail>;

    /// The Service whose ClusterIP is `ip` (advisor `GetSvcSpec`).
    fn service_by_ip(&self, ip: &str) -> Option<SvcDetail>;

    /// Every known pod record, dead ones included (advisor `GetPods` /
    /// `GET /pod/info`).
    fn pods(&self) -> Vec<PodDetail>;

    /// Every pod record whose `pod_ip` or `pod_ips` contains `ip`, alive or
    /// dead, in listing order.
    fn pods_holding_ip(&self, ip: &str) -> Vec<PodDetail> {
        self.pods()
            .into_iter()
            .filter(|p| pod_holds_ip(p, ip))
            .collect()
    }

    /// Every pod record named `namespace/name`, alive or dead, in listing
    /// order (the resolver applies the uid check and takes the first match).
    fn pods_named(&self, namespace: &str, name: &str) -> Vec<PodDetail> {
        self.pods()
            .into_iter()
            .filter(|p| p.pod_name == name && p.pod_namespace == namespace)
            .collect()
    }

    /// The host-network pods backing a Service: ALIVE pods in `namespace`
    /// with `host_network == Some(true)` whose labels contain every
    /// `selector` pair. Order does not matter (the resolver sorts by name).
    fn host_network_pods_matching(
        &self,
        namespace: &str,
        selector: &BTreeMap<String, String>,
    ) -> Vec<PodDetail> {
        self.pods()
            .into_iter()
            .filter(|p| {
                !p.is_dead
                    && p.pod_namespace == namespace
                    && is_host_network(p)
                    && labels_contain(&p.labels, selector)
            })
            .collect()
    }
}

/// A generated policy.
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedPolicy {
    /// The policy object (keys sorted, as the advisor's encoding/json emits).
    pub policy: Value,
    /// The YAML document with the comments spliced in exactly like advisor
    /// `MarshalPolicyYAML`: header lines before the document, rule comments
    /// directly above their rule.
    pub yaml: String,
    /// The comment lines in document order, without the leading `# `.
    pub comments: Vec<String>,
    /// The structured comments behind `yaml`, for [`render_yaml`] when the
    /// caller edits `policy` (metadata, kind) before rendering it again.
    pub comment_set: PolicyComments,
}

/// Generate a policy for `target` from its observed `traffic`.
///
/// `pod_name` is used for logging only (like the reference); names and
/// selectors come from `target`. No traffic, or no usable rule, yields the
/// default-deny policy.
pub fn generate(
    kind: PolicyKind,
    pod_name: &str,
    traffic: &[PodTraffic],
    target: &PodDetail,
    data: &dyn BrokerData,
) -> Result<GeneratedPolicy, String> {
    let (policy, comments) = match kind {
        PolicyKind::Standard => standard_policy(pod_name, traffic, target, data),
        PolicyKind::Cilium => cilium_policy(pod_name, traffic, target, data),
    };
    let yaml = render_yaml(&policy, &comments)
        .map_err(|e| format!("{kind:?} policy for pod {pod_name}: {e}"))?;
    let comment_lines = yaml
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix('#'))
        .map(|l| l.strip_prefix(' ').unwrap_or(l).to_string())
        .collect();
    Ok(GeneratedPolicy {
        policy,
        yaml,
        comments: comment_lines,
        comment_set: comments,
    })
}

/// Render a policy as YAML with `comments` spliced in (advisor
/// `MarshalPolicyYAML`). Rule comments are keyed by rule index, so the caller
/// may change anything except the order/number of `spec.ingress` /
/// `spec.egress` rules, and `spec` must stay a top-level key.
pub fn render_yaml(policy: &Value, comments: &PolicyComments) -> Result<String, String> {
    let body = serde_norway::to_string(policy).map_err(|e| format!("marshal policy: {e}"))?;
    Ok(insert_comments(&body, comments))
}

// ---------------------------------------------------------------------------
// Shared helpers (types.go, hostnetwork.go, common.HostCIDR)
// ---------------------------------------------------------------------------

/// Build a JSON object with keys inserted in sorted order, so the output is
/// key-sorted whether or not serde_json's `preserve_order` is enabled.
fn obj<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    let sorted: BTreeMap<&str, Value> = pairs.into_iter().collect();
    Value::Object(
        sorted
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

fn str_map(m: &BTreeMap<String, String>) -> Value {
    Value::Object(
        m.iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect::<Map<_, _>>(),
    )
}

fn standard_labels(pod_name: &str, component: &str) -> Value {
    obj([
        ("app.kubernetes.io/name", Value::from(pod_name)),
        ("app.kubernetes.io/component", Value::from(component)),
        ("app.kubernetes.io/part-of", Value::from("kguardian")),
    ])
}

fn object_meta(target: &PodDetail, suffix: &str) -> Value {
    obj([
        (
            "name",
            Value::from(format!("{}-{}", target.pod_name, suffix)),
        ),
        ("namespace", Value::from(target.pod_namespace.as_str())),
        ("labels", standard_labels(&target.pod_name, suffix)),
    ])
}

/// `common.HostCIDR`: the single-host CIDR of an IP — /32 for IPv4 (including
/// an IPv4-mapped IPv6 address, emitted in dotted form), /128 for IPv6, the
/// address in canonical text. `None` for anything unparseable.
fn host_cidr(ip: &str) -> Option<String> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => Some(format!("{a}/32")),
        IpAddr::V6(a) => Some(match a.to_ipv4_mapped() {
            Some(v4) => format!("{v4}/32"),
            None => format!("{a}/128"),
        }),
    }
}

/// `parsePort` (strconv.Atoi + range check).
fn parse_port(s: &str) -> Option<u16> {
    let n: i64 = s.parse().ok()?;
    if (1..=65535).contains(&n) {
        Some(n as u16)
    } else {
        None
    }
}

/// `protocolPtr`: TCP/UDP/SCTP verbatim, anything else TCP.
fn protocol_of(s: &str) -> &'static str {
    match s {
        "UDP" => "UDP",
        "SCTP" => "SCTP",
        "TCP" => "TCP",
        other => {
            tracing::warn!("Unknown protocol '{other}', defaulting to TCP.");
            "TCP"
        }
    }
}

type Port = (u16, &'static str);

/// `deduplicatePorts`: unique (port, protocol), port ASC then protocol ASC.
fn dedup_ports(ports: &[Port]) -> Vec<Port> {
    let mut out: Vec<Port> = ports.to_vec();
    out.sort();
    out.dedup();
    out
}

fn is_host_network(p: &PodDetail) -> bool {
    p.host_network == Some(true)
}

fn pod_holds_ip(p: &PodDetail, ip: &str) -> bool {
    p.pod_ip == ip || p.pod_ips.iter().any(|o| o == ip)
}

fn labels_contain(labels: &BTreeMap<String, String>, selector: &BTreeMap<String, String>) -> bool {
    selector.iter().all(|(k, v)| labels.get(k) == Some(v))
}

fn host_workload_name(p: &PodDetail) -> &str {
    if p.workload_name.is_empty() {
        &p.pod_name
    } else {
        &p.workload_name
    }
}

fn host_node_name<'a>(p: &'a PodDetail, peer_ip: &'a str) -> &'a str {
    if !p.node_name.is_empty() {
        &p.node_name
    } else if !p.spec_node_name.is_empty() {
        &p.spec_node_name
    } else {
        peer_ip
    }
}

fn host_network_peer_comment(p: &PodDetail, peer_ip: &str, selector: &str) -> String {
    format!(
        "host-network peer {}/{} on node {} — {} cannot match host traffic",
        p.pod_namespace,
        host_workload_name(p),
        host_node_name(p, peer_ip),
        selector
    )
}

fn host_network_target_warning(p: &PodDetail, kind: &str, selector: &str) -> Vec<String> {
    vec![
        format!(
            "WARNING: {}/{} runs with hostNetwork: true. A {} {} cannot select",
            p.pod_namespace,
            host_workload_name(p),
            kind,
            selector
        ),
        "host-network pods; this policy will have no effect. Use a CiliumClusterwideNetworkPolicy"
            .to_string(),
        "with a nodeSelector (host firewall) instead.".to_string(),
    ]
}

fn host_network_service_comment(
    svc: &SvcDetail,
    backends: &[PodDetail],
    peer_ip: &str,
    selector: &str,
) -> String {
    let nodes: Vec<&str> = backends
        .iter()
        .map(|b| host_node_name(b, ""))
        .filter(|n| !n.is_empty())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let node = if nodes.is_empty() {
        peer_ip.to_string()
    } else {
        nodes.join(",")
    };
    format!(
        "host-network peer {}/svc/{} on node {} — {} cannot match host traffic",
        svc.svc_namespace, svc.svc_name, node, selector
    )
}

/// `hostNetworkServiceCIDRs`: one host CIDR per distinct raw backend IP,
/// sorted bytewise on the raw IP; unparseable IPs skipped.
fn host_network_service_cidrs(backends: &[PodDetail]) -> Vec<String> {
    let ips: std::collections::BTreeSet<&str> = backends
        .iter()
        .map(|b| b.pod_ip.as_str())
        .filter(|ip| !ip.is_empty())
        .collect();
    ips.into_iter().filter_map(host_cidr).collect()
}

const HOST_ENTITIES: [&str; 2] = ["host", "remote-node"];

fn unattributed_peer_comment(ip: &str, at: &str) -> String {
    if at.is_empty() {
        format!("unattributed peer {ip}")
    } else {
        format!("unattributed peer {ip} at {at}")
    }
}

// ---------------------------------------------------------------------------
// Time handling (peer.go parseBrokerTime / excludedByGuard / newestTimeStamp)
// ---------------------------------------------------------------------------

/// A broker timestamp: RFC 3339 (with zone), or naive UTC with a `T` or space
/// separator and optional fractional seconds. `None` = unknown.
fn parse_broker_time(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Go's RFC3339 layout needs the literal 'T'; chrono also accepts ' '.
    if s.as_bytes().get(10) == Some(&b'T') {
        if let Ok(t) = DateTime::parse_from_rfc3339(s) {
            return Some(t.with_timezone(&Utc));
        }
    }
    ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"]
        .iter()
        .find_map(|f| NaiveDateTime::parse_from_str(s, f).ok())
        .map(|t| t.and_utc())
}

/// The start-time guard for a by-IP candidate given the row time `at`:
/// excluded when its start is unknown or after the flow, or — for a dead
/// record — when it was last seen before the flow (or never). A row with no
/// parseable time excludes nothing.
fn excluded_by_guard(c: &PodDetail, at: &str) -> bool {
    let Some(flow) = parse_broker_time(at) else {
        return false;
    };
    match parse_broker_time(&c.started_at) {
        Some(start) if start <= flow => {}
        _ => return true,
    }
    if c.is_dead {
        return match parse_broker_time(&c.time_stamp) {
            Some(seen) => seen < flow,
            None => true,
        };
    }
    false
}

/// The newest parseable stamp, verbatim; ties keep the first; "" if none.
fn newest_time_stamp(stamps: &[String]) -> String {
    let mut best: Option<(DateTime<Utc>, &str)> = None;
    for s in stamps {
        if let Some(t) = parse_broker_time(s) {
            if best.is_none_or(|(bt, _)| t > bt) {
                best = Some((t, s));
            }
        }
    }
    best.map(|(_, s)| s.to_string()).unwrap_or_default()
}

/// Newest-first on known times, unknown last.
fn cmp_times_desc(a: &str, b: &str) -> std::cmp::Ordering {
    match (parse_broker_time(a), parse_broker_time(b)) {
        (Some(x), Some(y)) => y.cmp(&x),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

/// `choosePeerCandidate`: guard, then alive first, newest start, newest
/// record, then namespace/name.
fn choose_peer_candidate(candidates: &[PodDetail], at: &str) -> Option<PodDetail> {
    let mut kept: Vec<&PodDetail> = candidates
        .iter()
        .filter(|c| !excluded_by_guard(c, at))
        .collect();
    kept.sort_by(|a, b| {
        a.is_dead
            .cmp(&b.is_dead)
            .then_with(|| cmp_times_desc(&a.started_at, &b.started_at))
            .then_with(|| cmp_times_desc(&a.time_stamp, &b.time_stamp))
            .then_with(|| {
                format!("{}/{}", a.pod_namespace, a.pod_name)
                    .cmp(&format!("{}/{}", b.pod_namespace, b.pod_name))
            })
    });
    kept.first().map(|p| (*p).clone())
}

// ---------------------------------------------------------------------------
// Peer resolution (peer.go)
// ---------------------------------------------------------------------------

/// The attributed identity of one observed peer. At most one of `pod`/`svc`;
/// neither = render the IP as a CIDR (with a comment when `unattributed`).
#[derive(Debug, Clone, Default)]
struct ResolvedPeer {
    ip: String,
    pod: Option<PodDetail>,
    svc: Option<SvcDetail>,
    /// Host-network pods backing `svc` (empty for an ordinary Service).
    backends: Vec<PodDetail>,
    unattributed: bool,
}

fn canonical_labels(labels: &BTreeMap<String, String>) -> String {
    let mut parts: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    parts.sort();
    parts.join(",")
}

impl ResolvedPeer {
    fn cidr(ip: &str) -> Self {
        ResolvedPeer {
            ip: ip.to_string(),
            ..Default::default()
        }
    }

    fn unattributed(ip: &str) -> Self {
        ResolvedPeer {
            ip: ip.to_string(),
            unattributed: true,
            ..Default::default()
        }
    }

    /// `identityKey`: groups rows and orders sibling rules for one IP.
    fn identity_key(&self) -> String {
        if self.unattributed {
            return "unattributed".into();
        }
        if let Some(svc) = &self.svc {
            if !self.backends.is_empty() {
                return format!("host:{}/svc/{}", svc.svc_namespace, svc.svc_name);
            }
            return format!(
                "sel:{}:{}",
                svc.svc_namespace,
                canonical_labels(&svc.selector)
            );
        }
        if let Some(pod) = &self.pod {
            if is_host_network(pod) {
                return format!("host:{}/{}", pod.pod_namespace, host_workload_name(pod));
            }
            if !pod.labels.is_empty() {
                return format!(
                    "sel:{}:{}",
                    pod.pod_namespace,
                    canonical_labels(&pod.labels)
                );
            }
        }
        "cidr".into()
    }
}

/// Resolves rows to identities for one generation, memoising every broker
/// read (N rows to one peer cost one lookup).
struct PeerResolver<'a> {
    data: &'a dyn BrokerData,
    cache: HashMap<(String, String, String), ResolvedPeer>,
    svc_by_ip: HashMap<String, Option<SvcDetail>>,
    pod_by_ip: HashMap<String, Option<PodDetail>>,
    holding_ip: HashMap<String, Vec<PodDetail>>,
    named: HashMap<(String, String), Vec<PodDetail>>,
    backends: HashMap<(String, String), Vec<PodDetail>>,
}

impl<'a> PeerResolver<'a> {
    fn new(data: &'a dyn BrokerData) -> Self {
        PeerResolver {
            data,
            cache: HashMap::new(),
            svc_by_ip: HashMap::new(),
            pod_by_ip: HashMap::new(),
            holding_ip: HashMap::new(),
            named: HashMap::new(),
            backends: HashMap::new(),
        }
    }

    fn service_by_ip(&mut self, ip: &str) -> Option<SvcDetail> {
        let data = self.data;
        self.svc_by_ip
            .entry(ip.to_string())
            .or_insert_with(|| data.service_by_ip(ip))
            .clone()
    }

    /// `hostNetworkServiceBackends`: sorted by pod name.
    fn service_backends(&mut self, svc: &SvcDetail) -> Vec<PodDetail> {
        if svc.selector.is_empty() {
            return Vec::new();
        }
        let data = self.data;
        let key = (svc.svc_namespace.clone(), canonical_labels(&svc.selector));
        self.backends
            .entry(key)
            .or_insert_with(|| {
                let mut out = data.host_network_pods_matching(&svc.svc_namespace, &svc.selector);
                out.sort_by(|a, b| a.pod_name.cmp(&b.pod_name));
                out
            })
            .clone()
    }

    fn svc_peer(&mut self, ip: &str, svc: SvcDetail) -> ResolvedPeer {
        let backends = self.service_backends(&svc);
        ResolvedPeer {
            ip: ip.to_string(),
            svc: Some(svc),
            backends,
            ..Default::default()
        }
    }

    fn resolve_row(&mut self, peer_ip: &str, row: &PodTraffic) -> ResolvedPeer {
        let stored_key = if row.peer_kind.is_empty() {
            String::new()
        } else {
            format!(
                "{}:{}/{}/{}",
                row.peer_kind, row.peer_namespace, row.peer_name, row.peer_uid
            )
        };
        let key = (peer_ip.to_string(), stored_key, row.time_stamp.clone());
        if let Some(p) = self.cache.get(&key) {
            return p.clone();
        }
        let p = if row.peer_kind.is_empty() {
            self.resolve_by_ip(peer_ip, &row.time_stamp)
        } else {
            self.resolve_stored(peer_ip, row)
        };
        self.cache.insert(key, p.clone());
        p
    }

    /// `resolveStored`: an ingest-time identity, used verbatim or pinned.
    fn resolve_stored(&mut self, peer_ip: &str, row: &PodTraffic) -> ResolvedPeer {
        match row.peer_kind.as_str() {
            "pod" | "node" => {
                if row.peer_name.is_empty() {
                    // A bare node IP with no host-network pod: nothing to select.
                    return ResolvedPeer::cidr(peer_ip);
                }
                let data = self.data;
                let named = self
                    .named
                    .entry((row.peer_namespace.clone(), row.peer_name.clone()))
                    .or_insert_with(|| data.pods_named(&row.peer_namespace, &row.peer_name));
                let found = named.iter().find(|p| {
                    p.pod_name == row.peer_name
                        && p.pod_namespace == row.peer_namespace
                        && (p.uid.is_empty() || row.peer_uid.is_empty() || p.uid == row.peer_uid)
                });
                match found {
                    Some(p) => ResolvedPeer {
                        ip: peer_ip.to_string(),
                        pod: Some(p.clone()),
                        ..Default::default()
                    },
                    None => {
                        tracing::warn!(
                            "Stored peer {}/{} ({}) for IP {peer_ip} is no longer known; pinning the IP",
                            row.peer_namespace,
                            row.peer_name,
                            row.peer_kind
                        );
                        ResolvedPeer::unattributed(peer_ip)
                    }
                }
            }
            "service" => match self.service_by_ip(peer_ip) {
                Some(svc)
                    if svc.svc_name == row.peer_name
                        && svc.svc_namespace == row.peer_namespace
                        && !svc.selector.is_empty() =>
                {
                    self.svc_peer(peer_ip, svc)
                }
                _ => {
                    tracing::warn!(
                        "Stored peer service {}/{} for IP {peer_ip} no longer matches; pinning the IP",
                        row.peer_namespace,
                        row.peer_name
                    );
                    ResolvedPeer::unattributed(peer_ip)
                }
            },
            other => {
                // Reference behaviour: an unknown kind resolves by IP WITHOUT
                // the row time (no start-time guard).
                tracing::warn!(
                    "Unknown stored peer kind {other:?} for IP {peer_ip}; resolving by IP"
                );
                self.resolve_by_ip(peer_ip, "")
            }
        }
    }

    /// `resolveByIP`: Service by ClusterIP, then the guarded pod candidates.
    fn resolve_by_ip(&mut self, peer_ip: &str, at: &str) -> ResolvedPeer {
        if let Some(svc) = self.service_by_ip(peer_ip) {
            if !svc.selector.is_empty() {
                return self.svc_peer(peer_ip, svc);
            }
        }
        let candidates = self.candidates_by_ip(peer_ip);
        if candidates.is_empty() {
            return ResolvedPeer::cidr(peer_ip);
        }
        match choose_peer_candidate(&candidates, at) {
            Some(pod) => ResolvedPeer {
                ip: peer_ip.to_string(),
                pod: Some(pod),
                ..Default::default()
            },
            None => {
                tracing::warn!(
                    "No pod that held IP {peer_ip} can have been the peer at {at}; leaving the peer unattributed"
                );
                ResolvedPeer::unattributed(peer_ip)
            }
        }
    }

    /// `candidatesByIP`: listing holders plus the by-IP record, deduplicated
    /// by namespace/name (first wins).
    fn candidates_by_ip(&mut self, peer_ip: &str) -> Vec<PodDetail> {
        let data = self.data;
        let mut all = self
            .holding_ip
            .entry(peer_ip.to_string())
            .or_insert_with(|| data.pods_holding_ip(peer_ip))
            .clone();
        if let Some(p) = self
            .pod_by_ip
            .entry(peer_ip.to_string())
            .or_insert_with(|| data.pod_by_ip(peer_ip))
            .clone()
        {
            all.push(p);
        }
        let mut seen = HashSet::new();
        all.into_iter()
            .filter(|p| seen.insert(format!("{}/{}", p.pod_namespace, p.pod_name)))
            .collect()
    }
}

/// One rule's worth of input: a resolved peer and every port it was seen on.
struct PeerRule {
    peer: ResolvedPeer,
    key: String,
    ports: Vec<Port>,
    stamps: Vec<String>,
}

/// `mergeOrAppendResolvedRule`, keyed on (peer IP, identity).
fn merge_rule(rules: &mut Vec<PeerRule>, peer: ResolvedPeer, port: Port, time_stamp: &str) {
    let key = peer.identity_key();
    if let Some(r) = rules
        .iter_mut()
        .find(|r| r.peer.ip == peer.ip && r.key == key)
    {
        if !time_stamp.is_empty() {
            r.stamps.push(time_stamp.to_string());
        }
        if !r.ports.contains(&port) {
            r.ports.push(port);
        }
        return;
    }
    rules.push(PeerRule {
        peer,
        key,
        ports: vec![port],
        stamps: if time_stamp.is_empty() {
            Vec::new()
        } else {
            vec![time_stamp.to_string()]
        },
    });
}

/// `groupPeerRules`: rules are already unique per (IP, identity); order them
/// by the raw peer IP bytewise, then identity key.
fn sort_rules(rules: &mut [PeerRule]) {
    rules.sort_by(|a, b| {
        format!("{}\x00{}", a.peer.ip, a.key).cmp(&format!("{}\x00{}", b.peer.ip, b.key))
    });
}

/// `processTrafficRules`: split rows into ingress and egress rules.
///
/// INGRESS: peer = `traffic_in_out_ip`, port = the target's `pod_port`.
/// EGRESS: peer = `traffic_in_out_ip`, port = the peer's `traffic_in_out_port`.
/// Rows with no peer, a peer equal to the target's `pod_ip`, or a bad port are
/// skipped.
fn process_traffic(
    traffic: &[PodTraffic],
    target: &PodDetail,
    data: &dyn BrokerData,
) -> (Vec<PeerRule>, Vec<PeerRule>) {
    let mut resolver = PeerResolver::new(data);
    let (mut ingress, mut egress) = (Vec::new(), Vec::new());
    for row in traffic {
        let (rules, port_str) = if row.traffic_type.eq_ignore_ascii_case("INGRESS") {
            (&mut ingress, &row.pod_port)
        } else if row.traffic_type.eq_ignore_ascii_case("EGRESS") {
            (&mut egress, &row.traffic_in_out_port)
        } else {
            tracing::debug!(
                "Skipping traffic record with unknown type: {}",
                row.traffic_type
            );
            continue;
        };
        let peer = row.traffic_in_out_ip.as_str();
        if peer.is_empty() || peer == target.pod_ip {
            continue;
        }
        let Some(port) = parse_port(port_str) else {
            tracing::warn!("Skipping traffic record with invalid port: {port_str}");
            continue;
        };
        let resolved = resolver.resolve_row(peer, row);
        merge_rule(
            rules,
            resolved,
            (port, protocol_of(&row.ip_protocol)),
            &row.time_stamp,
        );
    }
    sort_rules(&mut ingress);
    sort_rules(&mut egress);
    (ingress, egress)
}

// ---------------------------------------------------------------------------
// Comments (hostnetwork.go PolicyComments / insertComments)
// ---------------------------------------------------------------------------

/// The YAML comments a generated policy carries (advisor `PolicyComments`):
/// `header` lines precede the document; `ingress` / `egress` map a rule index
/// (position in `spec.ingress` / `spec.egress`) to the lines rendered directly
/// above that rule. Lines are stored without the leading `# `.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyComments {
    pub header: Vec<String>,
    pub ingress: BTreeMap<usize, Vec<String>>,
    pub egress: BTreeMap<usize, Vec<String>>,
}

impl PolicyComments {
    fn add(section: &mut BTreeMap<usize, Vec<String>>, idx: usize, line: Option<String>) {
        if let Some(line) = line.filter(|l| !l.is_empty()) {
            section.entry(idx).or_default().push(line);
        }
    }

    fn is_empty(&self) -> bool {
        self.header.is_empty() && self.ingress.is_empty() && self.egress.is_empty()
    }
}

/// `insertComments`: header lines before the document; each rule comment
/// directly above its rule under top-level `spec.ingress` / `spec.egress`.
/// Relies on the emitter placing block sequence items at their parent key's
/// column (`  egress:` then `  - `), which serde_norway (libyaml) does, as
/// sigs.k8s.io/yaml does.
fn insert_comments(doc: &str, c: &PolicyComments) -> String {
    if c.is_empty() {
        return doc.to_string();
    }
    let mut out: Vec<String> = c.header.iter().map(|h| format!("# {h}")).collect();
    let (mut top, mut section) = ("", "");
    let mut idx: isize = -1;
    for line in doc.trim_end_matches('\n').split('\n') {
        if !line.is_empty() && !line.starts_with(' ') {
            top = line.strip_suffix(':').unwrap_or(line);
            section = "";
        } else if top == "spec" && (line == "  ingress:" || line == "  egress:") {
            section = line.trim().trim_end_matches(':');
            idx = -1;
        } else if !section.is_empty() {
            if line.starts_with("  - ") {
                idx += 1;
                let map = if section == "ingress" {
                    &c.ingress
                } else {
                    &c.egress
                };
                if let Some(lines) = map.get(&(idx as usize)) {
                    out.extend(lines.iter().map(|cm| format!("  # {cm}")));
                }
            } else if !line.starts_with("    ") {
                section = "";
            }
        }
        out.push(line.to_string());
    }
    out.join("\n") + "\n"
}

// ---------------------------------------------------------------------------
// Standard NetworkPolicy (standard_policy.go)
// ---------------------------------------------------------------------------

fn label_selector(labels: &BTreeMap<String, String>) -> Value {
    if labels.is_empty() {
        Value::Object(Map::new())
    } else {
        obj([("matchLabels", str_map(labels))])
    }
}

fn standard_default_deny(target: &PodDetail) -> Value {
    obj([
        ("apiVersion", Value::from("networking.k8s.io/v1")),
        ("kind", Value::from("NetworkPolicy")),
        ("metadata", object_meta(target, "standard-policy-deny-all")),
        (
            "spec",
            obj([
                ("podSelector", label_selector(&target.labels)),
                ("policyTypes", Value::from(vec!["Ingress", "Egress"])),
            ]),
        ),
    ])
}

fn ip_block(cidr: String) -> Value {
    obj([("ipBlock", obj([("cidr", Value::from(cidr))]))])
}

fn namespaced_peer(labels: &BTreeMap<String, String>, namespace: &str) -> Value {
    let mut ns = BTreeMap::new();
    ns.insert(
        "kubernetes.io/metadata.name".to_string(),
        namespace.to_string(),
    );
    obj([
        ("podSelector", obj([("matchLabels", str_map(labels))])),
        ("namespaceSelector", obj([("matchLabels", str_map(&ns))])),
    ])
}

/// `peersForResolved`: the NetworkPolicyPeer list for one attributed peer and
/// the comment above its rule. Empty = drop the rule.
fn standard_peers(peer: &ResolvedPeer, at: &str) -> (Vec<Value>, Option<String>) {
    let ip = peer.ip.as_str();
    let ip_block_peer = |comment: Option<String>| match host_cidr(ip) {
        Some(cidr) => (vec![ip_block(cidr)], comment),
        None => {
            tracing::warn!("Skipping peer {ip}: cannot express it as a host CIDR");
            (Vec::new(), None)
        }
    };
    if peer.unattributed {
        return ip_block_peer(Some(unattributed_peer_comment(ip, at)));
    }
    if let Some(svc) = &peer.svc {
        if !peer.backends.is_empty() {
            let cidrs = host_network_service_cidrs(&peer.backends);
            if cidrs.is_empty() {
                return (Vec::new(), None);
            }
            return (
                cidrs.into_iter().map(ip_block).collect(),
                Some(host_network_service_comment(
                    svc,
                    &peer.backends,
                    ip,
                    "podSelector",
                )),
            );
        }
        return (
            vec![namespaced_peer(&svc.selector, &svc.svc_namespace)],
            None,
        );
    }
    if let Some(pod) = &peer.pod {
        if is_host_network(pod) {
            return ip_block_peer(Some(host_network_peer_comment(pod, ip, "podSelector")));
        }
        if !pod.labels.is_empty() {
            return (vec![namespaced_peer(&pod.labels, &pod.pod_namespace)], None);
        }
    }
    ip_block_peer(None)
}

fn standard_ports(ports: &[Port]) -> Value {
    Value::Array(
        dedup_ports(ports)
            .into_iter()
            .map(|(p, proto)| obj([("port", Value::from(p)), ("protocol", Value::from(proto))]))
            .collect(),
    )
}

fn standard_rules(
    rules: &[PeerRule],
    peer_field: &str,
    comments: &mut BTreeMap<usize, Vec<String>>,
) -> Vec<Value> {
    let mut out = Vec::new();
    for rule in rules {
        let (peers, comment) = standard_peers(&rule.peer, &newest_time_stamp(&rule.stamps));
        if peers.is_empty() {
            continue;
        }
        PolicyComments::add(comments, out.len(), comment);
        let mut m = Map::new();
        m.insert(peer_field.to_string(), Value::Array(peers));
        m.insert("ports".to_string(), standard_ports(&rule.ports));
        out.push(Value::Object(m));
    }
    out
}

fn standard_policy(
    pod_name: &str,
    traffic: &[PodTraffic],
    target: &PodDetail,
    data: &dyn BrokerData,
) -> (Value, PolicyComments) {
    let mut comments = PolicyComments::default();
    if is_host_network(target) {
        comments.header = host_network_target_warning(target, "NetworkPolicy", "podSelector");
    }
    if traffic.is_empty() {
        tracing::debug!("No traffic for pod {pod_name}; default-deny NetworkPolicy");
        return (standard_default_deny(target), comments);
    }
    let (ingress, egress) = process_traffic(traffic, target, data);

    // policyTypes follows the INTERNAL rule lists (reference behaviour): a
    // direction whose every rule was dropped keeps its policyType with no
    // rules, i.e. denies that direction.
    let mut policy_types = Vec::new();
    let mut spec = Map::new();
    spec.insert("podSelector".into(), label_selector(&target.labels));
    if !ingress.is_empty() {
        policy_types.push("Ingress");
        let rules = standard_rules(&ingress, "from", &mut comments.ingress);
        if !rules.is_empty() {
            spec.insert("ingress".into(), Value::Array(rules));
        }
    }
    if !egress.is_empty() {
        policy_types.push("Egress");
        let rules = standard_rules(&egress, "to", &mut comments.egress);
        if !rules.is_empty() {
            spec.insert("egress".into(), Value::Array(rules));
        }
    }
    if policy_types.is_empty() {
        tracing::debug!("No usable rules for pod {pod_name}; default-deny NetworkPolicy");
        return (standard_default_deny(target), comments);
    }
    spec.insert("policyTypes".into(), Value::from(policy_types));
    let policy = obj([
        ("apiVersion", Value::from("networking.k8s.io/v1")),
        ("kind", Value::from("NetworkPolicy")),
        ("metadata", object_meta(target, "standard-policy")),
        ("spec", sorted(spec)),
    ]);
    (policy, comments)
}

fn sorted(m: Map<String, Value>) -> Value {
    let b: BTreeMap<String, Value> = m.into_iter().collect();
    Value::Object(b.into_iter().collect())
}

// ---------------------------------------------------------------------------
// CiliumNetworkPolicy (cilium_policy.go, cilium_types.go)
// ---------------------------------------------------------------------------

const CILIUM_NAMESPACE_LABEL: &str = "k8s:io.kubernetes.pod.namespace";

/// `newCiliumEndpointSelector`: `k8s:`-prefixed matchLabels, `{}` if none.
fn cilium_selector(labels: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    labels
        .iter()
        .map(|(k, v)| (format!("k8s:{k}"), v.clone()))
        .collect()
}

fn cilium_selector_value(m: &BTreeMap<String, String>) -> Value {
    if m.is_empty() {
        Value::Object(Map::new())
    } else {
        obj([("matchLabels", str_map(m))])
    }
}

/// `createPeerEndpointSelector`: adds the namespace label when the peer is
/// in another namespace than the policy (an endpoint selector without it is
/// scoped to the policy's namespace). An unknown peer namespace is left as is.
fn cilium_peer_selector(
    labels: &BTreeMap<String, String>,
    peer_ns: &str,
    policy_ns: &str,
) -> Value {
    let mut m = cilium_selector(labels);
    if peer_ns.is_empty() {
        tracing::warn!(
            "Peer namespace unknown; endpoint selector is scoped to namespace {policy_ns:?}"
        );
    } else if peer_ns != policy_ns {
        m.insert(CILIUM_NAMESPACE_LABEL.to_string(), peer_ns.to_string());
    }
    cilium_selector_value(&m)
}

enum CiliumPeer {
    Endpoints(Value),
    Entities,
    Cidr(String),
    None,
}

/// `ciliumPeerFor`.
fn cilium_peer(peer: &ResolvedPeer, at: &str, policy_ns: &str) -> (CiliumPeer, Option<String>) {
    let ip = peer.ip.as_str();
    let cidr = |comment: Option<String>| match host_cidr(ip) {
        Some(c) => (CiliumPeer::Cidr(c), comment),
        None => {
            tracing::warn!("Skipping peer {ip}: cannot express it as a host CIDR");
            (CiliumPeer::None, None)
        }
    };
    if peer.unattributed {
        return cidr(Some(unattributed_peer_comment(ip, at)));
    }
    if let Some(svc) = &peer.svc {
        if !peer.backends.is_empty() {
            return (
                CiliumPeer::Entities,
                Some(host_network_service_comment(
                    svc,
                    &peer.backends,
                    ip,
                    "endpointSelector",
                )),
            );
        }
        return (
            CiliumPeer::Endpoints(cilium_peer_selector(
                &svc.selector,
                &svc.svc_namespace,
                policy_ns,
            )),
            None,
        );
    }
    if let Some(pod) = &peer.pod {
        if is_host_network(pod) {
            return (
                CiliumPeer::Entities,
                Some(host_network_peer_comment(pod, ip, "endpointSelector")),
            );
        }
        if !pod.labels.is_empty() {
            return (
                CiliumPeer::Endpoints(cilium_peer_selector(
                    &pod.labels,
                    &pod.pod_namespace,
                    policy_ns,
                )),
                None,
            );
        }
    }
    cidr(None)
}

fn cilium_to_ports(ports: &[Port]) -> (Value, String) {
    let deduped = dedup_ports(ports);
    let key = deduped
        .iter()
        .map(|(p, proto)| format!("{p}/{proto}"))
        .collect::<Vec<_>>()
        .join(",");
    let v = Value::Array(
        deduped
            .into_iter()
            .map(|(p, proto)| {
                obj([(
                    "ports",
                    Value::Array(vec![obj([
                        ("port", Value::from(p.to_string())),
                        ("protocol", Value::from(proto)),
                    ])]),
                )])
            })
            .collect(),
    );
    (v, key)
}

/// `transformToCilium{Ingress,Egress}Rules`. Host-network peers collapse into
/// one entities rule per distinct port list, positioned where the first such
/// peer fell; later peers only add their comment line.
fn cilium_rules(
    rules: &[PeerRule],
    ingress: bool,
    policy_ns: &str,
    comments: &mut BTreeMap<usize, Vec<String>>,
) -> Vec<Value> {
    let (endpoints_f, cidr_f, entities_f) = if ingress {
        ("fromEndpoints", "fromCIDR", "fromEntities")
    } else {
        ("toEndpoints", "toCIDR", "toEntities")
    };
    let mut out: Vec<Value> = Vec::new();
    let mut entity_rule_by_ports: HashMap<String, usize> = HashMap::new();
    for rule in rules {
        let (peer, comment) = cilium_peer(&rule.peer, &newest_time_stamp(&rule.stamps), policy_ns);
        let (to_ports, ports_key) = cilium_to_ports(&rule.ports);
        let mut m = Map::new();
        match peer {
            CiliumPeer::None => continue,
            CiliumPeer::Endpoints(sel) => {
                m.insert(endpoints_f.into(), Value::Array(vec![sel]));
            }
            CiliumPeer::Cidr(c) => {
                m.insert(cidr_f.into(), Value::Array(vec![Value::from(c)]));
            }
            CiliumPeer::Entities => {
                if let Some(&idx) = entity_rule_by_ports.get(&ports_key) {
                    PolicyComments::add(comments, idx, comment);
                    continue;
                }
                entity_rule_by_ports.insert(ports_key, out.len());
                m.insert(entities_f.into(), Value::from(HOST_ENTITIES.to_vec()));
            }
        }
        if to_ports.as_array().is_some_and(|a| !a.is_empty()) {
            m.insert("toPorts".into(), to_ports);
        }
        PolicyComments::add(comments, out.len(), comment);
        out.push(sorted(m));
    }
    out
}

fn cilium_default_deny(target: &PodDetail) -> Value {
    obj([
        ("apiVersion", Value::from("cilium.io/v2")),
        ("kind", Value::from("CiliumNetworkPolicy")),
        ("metadata", object_meta(target, "cilium-policy-deny-all")),
        (
            "spec",
            obj([
                (
                    "endpointSelector",
                    cilium_selector_value(&cilium_selector(&target.labels)),
                ),
                (
                    "description",
                    Value::from(format!(
                        "Default-deny Cilium network policy for pod {}",
                        target.pod_name
                    )),
                ),
                (
                    "enableDefaultDeny",
                    obj([
                        ("ingress", Value::Bool(true)),
                        ("egress", Value::Bool(true)),
                    ]),
                ),
            ]),
        ),
        ("status", Value::Object(Map::new())),
    ])
}

fn cilium_policy(
    pod_name: &str,
    traffic: &[PodTraffic],
    target: &PodDetail,
    data: &dyn BrokerData,
) -> (Value, PolicyComments) {
    let mut comments = PolicyComments::default();
    if is_host_network(target) {
        comments.header =
            host_network_target_warning(target, "CiliumNetworkPolicy", "endpointSelector");
    }
    if traffic.is_empty() {
        tracing::debug!("No traffic for pod {pod_name}; default-deny CiliumNetworkPolicy");
        return (cilium_default_deny(target), comments);
    }
    let (ingress, egress) = process_traffic(traffic, target, data);
    let ns = target.pod_namespace.as_str();
    let ingress_rules = cilium_rules(&ingress, true, ns, &mut comments.ingress);
    let egress_rules = cilium_rules(&egress, false, ns, &mut comments.egress);
    // Unlike the standard generator, Cilium falls back on the EMITTED rules.
    if ingress_rules.is_empty() && egress_rules.is_empty() {
        tracing::debug!("No usable rules for pod {pod_name}; default-deny CiliumNetworkPolicy");
        return (cilium_default_deny(target), comments);
    }
    let mut spec = Map::new();
    spec.insert(
        "endpointSelector".into(),
        cilium_selector_value(&cilium_selector(&target.labels)),
    );
    spec.insert(
        "description".into(),
        Value::from(format!(
            "Cilium network policy for pod {} generated by kguardian",
            target.pod_name
        )),
    );
    if !ingress_rules.is_empty() {
        spec.insert("ingress".into(), Value::Array(ingress_rules));
    }
    if !egress_rules.is_empty() {
        spec.insert("egress".into(), Value::Array(egress_rules));
    }
    let policy = obj([
        ("apiVersion", Value::from("cilium.io/v2")),
        ("kind", Value::from("CiliumNetworkPolicy")),
        ("metadata", object_meta(target, "cilium-policy")),
        ("spec", sorted(spec)),
        ("status", Value::Object(Map::new())),
    ]);
    (policy, comments)
}
