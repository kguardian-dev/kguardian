//! Parity with the advisor reference (every scenario of
//! advisor/pkg/network/fixture_golden_test.go, compared against the shared
//! goldens as parsed YAML + ordered `#` lines) and direct semantic checks of
//! the Kubernetes / Cilium meaning of the output.

use super::*;
use std::collections::HashMap;
use std::path::PathBuf;

// ---- stub broker (advisor brokerdata_test.go stubBrokerData) ---------------

#[derive(Default, Clone)]
struct Stub {
    /// PodByIP, keyed by IP.
    pods: HashMap<String, PodDetail>,
    /// ServiceByIP, keyed by IP.
    svcs: HashMap<String, SvcDetail>,
    /// The /pod/info listing.
    all_pods: Vec<PodDetail>,
}

impl BrokerData for Stub {
    fn pod_by_ip(&self, ip: &str) -> Option<PodDetail> {
        self.pods.get(ip).cloned()
    }
    fn service_by_ip(&self, ip: &str) -> Option<SvcDetail> {
        self.svcs.get(ip).cloned()
    }
    fn pods(&self) -> Vec<PodDetail> {
        self.all_pods.clone()
    }
}

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// fixturePodDetail
fn pod(name: &str, ns: &str, ip: &str, l: &[(&str, &str)]) -> PodDetail {
    PodDetail {
        pod_name: name.into(),
        pod_namespace: ns.into(),
        pod_ip: ip.into(),
        labels: labels(l),
        ..Default::default()
    }
}

/// hostFixturePodDetail
fn host_pod(
    name: &str,
    ns: &str,
    ip: &str,
    l: &[(&str, &str)],
    node: &str,
    workload: &str,
    host_network: bool,
) -> PodDetail {
    PodDetail {
        node_name: node.into(),
        workload_name: workload.into(),
        host_network: Some(host_network),
        ..pod(name, ns, ip, l)
    }
}

/// v4FixturePod
#[allow(clippy::too_many_arguments)]
fn v4_pod(
    name: &str,
    ns: &str,
    ip: &str,
    l: &[(&str, &str)],
    node: &str,
    workload: &str,
    started_at: &str,
    dead: bool,
) -> PodDetail {
    PodDetail {
        node_name: node.into(),
        workload_name: workload.into(),
        started_at: started_at.into(),
        is_dead: dead,
        ..pod(name, ns, ip, l)
    }
}

fn svc(name: &str, ns: &str, ip: &str, selector: &[(&str, &str)]) -> SvcDetail {
    SvcDetail {
        svc_ip: ip.into(),
        svc_name: name.into(),
        svc_namespace: ns.into(),
        selector: labels(selector),
    }
}

fn ingress(src: &str, pod_port: &str, peer: &str) -> PodTraffic {
    PodTraffic {
        traffic_type: "INGRESS".into(),
        pod_ip: src.into(),
        pod_port: pod_port.into(),
        traffic_in_out_ip: peer.into(),
        ip_protocol: "TCP".into(),
        ..Default::default()
    }
}

fn egress(src: &str, peer: &str, peer_port: &str) -> PodTraffic {
    PodTraffic {
        traffic_type: "EGRESS".into(),
        pod_ip: src.into(),
        traffic_in_out_ip: peer.into(),
        traffic_in_out_port: peer_port.into(),
        ip_protocol: "TCP".into(),
        ..Default::default()
    }
}

fn at(mut t: PodTraffic, ts: &str) -> PodTraffic {
    t.time_stamp = ts.into();
    t
}

fn with_peer_port(mut t: PodTraffic, port: &str) -> PodTraffic {
    t.traffic_in_out_port = port.into();
    t
}

fn stored(mut t: PodTraffic, kind: &str, ns: &str, name: &str, uid: &str) -> PodTraffic {
    t.peer_kind = kind.into();
    t.peer_namespace = ns.into();
    t.peer_name = name.into();
    t.peer_uid = uid.into();
    t
}

// ---- scenarios (one per fixture_golden_test.go input) ----------------------

struct Scenario {
    stub: Stub,
    target: PodDetail,
    traffic: Vec<PodTraffic>,
}

fn with_traffic() -> Scenario {
    Scenario {
        stub: Stub::default(),
        target: pod("web", "prod", "10.0.0.1", &[("app", "web")]),
        traffic: vec![
            ingress("10.0.0.1", "8080", "10.0.0.7"),
            egress("10.0.0.1", "10.96.0.10", "5432"),
        ],
    }
}

fn default_deny() -> Scenario {
    Scenario {
        stub: Stub::default(),
        target: pod("idle", "prod", "10.0.0.2", &[("app", "idle")]),
        traffic: vec![],
    }
}

fn endpoint_resolved() -> Scenario {
    let mut stub = Stub::default();
    stub.svcs.insert(
        "10.96.0.10".into(),
        svc("db", "prod", "10.96.0.10", &[("app", "db")]),
    );
    // brokerdata_test.go podDetail(): namespace "prod".
    stub.pods.insert(
        "10.0.0.7".into(),
        pod("frontend-1", "prod", "10.0.0.7", &[("app", "frontend")]),
    );
    Scenario {
        stub,
        target: pod("web", "prod", "10.0.0.1", &[("app", "web")]),
        traffic: vec![
            egress("10.0.0.1", "10.96.0.10", "5432"),
            ingress("10.0.0.1", "8080", "10.0.0.7"),
        ],
    }
}

fn dual_stack() -> Scenario {
    Scenario {
        stub: Stub::default(),
        target: pod("web6", "prod", "fd00::1", &[("app", "web")]),
        traffic: vec![
            ingress("fd00::1", "8080", "fd00::7"),
            egress("fd00::1", "fd00:96::a", "5432"),
            egress("fd00::1", "10.96.0.10", "5432"),
        ],
    }
}

fn hostnetwork_egress() -> Scenario {
    let mut stub = Stub::default();
    stub.pods.insert(
        "192.168.50.101".into(),
        host_pod(
            "node-exporter-abc12",
            "monitoring",
            "192.168.50.101",
            &[("app", "node-exporter")],
            "worker-1",
            "node-exporter",
            true,
        ),
    );
    stub.pods.insert(
        "192.168.50.102".into(),
        host_pod(
            "node-exporter-def34",
            "monitoring",
            "192.168.50.102",
            &[("app", "node-exporter")],
            "worker-2",
            "node-exporter",
            true,
        ),
    );
    Scenario {
        stub,
        target: host_pod(
            "prometheus",
            "monitoring",
            "10.0.0.5",
            &[("app", "prometheus")],
            "worker-3",
            "prometheus",
            false,
        ),
        traffic: vec![
            egress("10.0.0.5", "192.168.50.101", "9100"),
            egress("10.0.0.5", "192.168.50.102", "9100"),
            egress("10.0.0.5", "10.96.0.10", "5432"),
        ],
    }
}

fn hostnetwork_ingress() -> Scenario {
    let mut stub = Stub::default();
    stub.pods.insert(
        "192.168.50.101".into(),
        host_pod(
            "ingress-nginx-controller-abc12",
            "ingress-nginx",
            "192.168.50.101",
            &[("app.kubernetes.io/name", "ingress-nginx")],
            "worker-1",
            "ingress-nginx-controller",
            true,
        ),
    );
    stub.pods.insert(
        "10.0.0.7".into(),
        host_pod(
            "frontend-1",
            "prod",
            "10.0.0.7",
            &[("app", "frontend")],
            "worker-2",
            "frontend",
            false,
        ),
    );
    Scenario {
        stub,
        target: host_pod(
            "web",
            "prod",
            "10.0.0.1",
            &[("app", "web")],
            "worker-3",
            "web",
            false,
        ),
        traffic: vec![
            ingress("10.0.0.1", "8080", "192.168.50.101"),
            ingress("10.0.0.1", "8080", "10.0.0.7"),
        ],
    }
}

fn hostnetwork_target() -> Scenario {
    let mut stub = Stub::default();
    stub.pods.insert(
        "10.0.0.5".into(),
        host_pod(
            "prometheus",
            "monitoring",
            "10.0.0.5",
            &[("app", "prometheus")],
            "worker-3",
            "prometheus",
            false,
        ),
    );
    Scenario {
        stub,
        target: host_pod(
            "node-exporter-abc12",
            "monitoring",
            "192.168.50.101",
            &[("app", "node-exporter")],
            "worker-1",
            "node-exporter",
            true,
        ),
        traffic: vec![ingress("192.168.50.101", "9100", "10.0.0.5")],
    }
}

fn hostnetwork_service() -> Scenario {
    let mut stub = Stub::default();
    stub.svcs.insert(
        "10.96.0.20".into(),
        svc(
            "node-exporter",
            "monitoring",
            "10.96.0.20",
            &[("app", "node-exporter")],
        ),
    );
    stub.svcs.insert(
        "10.96.0.10".into(),
        svc("db", "prod", "10.96.0.10", &[("app", "db")]),
    );
    stub.all_pods = vec![
        host_pod(
            "node-exporter-def34",
            "monitoring",
            "192.168.50.102",
            &[("app", "node-exporter")],
            "worker-2",
            "node-exporter",
            true,
        ),
        host_pod(
            "node-exporter-abc12",
            "monitoring",
            "192.168.50.101",
            &[("app", "node-exporter")],
            "worker-1",
            "node-exporter",
            true,
        ),
        host_pod(
            "db-0",
            "prod",
            "10.0.0.9",
            &[("app", "db")],
            "worker-3",
            "db",
            false,
        ),
    ];
    Scenario {
        stub,
        target: host_pod(
            "prometheus",
            "monitoring",
            "10.0.0.5",
            &[("app", "prometheus")],
            "worker-3",
            "prometheus",
            false,
        ),
        traffic: vec![
            egress("10.0.0.5", "10.96.0.20", "9100"),
            egress("10.0.0.5", "10.96.0.10", "5432"),
        ],
    }
}

fn cross_namespace() -> Scenario {
    let mut stub = Stub::default();
    stub.pods.insert(
        "10.0.0.30".into(),
        pod("sonarr-0", "downloads", "10.0.0.30", &[("app", "sonarr")]),
    );
    stub.pods.insert(
        "10.0.0.40".into(),
        pod(
            "maintainerr-0",
            "media",
            "10.0.0.40",
            &[("app", "maintainerr")],
        ),
    );
    stub.svcs.insert(
        "10.96.0.50".into(),
        svc(
            "prometheus",
            "monitoring",
            "10.96.0.50",
            &[("app", "prometheus")],
        ),
    );
    Scenario {
        stub,
        target: pod("web", "prod", "10.0.0.1", &[("app", "web")]),
        traffic: vec![
            egress("10.0.0.1", "10.0.0.30", "8989"),
            egress("10.0.0.1", "10.96.0.50", "9090"),
            ingress("10.0.0.1", "8080", "10.0.0.40"),
        ],
    }
}

fn stale_ip_peer() -> Scenario {
    let stub = Stub {
        all_pods: vec![
            v4_pod(
                "autobrr-7d9c4b8f6-q2x9k",
                "home-system",
                "10.244.12.199",
                &[("app", "autobrr")],
                "worker-2",
                "autobrr",
                "2026-08-04T09:12:41",
                false,
            ),
            v4_pod(
                "cmangos-web-0",
                "game-servers",
                "10.244.5.8",
                &[("app", "cmangos-web")],
                "worker-1",
                "cmangos-web",
                "2026-07-01T00:00:00",
                false,
            ),
        ],
        ..Default::default()
    };
    Scenario {
        stub,
        target: pod(
            "cmangos-database",
            "game-servers",
            "10.244.3.17",
            &[("app", "cmangos-database")],
        ),
        traffic: vec![
            at(
                with_peer_port(ingress("10.244.3.17", "3306", "10.244.12.199"), "51234"),
                "2026-05-21T08:30:00",
            ),
            at(
                with_peer_port(ingress("10.244.3.17", "3306", "10.244.12.199"), "51235"),
                "2026-07-23T10:00:00",
            ),
            at(
                egress("10.244.3.17", "10.244.5.8", "8080"),
                "2026-07-23T10:00:05",
            ),
        ],
    }
}

fn stored_peer_identity() -> Scenario {
    let mut backup = v4_pod(
        "cmangos-backup-29271840-x7k2p",
        "game-servers",
        "10.244.12.199",
        &[("app", "cmangos-backup")],
        "worker-1",
        "cmangos-backup",
        "2026-09-03T04:59:30",
        true,
    );
    backup.uid = "0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6".into();
    let mut node_exporter = v4_pod(
        "node-exporter-abc12",
        "monitoring",
        "192.168.50.101",
        &[("app", "node-exporter")],
        "worker-1",
        "node-exporter",
        "2026-08-01T00:00:00",
        false,
    );
    node_exporter.host_network = Some(true);
    node_exporter.uid = "9c8b7a6f-5e4d-3c2b-1a09-f8e7d6c5b4a3".into();
    let mut stub = Stub::default();
    stub.svcs.insert(
        "10.96.0.10".into(),
        svc("db", "game-servers", "10.96.0.10", &[("app", "db")]),
    );
    stub.all_pods = vec![
        v4_pod(
            "autobrr-7d9c4b8f6-q2x9k",
            "home-system",
            "10.244.12.199",
            &[("app", "autobrr")],
            "worker-2",
            "autobrr",
            "",
            false,
        ),
        backup,
        node_exporter,
    ];
    Scenario {
        stub,
        target: pod(
            "cmangos-database",
            "game-servers",
            "10.244.3.17",
            &[("app", "cmangos-database")],
        ),
        traffic: vec![
            stored(
                at(
                    with_peer_port(ingress("10.244.3.17", "3306", "10.244.12.199"), "51234"),
                    "2026-09-03T05:00:00",
                ),
                "pod",
                "game-servers",
                "cmangos-backup-29271840-x7k2p",
                "0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6",
            ),
            stored(
                at(
                    egress("10.244.3.17", "10.96.0.10", "5432"),
                    "2026-09-03T05:00:01",
                ),
                "service",
                "game-servers",
                "db",
                "",
            ),
            stored(
                at(
                    egress("10.244.3.17", "192.168.50.101", "9100"),
                    "2026-09-03T05:00:02",
                ),
                "node",
                "monitoring",
                "node-exporter-abc12",
                "9c8b7a6f-5e4d-3c2b-1a09-f8e7d6c5b4a3",
            ),
        ],
    }
}

fn run(kind: PolicyKind, s: &Scenario) -> GeneratedPolicy {
    generate(kind, &s.target.pod_name, &s.traffic, &s.target, &s.stub).expect("generate")
}

// ---- parity -----------------------------------------------------------------

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test/fixtures/generators/networkpolicy")
}

fn comment_lines(yaml: &str) -> Vec<String> {
    yaml.lines()
        .map(str::trim)
        .filter(|l| l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

fn parse_yaml(y: &str) -> Value {
    serde_norway::from_str(y).expect("parse yaml")
}

type Golden = (&'static str, PolicyKind, fn() -> Scenario);

const GOLDENS: &[Golden] = &[
    ("standard_with_traffic", PolicyKind::Standard, with_traffic),
    ("cilium_with_traffic", PolicyKind::Cilium, with_traffic),
    ("standard_default_deny", PolicyKind::Standard, default_deny),
    ("cilium_default_deny", PolicyKind::Cilium, default_deny),
    (
        "cilium_endpoint_resolved",
        PolicyKind::Cilium,
        endpoint_resolved,
    ),
    ("standard_dualstack", PolicyKind::Standard, dual_stack),
    ("cilium_dualstack", PolicyKind::Cilium, dual_stack),
    (
        "standard_hostnetwork_egress_peer",
        PolicyKind::Standard,
        hostnetwork_egress,
    ),
    (
        "cilium_hostnetwork_egress_peer",
        PolicyKind::Cilium,
        hostnetwork_egress,
    ),
    (
        "standard_hostnetwork_ingress_peer",
        PolicyKind::Standard,
        hostnetwork_ingress,
    ),
    (
        "cilium_hostnetwork_ingress_peer",
        PolicyKind::Cilium,
        hostnetwork_ingress,
    ),
    (
        "standard_hostnetwork_target",
        PolicyKind::Standard,
        hostnetwork_target,
    ),
    (
        "cilium_hostnetwork_target",
        PolicyKind::Cilium,
        hostnetwork_target,
    ),
    (
        "standard_hostnetwork_service_peer",
        PolicyKind::Standard,
        hostnetwork_service,
    ),
    (
        "cilium_hostnetwork_service_peer",
        PolicyKind::Cilium,
        hostnetwork_service,
    ),
    (
        "standard_cross_namespace_peer",
        PolicyKind::Standard,
        cross_namespace,
    ),
    (
        "cilium_cross_namespace_peer",
        PolicyKind::Cilium,
        cross_namespace,
    ),
    (
        "standard_stale_ip_peer",
        PolicyKind::Standard,
        stale_ip_peer,
    ),
    ("cilium_stale_ip_peer", PolicyKind::Cilium, stale_ip_peer),
    (
        "standard_stored_peer_identity",
        PolicyKind::Standard,
        stored_peer_identity,
    ),
    (
        "cilium_stored_peer_identity",
        PolicyKind::Cilium,
        stored_peer_identity,
    ),
];

#[test]
fn every_golden_file_has_a_scenario() {
    let mut on_disk: Vec<String> = std::fs::read_dir(golden_dir())
        .expect("golden dir")
        .filter_map(|e| {
            let name = e.ok()?.file_name().into_string().ok()?;
            name.strip_suffix(".golden.yaml").map(str::to_string)
        })
        .collect();
    on_disk.sort();
    let mut covered: Vec<String> = GOLDENS.iter().map(|(n, _, _)| n.to_string()).collect();
    covered.sort();
    assert_eq!(on_disk, covered);
}

#[test]
fn parity_with_advisor_goldens() {
    let mut failures = Vec::new();
    for (name, kind, scenario) in GOLDENS {
        let path = golden_dir().join(format!("{name}.golden.yaml"));
        let want = std::fs::read_to_string(&path).expect("read golden");
        let got = run(*kind, &scenario());

        let (want_v, got_v) = (parse_yaml(&want), parse_yaml(&got.yaml));
        if want_v != got_v {
            failures.push(format!(
                "{name}: parsed policy differs\n--- want ---\n{want}\n--- got ---\n{}",
                got.yaml
            ));
        }
        if got_v != got.policy {
            failures.push(format!("{name}: GeneratedPolicy.policy != its own YAML"));
        }
        let (want_c, got_c) = (comment_lines(&want), comment_lines(&got.yaml));
        if want_c != got_c {
            failures.push(format!(
                "{name}: comment lines differ\nwant {want_c:#?}\ngot  {got_c:#?}"
            ));
        }
        let listed: Vec<String> = got.comments.iter().map(|c| format!("# {c}")).collect();
        if render_yaml(&got.policy, &got.comment_set).as_deref() != Ok(got.yaml.as_str()) {
            failures.push(format!("{name}: render_yaml(policy, comment_set) != yaml"));
        }
        if listed != got_c {
            failures.push(format!("{name}: GeneratedPolicy.comments != YAML comments"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

// ---- semantics ----------------------------------------------------------------

fn spec(p: &GeneratedPolicy) -> &Value {
    &p.policy["spec"]
}

fn rules<'a>(p: &'a GeneratedPolicy, dir: &str) -> &'a Vec<Value> {
    spec(p)[dir].as_array().expect("rules")
}

#[test]
fn cilium_cross_namespace_peer_carries_namespace_label() {
    let p = run(PolicyKind::Cilium, &cross_namespace());
    let eg = rules(&p, "egress");
    let ing = rules(&p, "ingress");
    let ns_of = |r: &Value, f: &str| {
        r[f][0]["matchLabels"][CILIUM_NAMESPACE_LABEL]
            .as_str()
            .map(str::to_string)
    };
    assert_eq!(ns_of(&eg[0], "toEndpoints").as_deref(), Some("downloads")); // pod peer
    assert_eq!(ns_of(&eg[1], "toEndpoints").as_deref(), Some("monitoring")); // service peer
    assert_eq!(ns_of(&ing[0], "fromEndpoints").as_deref(), Some("media"));
    // The policy's own selector never names a namespace (the policy's
    // metadata.namespace scopes it).
    let own = spec(&p)["endpointSelector"]["matchLabels"]
        .as_object()
        .unwrap();
    assert!(own.keys().all(|k| !k.contains("namespace")));
    assert_eq!(p.policy["metadata"]["namespace"], "prod");
}

#[test]
fn cilium_same_namespace_peer_has_no_namespace_label() {
    let p = run(PolicyKind::Cilium, &endpoint_resolved());
    for (dir, f) in [("egress", "toEndpoints"), ("ingress", "fromEndpoints")] {
        let m = rules(&p, dir)[0][f][0]["matchLabels"].as_object().unwrap();
        assert!(!m.contains_key(CILIUM_NAMESPACE_LABEL), "{dir}: {m:?}");
        assert!(m.keys().all(|k| k.starts_with("k8s:")));
    }
}

#[test]
fn networkpolicy_cross_namespace_peer_is_one_and_entry() {
    let p = run(PolicyKind::Standard, &cross_namespace());
    for (dir, field, ns, app) in [
        ("egress", "to", "downloads", "sonarr"),
        ("egress", "to", "monitoring", "prometheus"),
        ("ingress", "from", "media", "maintainerr"),
    ] {
        let rule = rules(&p, dir)
            .iter()
            .find(|r| r[field][0]["podSelector"]["matchLabels"]["app"] == app)
            .unwrap_or_else(|| panic!("{dir} rule for {app}"));
        let peers = rule[field].as_array().unwrap();
        // Exactly ONE peer entry holding both selectors = AND. Two entries
        // (one podSelector, one namespaceSelector) would be OR and admit the
        // whole namespace / same-labelled pods in the policy namespace.
        assert_eq!(peers.len(), 1, "{app}: {peers:?}");
        assert_eq!(
            peers[0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
            ns
        );
        assert!(peers[0].get("ipBlock").is_none());
    }
}

#[test]
fn ip_blocks_are_single_host_per_family() {
    let s = dual_stack();
    let std = run(PolicyKind::Standard, &s);
    let cidrs: Vec<&str> = ["ingress", "egress"]
        .iter()
        .flat_map(|d| rules(&std, d))
        .flat_map(|r| {
            r.get("from")
                .or(r.get("to"))
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
        })
        .filter_map(|p| p["ipBlock"]["cidr"].as_str())
        .collect();
    assert!(cidrs.contains(&"fd00::7/128"));
    assert!(cidrs.contains(&"fd00:96::a/128"));
    assert!(cidrs.contains(&"10.96.0.10/32"));

    let cil = run(PolicyKind::Cilium, &s);
    assert_eq!(rules(&cil, "ingress")[0]["fromCIDR"][0], "fd00::7/128");

    assert_eq!(host_cidr("::ffff:10.0.0.1").as_deref(), Some("10.0.0.1/32"));
    assert_eq!(host_cidr("FD00::0:1").as_deref(), Some("fd00::1/128"));
    assert_eq!(host_cidr("fe80::1%eth0"), None);
    assert_eq!(host_cidr("not-an-ip"), None);
}

#[test]
fn ingress_uses_own_port_egress_uses_peer_port() {
    let s = Scenario {
        stub: Stub::default(),
        target: pod("web", "prod", "10.0.0.1", &[("app", "web")]),
        traffic: vec![
            // Peer's ephemeral source port 51000 must NOT appear on ingress.
            with_peer_port(ingress("10.0.0.1", "8080", "10.0.0.7"), "51000"),
            // Our pod_port on an egress row must NOT appear on egress.
            PodTraffic {
                pod_port: "40000".into(),
                ..egress("10.0.0.1", "10.0.0.8", "5432")
            },
        ],
    };
    let std = run(PolicyKind::Standard, &s);
    assert_eq!(rules(&std, "ingress")[0]["ports"][0]["port"], 8080);
    assert_eq!(rules(&std, "egress")[0]["ports"][0]["port"], 5432);
    let cil = run(PolicyKind::Cilium, &s);
    assert_eq!(
        rules(&cil, "ingress")[0]["toPorts"][0]["ports"][0]["port"],
        "8080"
    );
    assert_eq!(
        rules(&cil, "egress")[0]["toPorts"][0]["ports"][0]["port"],
        "5432"
    );
}

#[test]
fn default_deny_without_traffic() {
    let std = run(PolicyKind::Standard, &default_deny());
    assert_eq!(
        spec(&std)["policyTypes"],
        serde_json::json!(["Ingress", "Egress"])
    );
    // Absent rule lists with both policyTypes = deny all both ways.
    assert!(spec(&std).get("ingress").is_none() && spec(&std).get("egress").is_none());
    assert_eq!(spec(&std)["podSelector"]["matchLabels"]["app"], "idle");

    let cil = run(PolicyKind::Cilium, &default_deny());
    assert_eq!(spec(&cil)["enableDefaultDeny"]["ingress"], true);
    assert_eq!(spec(&cil)["enableDefaultDeny"]["egress"], true);
    assert!(spec(&cil).get("ingress").is_none() && spec(&cil).get("egress").is_none());

    // Traffic that yields no usable rule at all also falls back to deny-all.
    let s = Scenario {
        traffic: vec![egress("10.0.0.2", "10.0.0.2", "80")], // self-traffic only
        ..default_deny()
    };
    assert_eq!(
        run(PolicyKind::Standard, &s).policy["metadata"]["name"],
        "idle-standard-policy-deny-all"
    );
    assert_eq!(
        run(PolicyKind::Cilium, &s).policy["metadata"]["name"],
        "idle-cilium-policy-deny-all"
    );
}

fn has_pod_selector(v: &Value) -> bool {
    match v {
        Value::Object(m) => {
            m.contains_key("podSelector") && m.contains_key("namespaceSelector")
                || m.values().any(has_pod_selector)
        }
        Value::Array(a) => a.iter().any(has_pod_selector),
        _ => false,
    }
}

#[test]
fn host_network_peers_never_become_selectors() {
    for s in [
        hostnetwork_egress(),
        hostnetwork_ingress(),
        hostnetwork_service(),
    ] {
        let std = run(PolicyKind::Standard, &s);
        let cil = run(PolicyKind::Cilium, &s);
        for dir in ["ingress", "egress"] {
            let Some(rs) = spec(&std)[dir].as_array() else {
                continue;
            };
            for r in rs {
                let peers = r.get("from").or(r.get("to")).unwrap();
                let text = peers.to_string();
                if text.contains("node-exporter") || text.contains("ingress-nginx") {
                    panic!("host-network peer rendered as a selector: {text}");
                }
            }
        }
        // Every host-network peer's labels are absent from the Cilium output;
        // those peers are entities rules instead.
        let text = cil.policy.to_string();
        assert!(!text.contains("k8s:app\":\"node-exporter"), "{text}");
        assert!(!text.contains("ingress-nginx\""), "{text}");
        assert!(text.contains("remote-node"));
    }
    // The ordinary peer in the same scenario still gets its selector.
    let std = run(PolicyKind::Standard, &hostnetwork_ingress());
    assert!(has_pod_selector(&std.policy["spec"]["ingress"][0]));
    // The Service backed by host-network pods pins the backend node IPs,
    // never its ClusterIP.
    let svc = run(PolicyKind::Standard, &hostnetwork_service());
    assert!(!svc.yaml.contains("10.96.0.20"));
}

#[test]
fn stale_ip_is_never_attributed_to_the_current_holder() {
    for kind in [PolicyKind::Standard, PolicyKind::Cilium] {
        let p = run(kind, &stale_ip_peer());
        assert!(!p.policy.to_string().contains("autobrr"));
        assert_eq!(
            p.comments,
            vec!["unattributed peer 10.244.12.199 at 2026-07-23T10:00:00".to_string()]
        );
    }
}

#[test]
fn output_is_independent_of_row_order() {
    for (name, kind, scenario) in GOLDENS {
        let s = scenario();
        let base = run(*kind, &s);
        let n = s.traffic.len();
        // Every rotation plus the reversal (deterministic "shuffles").
        let mut orders: Vec<Vec<PodTraffic>> = (0..n)
            .map(|i| {
                let mut t = s.traffic.clone();
                t.rotate_left(i);
                t
            })
            .collect();
        orders.push(s.traffic.iter().rev().cloned().collect());
        for t in orders {
            let got = generate(*kind, &s.target.pod_name, &t, &s.target, &s.stub).unwrap();
            assert_eq!(got.yaml, base.yaml, "{name}: order-dependent output");
        }
    }
}

#[test]
fn ports_dedup_and_sort_and_protocols_coexist() {
    let s = Scenario {
        stub: Stub::default(),
        target: pod("dns-client", "prod", "10.0.0.1", &[("app", "c")]),
        traffic: vec![
            egress("10.0.0.1", "10.96.0.10", "53"),
            PodTraffic {
                ip_protocol: "UDP".into(),
                ..egress("10.0.0.1", "10.96.0.10", "53")
            },
            egress("10.0.0.1", "10.96.0.10", "53"),
            egress("10.0.0.1", "10.96.0.10", "443"),
            egress("10.0.0.1", "10.96.0.10", "80"),
            egress("10.0.0.1", "10.96.0.10", "80junk"), // dropped (Atoi)
            egress("10.0.0.1", "10.96.0.10", "70000"),  // dropped (range)
        ],
    };
    let p = run(PolicyKind::Standard, &s);
    let eg = rules(&p, "egress");
    assert_eq!(eg.len(), 1);
    assert_eq!(
        eg[0]["ports"],
        serde_json::json!([
            {"port": 53, "protocol": "TCP"},
            {"port": 53, "protocol": "UDP"},
            {"port": 80, "protocol": "TCP"},
            {"port": 443, "protocol": "TCP"},
        ])
    );
}

#[test]
fn guard_excludes_late_starts_unknown_starts_and_long_dead_pods() {
    let flow = "2026-07-23T10:00:00";
    let mut p = pod("x", "ns", "10.0.0.9", &[("app", "x")]);
    // Unknown start: excluded.
    assert!(excluded_by_guard(&p, flow));
    // Started after the flow: excluded.
    p.started_at = "2026-07-23T10:00:01".into();
    assert!(excluded_by_guard(&p, flow));
    // Started before, alive: kept.
    p.started_at = "2026-07-01T00:00:00.123456".into();
    assert!(!excluded_by_guard(&p, flow));
    // Dead and last seen before the flow: excluded; last seen after: kept.
    p.is_dead = true;
    p.time_stamp = "2026-07-22T00:00:00".into();
    assert!(excluded_by_guard(&p, flow));
    p.time_stamp = "2026-07-24T00:00:00Z".into();
    assert!(!excluded_by_guard(&p, flow));
    // No row time: nothing to compare, kept.
    assert!(!excluded_by_guard(&pod("y", "ns", "", &[]), ""));
}

#[test]
fn stored_identity_that_vanished_is_pinned_not_re_resolved() {
    let mut s = stored_peer_identity();
    s.stub
        .all_pods
        .retain(|p| !p.pod_name.starts_with("cmangos-backup"));
    let p = run(PolicyKind::Cilium, &s);
    assert!(!p.policy.to_string().contains("autobrr"));
    assert_eq!(rules(&p, "ingress")[0]["fromCIDR"][0], "10.244.12.199/32");
    assert!(p
        .comments
        .contains(&"unattributed peer 10.244.12.199 at 2026-09-03T05:00:00".to_string()));
}

#[test]
fn wire_json_deserialises_with_nulls() {
    let t: PodTraffic = serde_json::from_value(serde_json::json!({
        "uuid": "u", "pod_name": "web", "pod_ip": "10.0.0.1", "pod_port": "8080",
        "ip_protocol": "TCP", "traffic_type": "INGRESS", "traffic_in_out_ip": "10.0.0.7",
        "traffic_in_out_port": null, "decision": null, "time_stamp": "2026-07-23T10:00:00",
        "peer_kind": null, "peer_namespace": null
    }))
    .unwrap();
    assert_eq!(t.traffic_in_out_port, "");
    assert_eq!(t.peer_kind, "");
    let mut d: PodDetail = serde_json::from_value(serde_json::json!({
        "pod_name": "web", "pod_ip": "10.0.0.1", "pod_namespace": "prod",
        "host_network": null, "pod_ips": null, "is_dead": false
    }))
    .unwrap();
    d.apply_pod_obj(&serde_json::json!({
        "metadata": {"labels": {"app": "web"}, "uid": "abc"}, "spec": {"nodeName": "n1"}
    }));
    assert_eq!(d.labels, labels(&[("app", "web")]));
    assert_eq!((d.uid.as_str(), d.spec_node_name.as_str()), ("abc", "n1"));
    assert_eq!(
        SvcDetail::selector_from_service_spec(
            &serde_json::json!({"spec": {"selector": {"app": "db"}}})
        ),
        labels(&[("app", "db")])
    );
}
