//! Workload profile export bundle (#1533 P2-4):
//! `GET /workloads/{ns}/{kind}/{name}/export`.
//!
//! One request, every artifact kguardian can generate for a workload,
//! assembled from the EXISTING generators:
//!
//! | artifact | generator |
//! |---|---|
//! | `networkpolicy` | [`crate::netpol`] (Rust port of the advisor reference, held to the shared goldens) |
//! | `ciliumnetworkpolicy` | same, Cilium kind |
//! | `seccompprofile` | [`crate::seccomp::bundle_export`] (the `/seccomp/profiles/{..}/export` path) |
//! | `securitycontext` | the profile's PSS recommendation ([`crate::pod_security`]) |
//! | `sbom`, `vex` | not available until runtime SBOM data exists (P1-3 / P1-5) |
//! | `admission` | not available until the image trust policy exists (P2-3) |
//!
//! Report and generate only: kguardian never applies anything. Every
//! document carries provenance annotations and a header saying so.
//!
//! # Modes
//!
//! `audit` (default) produces documents that observe without blocking:
//! `AuditNetworkPolicy` (kguardian's CRD, evaluated by the evaluator) instead
//! of `NetworkPolicy`, a `SCMP_ACT_LOG` SeccompProfile. A
//! CiliumNetworkPolicy has no per-policy audit mode, so in audit mode it is
//! withheld with a reason. `enforce` produces the enforcing kinds and is
//! refused (409) for an artifact whose evidence is partial (seccomp capture
//! below full, network observed under 24 h / not at all / truncated),
//! exactly like the standalone seccomp export, unless
//! `acknowledgePartial=true`.
//!
//! # Network policies for a workload
//!
//! The generator is per pod. For a workload it gets the traffic rows of
//! every pod of the workload (newest first, bounded) and, as the target, the
//! newest live pod with its labels replaced by the workload's selector
//! labels (`pod_details.workload_selector_labels`), so the policy selects
//! every replica rather than one ReplicaSet's `pod-template-hash`. When the
//! selector is unknown, per-instance labels are dropped from the pod's
//! labels instead (see [`INSTANCE_LABELS`]).

use crate::netpol::{
    self, BrokerData, PodDetail as NpPod, PodTraffic as NpTraffic, PolicyKind, SvcDetail as NpSvc,
};
use crate::read_budget::{cost_kib, ReadBudget, TRAFFIC_ROW_COST_BYTES};
use crate::workload_profile::{self as wp, error, not_found_workload, Key, Profile};
use actix_web::{get, http::StatusCode, web, HttpResponse, Responder};
use chrono::{NaiveDateTime, Utc};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// Every artifact, in bundle order.
pub const ARTIFACTS: [&str; 7] = [
    "networkpolicy",
    "ciliumnetworkpolicy",
    "seccompprofile",
    "securitycontext",
    "sbom",
    "vex",
    "admission",
];

/// Flow rows fed to the network generator (newest first).
pub const EXPORT_TRAFFIC_ROWS: i64 = 20_000;

/// Labels that name one pod or one revision, never the workload.
pub const INSTANCE_LABELS: [&str; 7] = [
    "pod-template-hash",
    "controller-revision-hash",
    "statefulset.kubernetes.io/pod-name",
    "apps.kubernetes.io/pod-index",
    "controller-uid",
    "batch.kubernetes.io/controller-uid",
    "pod-template-generation",
];

pub const ANNOTATION_PREFIX: &str = "kguardian.dev/";

// ---------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    /// Comma-separated subset of [`ARTIFACTS`]; default all.
    pub artifacts: Option<String>,
    /// `audit` (default) | `enforce`.
    pub mode: Option<String>,
    /// `yaml` (default) | `zip-manifest`.
    pub format: Option<String>,
    #[serde(rename = "acknowledgePartial")]
    pub acknowledge_partial: Option<String>,
    /// Record this export as the drift baseline (default true).
    pub record: Option<String>,
}

fn flag(v: Option<&str>, default: bool) -> bool {
    match v.map(|s| s.trim().to_ascii_lowercase()) {
        None => default,
        Some(s) if s.is_empty() => default,
        Some(s) => matches!(s.as_str(), "true" | "1" | "yes" | "on"),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub artifacts: Vec<&'static str>,
    pub enforce: bool,
    pub manifest: bool,
    pub acknowledge_partial: bool,
    pub record: bool,
}

pub fn plan(q: &ExportQuery) -> Result<Plan, String> {
    let artifacts: Vec<&'static str> = match q.artifacts.as_deref().map(str::trim) {
        None | Some("") => ARTIFACTS.to_vec(),
        Some(list) => {
            let mut out = Vec::new();
            for a in list.split(',').map(|a| a.trim().to_ascii_lowercase()) {
                if a.is_empty() {
                    continue;
                }
                let Some(known) = ARTIFACTS.iter().find(|x| **x == a) else {
                    return Err(format!(
                        "unknown artifact {a:?}; expected any of {}",
                        ARTIFACTS.join(",")
                    ));
                };
                if !out.contains(known) {
                    out.push(*known);
                }
            }
            if out.is_empty() {
                return Err("artifacts is empty".into());
            }
            // Bundle order, whatever order was asked for.
            ARTIFACTS
                .iter()
                .copied()
                .filter(|a| out.contains(a))
                .collect()
        }
    };
    let enforce = match q.mode.as_deref().map(str::trim) {
        None | Some("") | Some("audit") => false,
        Some("enforce") => true,
        Some(m) => return Err(format!("invalid mode {m:?}; expected audit or enforce")),
    };
    let manifest = match q.format.as_deref().map(str::trim) {
        None | Some("") | Some("yaml") => false,
        Some("zip-manifest") => true,
        Some(f) => {
            return Err(format!(
                "invalid format {f:?}; expected yaml or zip-manifest"
            ))
        }
    };
    Ok(Plan {
        artifacts,
        enforce,
        manifest,
        acknowledge_partial: flag(q.acknowledge_partial.as_deref(), false),
        record: flag(q.record.as_deref(), true),
    })
}

// ---------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------

/// One entry of the bundle.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub artifact: &'static str,
    /// Suggested file name inside a zip.
    pub file_name: String,
    /// False = nothing generated; `reason` says why.
    pub available: bool,
    /// Set when the artifact was refused in enforce mode (partial evidence).
    pub refused: Option<String>,
    /// Why it is unavailable / withheld / refused; `null` when included.
    pub reason: Option<String>,
    pub api_version: Option<String>,
    pub kind: Option<String>,
    /// `audit` | `enforce` (what this document does once applied).
    pub mode: &'static str,
    /// `application/yaml`; `null` when not available.
    pub content_type: Option<&'static str>,
    /// The document text (YAML, comment header included); `null` when not
    /// available.
    pub content: Option<String>,
    /// How to use it (`kubectl apply -f <file>` / `kubectl patch ...`).
    pub apply_with: Option<String>,
}

fn unavailable(artifact: &'static str, mode: &'static str, reason: &str) -> Document {
    Document {
        artifact,
        file_name: format!("{artifact}.yaml"),
        available: false,
        refused: None,
        reason: Some(reason.to_string()),
        api_version: None,
        kind: None,
        mode,
        content_type: None,
        content: None,
        apply_with: None,
    }
}

fn refused(artifact: &'static str, reason: String) -> Document {
    Document {
        refused: Some(reason.clone()),
        ..unavailable(artifact, "enforce", &reason)
    }
}

/// Provenance stamped onto every Kubernetes document.
pub fn provenance(key: &Key, p: &Profile, mode: &str) -> BTreeMap<String, String> {
    let a = |k: &str| format!("{ANNOTATION_PREFIX}{k}");
    BTreeMap::from([
        (
            a("generated-by"),
            format!("kguardian-broker/{}", env!("CARGO_PKG_VERSION")),
        ),
        (a("generated-at"), p.generated_at.to_rfc3339()),
        (
            a("source-workload"),
            format!("{}/{}/{}", key.namespace, key.kind, key.name),
        ),
        (
            a("profile-revision"),
            p.version
                .as_ref()
                .map_or("unversioned".to_string(), |v| v.revision.to_string()),
        ),
        (a("profile-hash"), p.content_hash.clone()),
        (a("export-mode"), mode.to_string()),
        (a("applied-by-kguardian"), "false".to_string()),
    ])
}

fn doc_header(artifact: &str, mode: &str) -> String {
    format!(
        "# kguardian export: {artifact} ({mode} mode)\n\
         # kguardian never applies this document. Review it, commit it, and apply it yourself.\n"
    )
}

/// DNS-1123 name for a workload's generated object.
pub fn object_name(workload: &str) -> String {
    let mut n: String = format!("{workload}-kguardian")
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    n.truncate(253);
    n.trim_matches(|c: char| c == '-' || c == '.').to_string()
}

// ---------------------------------------------------------------------
// Network: data adapter over the broker's own tables
// ---------------------------------------------------------------------

fn fmt_ts(t: NaiveDateTime) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.f").to_string()
}

fn np_pod(p: crate::PodDetail) -> NpPod {
    let mut out = NpPod {
        pod_name: p.pod_name,
        pod_namespace: p.pod_namespace.unwrap_or_default(),
        pod_ip: p.pod_ip,
        pod_ips: p
            .pod_ips
            .as_ref()
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        node_name: p.node_name,
        workload_name: p.workload_name.unwrap_or_default(),
        host_network: p.host_network,
        is_dead: p.is_dead,
        started_at: p.started_at.map(fmt_ts).unwrap_or_default(),
        time_stamp: fmt_ts(p.time_stamp),
        ..Default::default()
    };
    if let Some(obj) = &p.pod_obj {
        out.apply_pod_obj(obj);
    }
    out
}

/// `BrokerData` over the broker's tables: the same lookups the advisor
/// makes over HTTP (`/pod/ip`, `/svc/ip`, `/pod/info`), done in-process
/// and memoised per request. Errors are logged and read as "not found",
/// the reference behaviour.
struct DbData<'a> {
    conn: RefCell<&'a mut PgConnection>,
    by_ip: RefCell<HashMap<String, Option<NpPod>>>,
    holders: RefCell<HashMap<String, Vec<NpPod>>>,
    svc: RefCell<HashMap<String, Option<NpSvc>>>,
}

fn logged<T>(r: Result<T, DbError>, what: &str) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, lookup = what, "export: broker lookup failed; treated as not found");
            None
        }
    }
}

impl BrokerData for DbData<'_> {
    fn pod_by_ip(&self, ip: &str) -> Option<NpPod> {
        if let Some(v) = self.by_ip.borrow().get(ip) {
            return v.clone();
        }
        let v = logged(
            crate::get::pod_ip(&mut self.conn.borrow_mut(), ip),
            "pod_by_ip",
        )
        .flatten()
        .map(np_pod);
        self.by_ip.borrow_mut().insert(ip.to_string(), v.clone());
        v
    }

    fn service_by_ip(&self, ip: &str) -> Option<NpSvc> {
        if let Some(v) = self.svc.borrow().get(ip) {
            return v.clone();
        }
        let v = logged(
            crate::get::svc_ip(&mut self.conn.borrow_mut(), ip),
            "service_by_ip",
        )
        .flatten()
        .map(|s| NpSvc {
            svc_ip: s.svc_ip,
            svc_name: s.svc_name.unwrap_or_default(),
            svc_namespace: s.svc_namespace.unwrap_or_default(),
            selector: s
                .service_spec
                .as_ref()
                .map(NpSvc::selector_from_service_spec)
                .unwrap_or_default(),
        });
        self.svc.borrow_mut().insert(ip.to_string(), v.clone());
        v
    }

    fn pods(&self) -> Vec<NpPod> {
        use crate::schema::pod_details::dsl as pd;
        let rows: Option<Vec<crate::PodDetail>> = logged(
            pd::pod_details
                .limit(crate::read_budget::ASSUMED_MAX_PODS)
                .load(&mut **self.conn.borrow_mut())
                .map_err(|e| Box::new(e) as DbError),
            "pods",
        );
        rows.unwrap_or_default().into_iter().map(np_pod).collect()
    }

    fn pods_holding_ip(&self, ip: &str) -> Vec<NpPod> {
        if let Some(v) = self.holders.borrow().get(ip) {
            return v.clone();
        }
        let v: Vec<NpPod> = logged(
            crate::get::pod_candidates_by_ip(&mut self.conn.borrow_mut(), ip),
            "pods_holding_ip",
        )
        .unwrap_or_default()
        .into_iter()
        .map(np_pod)
        .collect();
        self.holders.borrow_mut().insert(ip.to_string(), v.clone());
        v
    }

    fn pods_named(&self, namespace: &str, name: &str) -> Vec<NpPod> {
        use crate::schema::pod_details::dsl as pd;
        logged(
            pd::pod_details
                .filter(pd::pod_name.eq(name))
                .filter(pd::pod_namespace.eq(namespace))
                .load::<crate::PodDetail>(&mut **self.conn.borrow_mut())
                .map_err(|e| Box::new(e) as DbError),
            "pods_named",
        )
        .unwrap_or_default()
        .into_iter()
        .map(np_pod)
        .collect()
    }

    fn host_network_pods_matching(
        &self,
        namespace: &str,
        selector: &BTreeMap<String, String>,
    ) -> Vec<NpPod> {
        use crate::schema::pod_details::dsl as pd;
        logged(
            pd::pod_details
                .filter(pd::pod_namespace.eq(namespace))
                .filter(pd::host_network.eq(true))
                .filter(pd::is_dead.eq(false))
                .limit(crate::read_budget::ASSUMED_MAX_PODS)
                .load::<crate::PodDetail>(&mut **self.conn.borrow_mut())
                .map_err(|e| Box::new(e) as DbError),
            "host_network_pods_matching",
        )
        .unwrap_or_default()
        .into_iter()
        .map(np_pod)
        .filter(|p| selector.iter().all(|(k, v)| p.labels.get(k) == Some(v)))
        .collect()
    }
}

/// The generator inputs for a workload: its newest live pod as the target
/// (selector labels substituted) and the newest flow rows of all its pods.
fn network_inputs(
    conn: &mut PgConnection,
    key: &Key,
) -> Result<Option<(NpPod, Vec<NpTraffic>)>, DbError> {
    use crate::schema::pod_details::dsl as pd;
    use crate::schema::pod_traffic::dsl as pt;
    let pods: Vec<crate::PodDetail> = if key.kind == "Pod" {
        pd::pod_details
            .filter(pd::pod_namespace.eq(&key.namespace))
            .filter(pd::pod_name.eq(&key.name))
            .load(conn)?
    } else {
        pd::pod_details
            .filter(pd::pod_namespace.eq(&key.namespace))
            .filter(pd::workload_kind.eq(&key.kind))
            .filter(pd::workload_name.eq(&key.name))
            .order((pd::is_dead.asc(), pd::time_stamp.desc()))
            .limit(wp::PODS_MAX)
            .load(conn)?
    };
    let Some(first) = pods.iter().find(|p| !p.is_dead).or(pods.first()).cloned() else {
        return Ok(None);
    };
    let names: Vec<String> = pods.iter().map(|p| p.pod_name.clone()).collect();
    let selector: Option<BTreeMap<String, String>> = first
        .workload_selector_labels
        .as_ref()
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect::<BTreeMap<_, _>>()
        })
        .filter(|m| !m.is_empty());
    let mut target = np_pod(first);
    target.labels = match selector {
        Some(s) => s,
        None => target
            .labels
            .into_iter()
            .filter(|(k, _)| !INSTANCE_LABELS.contains(&k.as_str()))
            .collect(),
    };
    let rows: Vec<crate::PodTraffic> = pt::pod_traffic
        .filter(pt::pod_namespace.eq(&key.namespace))
        .filter(pt::pod_name.eq_any(&names))
        .order((pt::time_stamp.desc(), pt::uuid.desc()))
        .limit(EXPORT_TRAFFIC_ROWS)
        .load(conn)?;
    let traffic = rows
        .into_iter()
        .map(|r| NpTraffic {
            pod_ip: r.pod_ip.unwrap_or_default(),
            pod_port: r.pod_port.unwrap_or_default(),
            traffic_type: r.traffic_type.unwrap_or_default(),
            traffic_in_out_ip: r.traffic_in_out_ip.unwrap_or_default(),
            traffic_in_out_port: r.traffic_in_out_port.unwrap_or_default(),
            ip_protocol: r.ip_protocol.unwrap_or_default(),
            time_stamp: fmt_ts(r.time_stamp),
            peer_kind: r.peer_kind.unwrap_or_default(),
            peer_namespace: r.peer_namespace.unwrap_or_default(),
            peer_name: r.peer_name.unwrap_or_default(),
            peer_uid: r.peer_uid.unwrap_or_default(),
            peer_workload_kind: r.peer_workload_kind.unwrap_or_default(),
            peer_workload_name: r.peer_workload_name.unwrap_or_default(),
        })
        .collect();
    Ok(Some((target, traffic)))
}

/// Why network evidence is too thin to enforce, or `None`.
pub fn network_partial(p: &Profile) -> Option<String> {
    let n = &p.dimensions.network;
    if n.peers.is_empty() {
        return Some("no flows have been observed for this workload".into());
    }
    if n.truncated {
        return Some(
            "the flow summary is truncated (more peers or flow rows than the export reads)".into(),
        );
    }
    if p.readiness
        .iter()
        .any(|r| r.id == "trafficObserved24h" && r.ok != Some(true))
    {
        return Some("traffic has been observed for less than 24 h".into());
    }
    None
}

/// Rewrite a generated policy for the bundle: workload name, provenance
/// annotations, and (audit mode) the AuditNetworkPolicy kind.
pub fn restamp(
    policy: &mut Value,
    key: &Key,
    audit_kind: bool,
    annotations: &BTreeMap<String, String>,
) {
    if audit_kind {
        policy["apiVersion"] = json!("kguardian.dev/v1alpha1");
        policy["kind"] = json!("AuditNetworkPolicy");
    }
    let meta = &mut policy["metadata"];
    meta["name"] = json!(object_name(&key.name));
    meta["namespace"] = json!(key.namespace);
    if let Some(labels) = meta.get_mut("labels").and_then(Value::as_object_mut) {
        labels.insert("app.kubernetes.io/name".into(), json!(key.name));
    }
    let ann = meta
        .as_object_mut()
        .expect("policy metadata is an object")
        .entry("annotations")
        .or_insert_with(|| json!({}));
    for (k, v) in annotations {
        ann[k] = json!(v);
    }
}

fn network_doc(
    artifact: &'static str,
    kind: PolicyKind,
    key: &Key,
    p: &Profile,
    plan: &Plan,
    inputs: Option<&(NpPod, Vec<NpTraffic>)>,
    data: &dyn BrokerData,
) -> Document {
    let mode = if plan.enforce { "enforce" } else { "audit" };
    if kind == PolicyKind::Cilium && !plan.enforce {
        return unavailable(
            artifact,
            mode,
            "withheld in audit mode: a CiliumNetworkPolicy has no per-policy audit mode and enforces as soon as it is applied. Use the networkpolicy artifact (an AuditNetworkPolicy, evaluated by kguardian without blocking) to audit, then export with mode=enforce.",
        );
    }
    if plan.enforce && !plan.acknowledge_partial {
        if let Some(why) = network_partial(p) {
            return refused(
                artifact,
                format!("refusing to export an enforcing {artifact}: {why}. Export in audit mode, or pass acknowledgePartial=true."),
            );
        }
    }
    let Some((target, traffic)) = inputs else {
        return unavailable(
            artifact,
            mode,
            "no pod of this workload is known to the broker",
        );
    };
    let gen = match netpol::generate(kind, &key.name, traffic, target, data) {
        Ok(g) => g,
        Err(e) => return unavailable(artifact, mode, &format!("generation failed: {e}")),
    };
    let mut policy = gen.policy.clone();
    let audit_kind = kind == PolicyKind::Standard && !plan.enforce;
    restamp(&mut policy, key, audit_kind, &provenance(key, p, mode));
    let body = match netpol::render_yaml(&policy, &gen.comment_set) {
        Ok(b) => b,
        Err(e) => return unavailable(artifact, mode, &format!("rendering failed: {e}")),
    };
    let mut header = doc_header(artifact, mode);
    if audit_kind {
        header.push_str("# AuditNetworkPolicy: same spec as a NetworkPolicy; the kguardian evaluator reports would-deny flows without dropping anything. Promote with `kubectl kguardian audit promote`.\n");
    }
    if p.dimensions.network.truncated {
        header.push_str(
            "# WARNING: built from a truncated flow set; rules for unseen peers may be missing.\n",
        );
    }
    Document {
        artifact,
        file_name: format!("{artifact}.yaml"),
        available: true,
        refused: None,
        reason: None,
        api_version: policy["apiVersion"].as_str().map(String::from),
        kind: policy["kind"].as_str().map(String::from),
        mode,
        content_type: Some("application/yaml"),
        content: Some(header + &body),
        apply_with: Some(format!("kubectl apply -f {artifact}.yaml")),
    }
}

fn seccomp_doc(
    conn: &mut PgConnection,
    key: &Key,
    p: &Profile,
    plan: &Plan,
) -> Result<Document, DbError> {
    let mode = if plan.enforce { "enforce" } else { "audit" };
    let artifact = "seccompprofile";
    let Some(b) = crate::seccomp::bundle_export(
        conn,
        &key.namespace,
        &key.kind,
        &key.name,
        plan.enforce,
        plan.acknowledge_partial,
        &provenance(key, p, mode),
    )?
    else {
        return Ok(unavailable(
            artifact,
            mode,
            "no syscalls have been captured for this workload",
        ));
    };
    if let Some(msg) = b.refused {
        return Ok(refused(artifact, msg.trim().to_string()));
    }
    Ok(Document {
        artifact,
        file_name: format!("{artifact}.yaml"),
        available: true,
        refused: None,
        reason: None,
        api_version: Some("kguardian.dev/v1alpha1".into()),
        kind: Some("SeccompProfile".into()),
        mode,
        content_type: Some("application/yaml"),
        content: b.yaml.map(|y| doc_header(artifact, mode) + &y),
        apply_with: Some(format!("kubectl apply -f {artifact}.yaml")),
    })
}

fn security_context_doc(key: &Key, p: &Profile, plan: &Plan) -> Document {
    let mode = if plan.enforce { "enforce" } else { "audit" };
    let artifact = "securitycontext";
    let a = &p.dimensions.pod_security.analysis;
    let Some(rec) = &a.recommendation else {
        let why = match a.level {
            None => "no container securityContext has been reported for this workload",
            _ => "nothing failing is patchable (every evaluated check passes restricted, or only ephemeral containers fail)",
        };
        return unavailable(artifact, mode, why);
    };
    let label = if plan.enforce { "enforce" } else { "audit" };
    let mut header = doc_header(artifact, mode);
    header.push_str(&format!(
        "# Strategic-merge PATCH for {kind}/{name}, not a standalone object. Apply with:\n\
         #   kubectl patch {kind_l} {name} -n {ns} --type strategic --patch-file {artifact}.patch.yaml\n\
         # Then check the namespace against the target level without blocking first:\n\
         #   kubectl label namespace {ns} pod-security.kubernetes.io/{label}=restricted\n",
        kind = key.kind,
        name = key.name,
        kind_l = key.kind.to_ascii_lowercase(),
        ns = key.namespace,
    ));
    for c in &rec.caveats {
        header.push_str(&format!("# CAVEAT: {c}\n"));
    }
    Document {
        artifact,
        file_name: format!("{artifact}.patch.yaml"),
        available: true,
        refused: None,
        reason: None,
        api_version: None,
        kind: None,
        mode,
        content_type: Some("application/yaml"),
        content: Some(header + &rec.yaml),
        apply_with: Some(format!(
            "kubectl patch {} {} -n {} --type strategic --patch-file {artifact}.patch.yaml",
            key.kind.to_ascii_lowercase(),
            key.name,
            key.namespace
        )),
    }
}

/// The whole bundle.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Bundle {
    pub workload: Value,
    pub mode: &'static str,
    pub generated_at: String,
    pub profile: Value,
    pub recorded: bool,
    pub documents: Vec<Document>,
}

/// Build every requested document. Pure apart from the DB reads.
pub fn build_documents(
    conn: &mut PgConnection,
    key: &Key,
    p: &Profile,
    plan: &Plan,
) -> Result<Vec<Document>, DbError> {
    let mode = if plan.enforce { "enforce" } else { "audit" };
    let wants_net = plan
        .artifacts
        .iter()
        .any(|a| *a == "networkpolicy" || *a == "ciliumnetworkpolicy");
    let inputs = if wants_net {
        network_inputs(conn, key)?
    } else {
        None
    };
    let mut docs = Vec::new();
    for a in &plan.artifacts {
        let d = match *a {
            "networkpolicy" | "ciliumnetworkpolicy" => {
                let kind = if *a == "networkpolicy" {
                    PolicyKind::Standard
                } else {
                    PolicyKind::Cilium
                };
                let data = DbData {
                    conn: RefCell::new(&mut *conn),
                    by_ip: RefCell::default(),
                    holders: RefCell::default(),
                    svc: RefCell::default(),
                };
                network_doc(a, kind, key, p, plan, inputs.as_ref(), &data)
            }
            "seccompprofile" => seccomp_doc(conn, key, p, plan)?,
            "securitycontext" => security_context_doc(key, p, plan),
            "sbom" => unavailable(
                "sbom",
                mode,
                "not available: a CycloneDX runtime SBOM needs the runtime package data from P1-3/P1-5, which does not exist yet",
            ),
            "vex" => unavailable(
                "vex",
                mode,
                "not available: an OpenVEX draft needs vulnerability data and runtime package evidence (P1-3/P1-5), which do not exist yet",
            ),
            _ => unavailable(
                "admission",
                mode,
                "not available: the image admission policy needs the image trust policy (P2-3), which has not landed",
            ),
        };
        docs.push(d);
    }
    Ok(docs)
}

/// The multi-document YAML: a bundle header, then every available
/// Kubernetes object as its own document. The securityContext PATCH is not
/// an object, so it is appended as comments (the stream stays safe to
/// `kubectl apply -f`); the manifest format carries it as its own file.
pub fn render_bundle_yaml(
    key: &Key,
    p: &Profile,
    plan: &Plan,
    docs: &[Document],
    recorded: bool,
) -> String {
    let mode = if plan.enforce { "enforce" } else { "audit" };
    let mut y = format!(
        "# kguardian export bundle for {ns}/{kind}/{name}\n\
         # mode: {mode}; profile revision {rev} ({hash}); generated {at} by kguardian-broker/{ver}\n\
         # kguardian never applies anything. Review every document, commit it, and apply it yourself.\n",
        ns = key.namespace,
        kind = key.kind,
        name = key.name,
        rev = p.version.as_ref().map_or("unversioned".to_string(), |v| v.revision.to_string()),
        hash = p.content_hash,
        at = p.generated_at.to_rfc3339(),
        ver = env!("CARGO_PKG_VERSION"),
    );
    if recorded {
        y.push_str("# This export is recorded as the drift baseline for the workload.\n");
    }
    for d in docs.iter().filter(|d| !d.available) {
        y.push_str(&format!(
            "# not included: {} ({})\n",
            d.artifact,
            d.reason.as_deref().unwrap_or("not available")
        ));
    }
    for d in docs
        .iter()
        .filter(|d| d.available && d.artifact != "securitycontext")
    {
        y.push_str("---\n");
        y.push_str(d.content.as_deref().unwrap_or(""));
    }
    if let Some(d) = docs
        .iter()
        .find(|d| d.available && d.artifact == "securitycontext")
    {
        y.push_str(
            "\n# ---- securitycontext (strategic-merge patch; not part of the apply stream) ----\n",
        );
        for line in d.content.as_deref().unwrap_or("").lines() {
            if line.starts_with('#') {
                y.push_str(line);
            } else {
                y.push_str("#   ");
                y.push_str(line);
            }
            y.push('\n');
        }
    }
    y
}

// ---------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------

#[get(
    "/workloads/{namespace}/{kind}/{name}/export",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_workload_export(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<(String, String, String)>,
    query: web::Query<ExportQuery>,
) -> actix_web::Result<impl Responder> {
    let (ns, kind, name) = path.into_inner();
    let Some(key) = Key::parse(ns, kind, name) else {
        return Ok(wp::bad_key());
    };
    let plan = match plan(&query.into_inner()) {
        Ok(p) => p,
        Err(m) => return Ok(error(StatusCode::BAD_REQUEST, "bad_request", &m)),
    };
    // The profile, plus the export's own bounded reads: flow rows for the
    // network generator and its memoised per-IP lookups.
    let charge = wp::profile_charge_kib()
        .saturating_add(cost_kib(EXPORT_TRAFFIC_ROWS, TRAFFIC_ROW_COST_BYTES))
        .saturating_add(cost_kib(wp::PODS_MAX, 4_096));
    let _permit = match budget.acquire(charge).await {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    enum Out {
        NotFound,
        Refused(Vec<Document>),
        Ok(Bundle, String),
    }
    let plan2 = plan.clone();
    let out = web::block(move || -> Result<Out, DbError> {
        let mut conn = pool.get()?;
        let s = wp::load_sources(&mut conn, &key)?;
        if s.is_empty() {
            return Ok(Out::NotFound);
        }
        let p = wp::build(&key, &s, Utc::now());
        let docs = build_documents(&mut conn, &key, &p, &plan2)?;
        let refusals: Vec<Document> = docs
            .iter()
            .filter(|d| d.refused.is_some())
            .cloned()
            .collect();
        if !refusals.is_empty() {
            return Ok(Out::Refused(refusals));
        }
        let included: Vec<String> = docs
            .iter()
            .filter(|d| d.available)
            .map(|d| d.artifact.to_string())
            .collect();
        let recorded = plan2.record && !included.is_empty();
        if recorded {
            crate::profile_drift::record_export(
                &mut conn,
                &key,
                p.version.as_ref().map(|v| v.revision),
                &p.content_hash,
                if plan2.enforce { "enforce" } else { "audit" },
                &included,
                &p.snapshot,
            )?;
        }
        let yaml = render_bundle_yaml(&key, &p, &plan2, &docs, recorded);
        Ok(Out::Ok(
            Bundle {
                workload: json!({
                    "clusterId": crate::image_inventory::DEFAULT_CLUSTER_ID,
                    "namespace": key.namespace,
                    "kind": key.kind,
                    "name": key.name,
                }),
                mode: if plan2.enforce { "enforce" } else { "audit" },
                generated_at: p.generated_at.to_rfc3339(),
                profile: json!({
                    "revision": p.version.as_ref().map(|v| v.revision),
                    "contentHash": p.content_hash,
                }),
                recorded,
                documents: docs,
            },
            yaml,
        ))
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(match out {
        Out::NotFound => not_found_workload(),
        Out::Refused(r) => HttpResponse::Conflict().json(json!({
            "error": "export_refused",
            "message": "enforce mode was refused for artifacts whose evidence is partial; export in audit mode, drop those artifacts, or pass acknowledgePartial=true",
            "refusals": r.iter().map(|d| json!({ "artifact": d.artifact, "reason": d.refused })).collect::<Vec<_>>(),
        })),
        Out::Ok(bundle, yaml) => {
            let mut b = HttpResponse::Ok();
            b.insert_header(("X-Kguardian-Export-Mode", bundle.mode));
            b.insert_header((
                "X-Kguardian-Export-Recorded",
                if bundle.recorded { "true" } else { "false" },
            ));
            if plan.manifest {
                b.json(bundle)
            } else {
                b.content_type("application/yaml").body(yaml)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(artifacts: Option<&str>, mode: Option<&str>, format: Option<&str>) -> ExportQuery {
        ExportQuery {
            artifacts: artifacts.map(String::from),
            mode: mode.map(String::from),
            format: format.map(String::from),
            acknowledge_partial: None,
            record: None,
        }
    }

    #[test]
    fn plan_defaults_to_audit_yaml_all_artifacts_recorded() {
        let p = plan(&q(None, None, None)).unwrap();
        assert_eq!(p.artifacts, ARTIFACTS.to_vec());
        assert!(!p.enforce && !p.manifest && !p.acknowledge_partial && p.record);
    }

    #[test]
    fn plan_validates_and_orders_artifacts() {
        let p = plan(&q(
            Some("seccompprofile, NetworkPolicy,seccompprofile"),
            Some("enforce"),
            Some("zip-manifest"),
        ))
        .unwrap();
        assert_eq!(p.artifacts, vec!["networkpolicy", "seccompprofile"]);
        assert!(p.enforce && p.manifest);
        assert!(plan(&q(Some("helmchart"), None, None)).is_err());
        assert!(plan(&q(Some(" , "), None, None)).is_err());
        assert!(plan(&q(None, Some("dry-run"), None)).is_err());
        assert!(plan(&q(None, None, Some("tar"))).is_err());
        let mut x = q(None, None, None);
        x.record = Some("false".into());
        x.acknowledge_partial = Some("1".into());
        let p = plan(&x).unwrap();
        assert!(!p.record && p.acknowledge_partial);
    }

    #[test]
    fn object_names_are_dns_1123() {
        assert_eq!(object_name("checkout"), "checkout-kguardian");
        assert_eq!(object_name("Web_API"), "web-api-kguardian");
        assert!(object_name(&"a".repeat(300)).len() <= 253);
    }

    fn key() -> Key {
        Key {
            namespace: "payments".into(),
            kind: "Deployment".into(),
            name: "checkout".into(),
        }
    }

    #[test]
    fn restamp_switches_kind_only_for_audit_and_keeps_spec() {
        let policy = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "checkout-7d9-standard-policy", "namespace": "payments",
                          "labels": {"app.kubernetes.io/name": "checkout-7d9", "app.kubernetes.io/part-of": "kguardian"}},
            "spec": {"podSelector": {"matchLabels": {"app": "checkout"}}, "policyTypes": ["Ingress"]}
        });
        let ann = BTreeMap::from([("kguardian.dev/export-mode".to_string(), "audit".to_string())]);
        let mut a = policy.clone();
        restamp(&mut a, &key(), true, &ann);
        assert_eq!(a["apiVersion"], "kguardian.dev/v1alpha1");
        assert_eq!(a["kind"], "AuditNetworkPolicy");
        assert_eq!(a["metadata"]["name"], "checkout-kguardian");
        assert_eq!(
            a["metadata"]["labels"]["app.kubernetes.io/name"],
            "checkout"
        );
        assert_eq!(
            a["metadata"]["annotations"]["kguardian.dev/export-mode"],
            "audit"
        );
        assert_eq!(a["spec"], policy["spec"], "the spec is never touched");
        let mut e = policy.clone();
        restamp(&mut e, &key(), false, &ann);
        assert_eq!(e["kind"], "NetworkPolicy");
        assert_eq!(e["apiVersion"], "networking.k8s.io/v1");
    }

    fn sources() -> crate::workload_profile::Sources {
        crate::workload_profile::Sources {
            containers: vec![crate::image_inventory::ContainerImages {
                cluster_id: "primary".into(),
                container_name: "app".into(),
                container_kind: "regular".into(),
                mixed_digests: false,
                digests: vec![crate::image_inventory::ContainerDigest {
                    digest: format!("sha256:{}", "a".repeat(64)),
                    image_ref: "ghcr.io/example/checkout:1".into(),
                    security_context: json!({}),
                    pod_security: json!({"automountServiceAccountToken": false}),
                    last_pod_name: Some("checkout-1".into()),
                    first_seen: Utc::now().naive_utc(),
                    last_seen: Utc::now().naive_utc(),
                    state: Some("running".into()),
                    state_reason: None,
                    ran_as_init: false,
                }],
                previous_digests: vec![],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn stubs_and_the_patch_never_enter_the_apply_stream() {
        let p = wp::build(&key(), &sources(), Utc::now());
        let pl = plan(&q(Some("securitycontext,sbom,vex,admission"), None, None)).unwrap();
        let mut docs: Vec<Document> = vec![
            security_context_doc(&key(), &p, &pl),
            unavailable(
                "sbom",
                "audit",
                "not available: runtime SBOM data does not exist yet",
            ),
            unavailable("vex", "audit", "not available: no vulnerability data"),
            unavailable("admission", "audit", "not available: P2-3"),
        ];
        assert!(
            docs[0].available,
            "a context that fails restricted gets a patch"
        );
        assert!(docs[0]
            .apply_with
            .as_deref()
            .unwrap()
            .starts_with("kubectl patch deployment checkout -n payments --type strategic"));
        let y = render_bundle_yaml(&key(), &p, &pl, &docs, false);
        assert!(y.contains("kguardian never applies anything"));
        assert!(y.contains("# not included: sbom (not available"));
        assert!(y.contains("# not included: admission (not available: P2-3)"));
        // No `---` document at all: the patch is commented out, stubs are
        // header lines only.
        assert!(!y.contains("\n---\n") && !y.starts_with("---"));
        for line in y.lines().filter(|l| !l.trim().is_empty()) {
            assert!(
                line.starts_with('#'),
                "non-comment line in the stream: {line}"
            );
        }
        // Enforce mode suggests the enforce label.
        let en = plan(&q(Some("securitycontext"), Some("enforce"), None)).unwrap();
        docs[0] = security_context_doc(&key(), &p, &en);
        assert!(docs[0]
            .content
            .as_deref()
            .unwrap()
            .contains("pod-security.kubernetes.io/enforce=restricted"));
    }

    #[test]
    fn provenance_names_the_source_and_says_it_is_not_applied() {
        let p = wp::build(&key(), &sources(), Utc::now());
        let a = provenance(&key(), &p, "audit");
        assert_eq!(
            a["kguardian.dev/source-workload"],
            "payments/Deployment/checkout"
        );
        assert_eq!(a["kguardian.dev/applied-by-kguardian"], "false");
        assert_eq!(a["kguardian.dev/profile-revision"], "unversioned");
        assert_eq!(a["kguardian.dev/profile-hash"], p.content_hash);
        assert!(a["kguardian.dev/generated-by"].starts_with("kguardian-broker/"));
    }

    #[test]
    fn network_enforce_needs_evidence() {
        let p = wp::build(&key(), &sources(), Utc::now());
        assert_eq!(
            network_partial(&p).as_deref(),
            Some("no flows have been observed for this workload")
        );
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use diesel::connection::SimpleConnection;

    const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");

    fn live_conn() -> PgConnection {
        use diesel_migrations::MigrationHarness;
        let url = std::env::var("KG_TEST_DATABASE_URL").expect("set KG_TEST_DATABASE_URL");
        let mut conn = PgConnection::establish(&url).expect("connect");
        conn.run_pending_migrations(TEST_MIGRATIONS)
            .expect("migrate");
        conn
    }

    const NS: &str = "kgtest-export";

    fn reset(conn: &mut PgConnection) {
        conn.batch_execute(&format!(
            "DELETE FROM workload_containers WHERE pod_namespace = '{NS}'; \
             DELETE FROM workload_syscalls WHERE pod_namespace = '{NS}'; \
             DELETE FROM pod_syscalls WHERE pod_namespace = '{NS}'; \
             DELETE FROM pod_traffic WHERE pod_namespace = '{NS}'; \
             DELETE FROM pod_details WHERE pod_namespace IN ('{NS}', '{NS}-db'); \
             DELETE FROM svc_details WHERE svc_namespace = '{NS}-db'; \
             DELETE FROM workload_profile_versions WHERE pod_namespace = '{NS}'; \
             DELETE FROM workload_profile_latest WHERE pod_namespace = '{NS}'; \
             DELETE FROM workload_profile_exports WHERE pod_namespace = '{NS}';"
        ))
        .expect("reset");
    }

    fn seed(conn: &mut PgConnection, capture: &str) {
        let d = format!("sha256:{}", "e".repeat(64));
        conn.batch_execute(&format!(
            "INSERT INTO pod_details (pod_name, pod_ip, pod_namespace, pod_obj, time_stamp, node_name, is_dead, \
               workload_kind, workload_name, workload_selector_labels, capture_level, started_at) VALUES \
             ('kgx-api-1', '10.77.0.1', '{NS}', '{{\"metadata\": {{\"labels\": {{\"app\": \"api\", \"pod-template-hash\": \"abc\"}}}}}}', \
               timezone('UTC', NOW()), 'n1', false, 'Deployment', 'api', '{{\"app\": \"api\"}}', '{capture}', \
               timezone('UTC', NOW()) - INTERVAL '10 days'), \
             ('kgx-db-1', '10.77.0.9', '{NS}-db', '{{\"metadata\": {{\"labels\": {{\"app\": \"db\"}}}}}}', \
               timezone('UTC', NOW()), 'n1', false, 'StatefulSet', 'db', '{{\"app\": \"db\"}}', 'full', \
               timezone('UTC', NOW()) - INTERVAL '10 days'); \
             INSERT INTO images (digest, repository, tags, digest_kind) VALUES ('{d}', 'ghcr.io/example/api', '{{1}}', 'repo') \
               ON CONFLICT (digest) DO NOTHING; \
             INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, container_name, image_digest, \
               container_kind, image_ref, security_context, pod_security, last_pod_name, state) VALUES \
             ('{NS}', 'Deployment', 'api', 'app', '{d}', 'regular', 'ghcr.io/example/api:1', \
               '{{\"allowPrivilegeEscalation\": false, \"runAsNonRoot\": true, \"capabilitiesDrop\": [\"ALL\"], \"seccompProfileType\": \"RuntimeDefault\"}}', \
               '{{\"automountServiceAccountToken\": false}}', 'kgx-api-1', 'running'); \
             INSERT INTO pod_traffic (uuid, pod_name, pod_namespace, pod_ip, pod_port, ip_protocol, traffic_type, \
               traffic_in_out_ip, traffic_in_out_port, time_stamp, peer_kind, peer_namespace, peer_name, peer_uid) VALUES \
             ('kgx-1', 'kgx-api-1', '{NS}', '10.77.0.1', '40000', 'TCP', 'EGRESS', '10.77.0.9', '5432', \
               timezone('UTC', NOW()) - INTERVAL '3 days', 'pod', '{NS}-db', 'kgx-db-1', NULL), \
             ('kgx-2', 'kgx-api-1', '{NS}', '10.77.0.1', '40001', 'TCP', 'EGRESS', '203.0.113.50', '443', \
               timezone('UTC', NOW()) - INTERVAL '3 days', NULL, NULL, NULL, NULL); \
             INSERT INTO pod_syscalls (pod_name, pod_namespace, syscalls, arch, time_stamp) VALUES \
             ('kgx-api-1', '{NS}', 'read,write', 'x86_64', timezone('UTC', NOW())); \
             INSERT INTO workload_syscalls (pod_namespace, workload_kind, workload_name, syscalls, arches, hash, updated_at, syscall_count) \
             VALUES ('{NS}', 'Deployment', 'api', 'read,write', 'x86_64', 'h', timezone('UTC', NOW()), 2);"
        ))
        .expect("seed");
    }

    fn key() -> Key {
        Key {
            namespace: NS.into(),
            kind: "Deployment".into(),
            name: "api".into(),
        }
    }

    fn docs(conn: &mut PgConnection, pl: &Plan) -> (Profile, Vec<Document>) {
        let s = wp::load_sources(conn, &key()).unwrap();
        let p = wp::build(&key(), &s, Utc::now());
        let d = build_documents(conn, &key(), &p, pl).unwrap();
        (p, d)
    }

    fn find<'a>(d: &'a [Document], a: &str) -> &'a Document {
        d.iter().find(|x| x.artifact == a).unwrap()
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_export_bundle_audit_and_enforce() {
        let mut conn = live_conn();
        reset(&mut conn);
        seed(&mut conn, "medium");

        // Audit: AuditNetworkPolicy selecting the WORKLOAD (no
        // pod-template-hash), cross-namespace peer with AND semantics, a LOG
        // SeccompProfile, CNP withheld, stubs unavailable.
        let audit = plan(&ExportQuery {
            artifacts: None,
            mode: None,
            format: None,
            acknowledge_partial: None,
            record: Some("false".into()),
        })
        .unwrap();
        let (p, d) = docs(&mut conn, &audit);
        let np = find(&d, "networkpolicy");
        assert!(np.available, "{:?}", np.reason);
        assert_eq!(np.kind.as_deref(), Some("AuditNetworkPolicy"));
        let body: Value = serde_norway::from_str(np.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            body["spec"]["podSelector"]["matchLabels"],
            json!({"app": "api"})
        );
        assert_eq!(body["metadata"]["name"], "api-kguardian");
        assert_eq!(
            body["metadata"]["annotations"]["kguardian.dev/applied-by-kguardian"],
            "false"
        );
        let egress = body["spec"]["egress"].as_array().unwrap();
        let db = egress
            .iter()
            .find(|r| r["ports"][0]["port"] == json!(5432))
            .expect("db rule");
        // One peer entry carrying BOTH selectors (AND), in the db namespace.
        assert_eq!(db["to"].as_array().unwrap().len(), 1);
        assert_eq!(
            db["to"][0]["podSelector"]["matchLabels"],
            json!({"app": "db"})
        );
        assert_eq!(
            db["to"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
            json!(format!("{NS}-db"))
        );
        let ext = egress
            .iter()
            .find(|r| r["ports"][0]["port"] == json!(443))
            .expect("external rule");
        assert_eq!(ext["to"][0]["ipBlock"]["cidr"], json!("203.0.113.50/32"));
        assert!(!find(&d, "ciliumnetworkpolicy").available);
        let sc = find(&d, "seccompprofile");
        assert!(sc.available);
        assert!(sc
            .content
            .as_deref()
            .unwrap()
            .contains("defaultAction: SCMP_ACT_LOG"));
        assert!(sc
            .content
            .as_deref()
            .unwrap()
            .contains("kguardian.dev/source-workload"));
        for a in ["sbom", "vex", "admission"] {
            assert!(!find(&d, a).available);
        }
        let y = render_bundle_yaml(&key(), &p, &audit, &d, false);
        let stream: Vec<Value> = y
            .split("\n---\n")
            .skip(1)
            .map(|doc| serde_norway::from_str(doc).unwrap())
            .collect();
        assert_eq!(stream.len(), 2, "AuditNetworkPolicy + SeccompProfile");

        // Enforce: the seccomp capture is partial (medium) -> refused; the
        // network has 3 days of flows -> a real NetworkPolicy and a CNP whose
        // cross-namespace peer carries the namespace label.
        let mut enforce = audit.clone();
        enforce.enforce = true;
        let (_, d) = docs(&mut conn, &enforce);
        assert!(find(&d, "seccompprofile").refused.is_some());
        let np = find(&d, "networkpolicy");
        assert_eq!(np.kind.as_deref(), Some("NetworkPolicy"));
        let cnp = find(&d, "ciliumnetworkpolicy");
        assert!(cnp.available, "{:?}", cnp.reason);
        let c: Value = serde_norway::from_str(cnp.content.as_deref().unwrap()).unwrap();
        let eps = c["spec"]["egress"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r.get("toEndpoints"))
            .flat_map(|e| e.as_array().unwrap().clone())
            .collect::<Vec<_>>();
        assert!(eps
            .iter()
            .any(|e| e["matchLabels"]["k8s:io.kubernetes.pod.namespace"]
                == json!(format!("{NS}-db"))));
        assert!(c["spec"]["endpointSelector"]["matchLabels"]
            .get("k8s:io.kubernetes.pod.namespace")
            .is_none());
        // acknowledgePartial lets the partial seccomp through.
        enforce.acknowledge_partial = true;
        let (_, d) = docs(&mut conn, &enforce);
        let sc = find(&d, "seccompprofile");
        assert!(sc.available);
        assert!(sc.content.as_deref().unwrap().contains("SCMP_ACT_ERRNO"));
        reset(&mut conn);
    }

    #[test]
    #[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
    fn live_export_record_becomes_the_drift_baseline() {
        let mut conn = live_conn();
        reset(&mut conn);
        seed(&mut conn, "full");
        let s = wp::load_sources(&mut conn, &key()).unwrap();
        let p = wp::build(&key(), &s, Utc::now());
        assert!(p.drift.baselines.export.is_none());
        crate::profile_drift::record_export(
            &mut conn,
            &key(),
            None,
            &p.content_hash,
            "audit",
            &["networkpolicy".to_string()],
            &p.snapshot,
        )
        .unwrap();
        // The image changes and the securityContext regresses afterwards.
        conn.batch_execute(&format!(
            "INSERT INTO images (digest, repository, tags, digest_kind) VALUES ('sha256:{f}', 'ghcr.io/example/api', '{{2}}', 'repo') ON CONFLICT (digest) DO NOTHING; \
             UPDATE workload_containers SET image_digest = 'sha256:{f}', security_context = '{{\"privileged\": true}}' \
             WHERE pod_namespace = '{NS}';",
            f = "f".repeat(64)
        ))
        .unwrap();
        let s = wp::load_sources(&mut conn, &key()).unwrap();
        let p = wp::build(&key(), &s, Utc::now());
        assert_eq!(p.drift.baselines.export.as_ref().unwrap().mode, "audit");
        let kinds: Vec<&str> = p.drift.items.iter().map(|i| i.kind).collect();
        assert!(kinds.contains(&"imageChangedSinceExport"), "{kinds:?}");
        assert!(kinds.contains(&"securityContextRegression"), "{kinds:?}");
        // The snapshotter carries drift counts into the list summary, which
        // the /metrics gauge is built from.
        crate::workload_profile::snapshot_one(&mut conn, &key(), 50).unwrap();
        let series = crate::profile_drift::load_series(&mut conn).unwrap();
        let mine: Vec<(String, i64)> = series
            .iter()
            .filter(|(ns, _, name, _, _)| ns == NS && name == "api")
            .map(|(_, _, _, ty, n)| (ty.clone(), *n))
            .collect();
        assert_eq!(
            mine,
            vec![
                ("imageChangedSinceExport".to_string(), 1),
                ("securityContextRegression".to_string(), 1),
            ]
        );
        // A new export of the current state is the new baseline: the drift
        // is accepted and clears.
        crate::profile_drift::record_export(
            &mut conn,
            &key(),
            None,
            &p.content_hash,
            "audit",
            &[],
            &p.snapshot,
        )
        .unwrap();
        let s = wp::load_sources(&mut conn, &key()).unwrap();
        assert!(wp::build(&key(), &s, Utc::now()).drift.items.is_empty());
        // Records are capped per workload.
        for _ in 0..(crate::profile_drift::EXPORTS_MAX_PER_WORKLOAD + 5) {
            crate::profile_drift::record_export(
                &mut conn,
                &key(),
                None,
                "h",
                "audit",
                &[],
                &p.snapshot,
            )
            .unwrap();
        }
        #[derive(QueryableByName)]
        struct N {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            n: i64,
        }
        let n: N = diesel::sql_query(format!(
            "SELECT count(*) AS n FROM workload_profile_exports WHERE pod_namespace = '{NS}'"
        ))
        .get_result(&mut conn)
        .unwrap();
        assert_eq!(n.n, crate::profile_drift::EXPORTS_MAX_PER_WORKLOAD);
        reset(&mut conn);
    }
}
