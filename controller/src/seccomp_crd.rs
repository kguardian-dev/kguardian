//! The `SeccompProfile` custom resource (`kguardian.dev/v1alpha1`).
//!
//! The CR spec is the source of truth for what lands on a node: the
//! user commits and applies it (policy-as-code); kguardian only renders
//! the standard seccomp JSON from it, writes that file to every node,
//! and reports back through `status`. Nothing derived from broker data
//! ever ends up in the file — `render_profile` reads the spec alone.
//!
//! The CRD YAML in `charts/kguardian/files/kguardian.dev_seccompprofiles.yaml`
//! is generated FROM this type (see the `crd_yaml_*` tests) and committed;
//! a test fails when the two drift.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Spec of a `SeccompProfile`: a seccomp profile in its native shape,
/// plus an optional pointer at the workload it is for.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[kube(
    group = "kguardian.dev",
    version = "v1alpha1",
    kind = "SeccompProfile",
    namespaced,
    status = "SeccompProfileStatus",
    shortname = "scmp",
    doc = "A seccomp profile that kguardian distributes to every node as \
           kguardian/<namespace>/<name>.json under the kubelet seccomp root. \
           Reference it from a pod with securityContext.seccompProfile \
           {type: Localhost, localhostProfile: kguardian/<namespace>/<name>.json}.",
    printcolumn = r#"{"name":"Action","type":"string","jsonPath":".spec.defaultAction"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.distribution.summary"}"#,
    printcolumn = r#"{"name":"Drift","type":"string","jsonPath":".status.drift"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct SeccompProfileSpec {
    /// Action for any syscall not matched by a rule.
    pub default_action: DefaultAction,
    /// Architectures the profile applies to (seccomp `architectures`).
    /// Omitted ⇒ the rendered file carries no `architectures` field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<Architecture>>,
    /// Syscall rules. kguardian generates `SCMP_ACT_ALLOW` rules only;
    /// the other actions are accepted for hand edits.
    #[schemars(length(min = 1))]
    pub syscalls: Vec<SyscallRule>,
    /// The workload this profile is for. Enables the `CaptureComplete`
    /// and `Drift` conditions; optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_ref: Option<WorkloadRef>,
}

/// One seccomp rule: a set of syscall names sharing an action.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyscallRule {
    /// Syscall names (`^[a-z][a-z0-9_]{0,63}$`).
    #[schemars(length(min = 1))]
    pub names: Vec<SyscallName>,
    pub action: RuleAction,
    /// errno to return for `SCMP_ACT_ERRNO` rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno_ret: Option<u32>,
}

/// A syscall name. Validated by the CRD schema pattern.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord)]
pub struct SyscallName(#[schemars(regex(pattern = r"^[a-z][a-z0-9_]{0,63}$"))] pub String);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum DefaultAction {
    #[serde(rename = "SCMP_ACT_LOG")]
    Log,
    #[serde(rename = "SCMP_ACT_ERRNO")]
    Errno,
    #[serde(rename = "SCMP_ACT_KILL")]
    Kill,
    #[serde(rename = "SCMP_ACT_KILL_PROCESS")]
    KillProcess,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum RuleAction {
    #[serde(rename = "SCMP_ACT_ALLOW")]
    Allow,
    #[serde(rename = "SCMP_ACT_LOG")]
    Log,
    #[serde(rename = "SCMP_ACT_ERRNO")]
    Errno,
    #[serde(rename = "SCMP_ACT_KILL")]
    Kill,
    #[serde(rename = "SCMP_ACT_KILL_PROCESS")]
    KillProcess,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum Architecture {
    #[serde(rename = "SCMP_ARCH_X86_64")]
    X8664,
    #[serde(rename = "SCMP_ARCH_ARM64")]
    Arm64,
    #[serde(rename = "SCMP_ARCH_X86")]
    X86,
    #[serde(rename = "SCMP_ARCH_X32")]
    X32,
    #[serde(rename = "SCMP_ARCH_AARCH64")]
    Aarch64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct WorkloadRef {
    pub kind: WorkloadKind,
    pub name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum WorkloadKind {
    Deployment,
    StatefulSet,
    DaemonSet,
    CronJob,
    Job,
    ReplicaSet,
    ReplicationController,
}

impl WorkloadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkloadKind::Deployment => "Deployment",
            WorkloadKind::StatefulSet => "StatefulSet",
            WorkloadKind::DaemonSet => "DaemonSet",
            WorkloadKind::CronJob => "CronJob",
            WorkloadKind::Job => "Job",
            WorkloadKind::ReplicaSet => "ReplicaSet",
            WorkloadKind::ReplicationController => "ReplicationController",
        }
    }
}

/// `status` of a `SeccompProfile`. Two writers: each controller
/// server-side-applies its own `nodes[name=<node>]` entry (field manager
/// `kguardian-controller/<node>`), and every controller applies the same
/// computed summary (everything else) under the shared manager
/// `kguardian-summary`, so the summary converges to the last writer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SeccompProfileStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// FNV-1a-64 (hex) of the rendered file — what is on a ready node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// The `localhostProfile` value pods reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub localhost_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution: Option<Distribution>,
    /// Mirror of the `Drift` condition's status (`True`/`False`/`Unknown`)
    /// for the printer column — CRD printer columns take simple JSON
    /// paths only, no `[?(@.type=="Drift")]` filters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<String>,
    /// Per-node state; each entry is owned by that node's controller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(extend("x-kubernetes-list-type" = "map", "x-kubernetes-list-map-keys" = ["name"]))]
    pub nodes: Vec<NodeStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(extend("x-kubernetes-list-type" = "map", "x-kubernetes-list-map-keys" = ["type"]))]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Distribution {
    pub ready: u32,
    pub total: u32,
    pub state: DistributionState,
    /// `ready/total`, for the `Ready` printer column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum DistributionState {
    Ready,
    Partial,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    pub name: String,
    pub hash: String,
    /// RFC 3339; when this node last wrote the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_written: Option<String>,
}

/// A `metav1.Condition`-shaped condition (`type`, `status`, `reason`,
/// `message`, `lastTransitionTime`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    /// `"True"`, `"False"` or `"Unknown"`.
    pub status: String,
    pub reason: String,
    #[serde(default)]
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
}

/// The file written to a node. Exactly the standard seccomp JSON the
/// kubelet loads; field order is the struct order so the bytes are
/// stable across nodes and controller versions.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RenderedProfile {
    pub default_action: DefaultAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<Architecture>>,
    pub syscalls: Vec<RenderedRule>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RenderedRule {
    pub names: Vec<String>,
    pub action: RuleAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno_ret: Option<u32>,
}

/// Render the node file from a spec. Deterministic: names inside each
/// rule are sorted and de-duplicated, rules keep their spec order (a
/// later rule for the same name is the user's business), architectures
/// are de-duplicated and sorted, and the output is pretty-printed JSON
/// with a trailing newline. Same spec ⇒ same bytes ⇒ same hash on every
/// node.
pub fn render_profile(spec: &SeccompProfileSpec) -> Vec<u8> {
    let architectures = spec.architectures.as_ref().map(|a| {
        let mut a: Vec<Architecture> = a.clone();
        a.sort_by_key(|x| serde_json::to_string(x).unwrap_or_default());
        a.dedup();
        a
    });
    let syscalls = spec
        .syscalls
        .iter()
        .map(|r| {
            let names: BTreeSet<&str> = r.names.iter().map(|n| n.0.as_str()).collect();
            RenderedRule {
                names: names.into_iter().map(str::to_string).collect(),
                action: r.action,
                errno_ret: r.errno_ret,
            }
        })
        .collect();
    let rendered = RenderedProfile {
        default_action: spec.default_action,
        architectures,
        syscalls,
    };
    let mut out = serde_json::to_vec_pretty(&rendered).expect("rendered profile serialises");
    out.push(b'\n');
    out
}

/// FNV-1a-64 of `bytes`, as 16 lowercase hex chars. Cheap, dependency
/// free, and identical on every node — it only has to detect a change,
/// not resist an adversary.
pub fn fingerprint(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// `kguardian/<namespace>/<name>.json` — the `localhostProfile` value and
/// the path under the seccomp root.
pub fn localhost_profile_path(namespace: &str, name: &str) -> String {
    format!("kguardian/{namespace}/{name}.json")
}

/// The sorted-unique set of names across the spec's `SCMP_ACT_ALLOW`
/// rules — what the workload is allowed to call.
pub fn allowed_names(spec: &SeccompProfileSpec) -> BTreeSet<String> {
    spec.syscalls
        .iter()
        .filter(|r| r.action == RuleAction::Allow)
        .flat_map(|r| r.names.iter().map(|n| n.0.clone()))
        .collect()
}

/// Generate the CRD as YAML. This is what gets committed to
/// `charts/kguardian/files/kguardian.dev_seccompprofiles.yaml`.
pub fn crd_yaml() -> String {
    use kube::CustomResourceExt;
    serde_norway::to_string(&SeccompProfile::crd()).expect("CRD serialises to YAML")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec(names: &[&str]) -> SeccompProfileSpec {
        SeccompProfileSpec {
            default_action: DefaultAction::Log,
            architectures: Some(vec![Architecture::Arm64, Architecture::X8664]),
            syscalls: vec![SyscallRule {
                names: names.iter().map(|n| SyscallName(n.to_string())).collect(),
                action: RuleAction::Allow,
                errno_ret: None,
            }],
            workload_ref: Some(WorkloadRef {
                kind: WorkloadKind::Deployment,
                name: "web".into(),
            }),
        }
    }

    #[test]
    fn render_is_deterministic_and_sorts_names() {
        let a = render_profile(&spec(&["write", "read", "accept4", "read"]));
        let b = render_profile(&spec(&["accept4", "read", "write"]));
        assert_eq!(a, b, "order and duplicates must not change the bytes");
        assert_eq!(fingerprint(&a), fingerprint(&b));
        let text = String::from_utf8(a).unwrap();
        assert!(text.ends_with('\n'));
        // Architectures are sorted too.
        let arm = text.find("SCMP_ARCH_ARM64").unwrap();
        let x86 = text.find("SCMP_ARCH_X86_64").unwrap();
        assert!(arm < x86);
    }

    #[test]
    fn render_matches_the_standard_seccomp_shape() {
        // Same field names and nesting as advisor/pkg/k8s.SeccompProfile
        // and broker/src/seccomp.rs SeccompProfile: {defaultAction,
        // architectures, syscalls:[{names, action}]}. errnoRet only when
        // set; architectures only when given.
        let bytes = render_profile(&spec(&["read"]));
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "defaultAction": "SCMP_ACT_LOG",
                "architectures": ["SCMP_ARCH_ARM64", "SCMP_ARCH_X86_64"],
                "syscalls": [ { "names": ["read"], "action": "SCMP_ACT_ALLOW" } ]
            })
        );
        // Field order in the bytes is the struct order (serde_json's
        // Value re-sorts keys, so check the text).
        let text = String::from_utf8(bytes).unwrap();
        let pos = |k: &str| text.find(k).unwrap();
        assert!(pos("defaultAction") < pos("architectures"));
        assert!(pos("architectures") < pos("syscalls"));

        let mut s = spec(&["read"]);
        s.architectures = None;
        s.syscalls.push(SyscallRule {
            names: vec![SyscallName("ptrace".into())],
            action: RuleAction::Errno,
            errno_ret: Some(1),
        });
        let v: serde_json::Value = serde_json::from_slice(&render_profile(&s)).unwrap();
        assert!(v.get("architectures").is_none());
        assert_eq!(v["syscalls"][1]["errnoRet"], 1);
        assert_eq!(v["syscalls"][1]["action"], "SCMP_ACT_ERRNO");
    }

    #[test]
    fn fingerprint_is_stable_and_sensitive() {
        assert_eq!(fingerprint(b""), "cbf29ce484222325");
        assert_eq!(fingerprint(b"a"), "af63dc4c8601ec8c");
        assert_ne!(fingerprint(b"a"), fingerprint(b"b"));
        assert_eq!(fingerprint(b"hello").len(), 16);
    }

    #[test]
    fn allowed_names_only_counts_allow_rules() {
        let mut s = spec(&["read", "write"]);
        s.syscalls.push(SyscallRule {
            names: vec![SyscallName("ptrace".into())],
            action: RuleAction::Errno,
            errno_ret: None,
        });
        assert_eq!(
            allowed_names(&s),
            BTreeSet::from(["read".to_string(), "write".to_string()])
        );
    }

    #[test]
    fn spec_round_trips_through_the_documented_yaml() {
        let yaml = r#"
defaultAction: SCMP_ACT_LOG
architectures: [SCMP_ARCH_X86_64, SCMP_ARCH_ARM64]
syscalls:
  - names: [accept4, read, write]
    action: SCMP_ACT_ALLOW
workloadRef:
  kind: Deployment
  name: web
"#;
        let s: SeccompProfileSpec = serde_norway::from_str(yaml).unwrap();
        assert_eq!(s.default_action, DefaultAction::Log);
        assert_eq!(
            s.workload_ref.as_ref().unwrap().kind,
            WorkloadKind::Deployment
        );
        assert_eq!(s.syscalls[0].names.len(), 3);
        // Unknown action is rejected.
        assert!(serde_norway::from_str::<SeccompProfileSpec>(
            "defaultAction: SCMP_ACT_TRACE\nsyscalls: [{names: [read], action: SCMP_ACT_ALLOW}]"
        )
        .is_err());
    }

    #[test]
    fn crd_yaml_has_the_contract_surface() {
        let y = crd_yaml();
        for needle in [
            "name: seccompprofiles.kguardian.dev",
            "group: kguardian.dev",
            "kind: SeccompProfile",
            "scope: Namespaced",
            "name: v1alpha1",
            "status: {}", // subresource enabled
            "- SCMP_ACT_KILL_PROCESS",
            "pattern: ^[a-z][a-z0-9_]{0,63}$",
            "minItems: 1",
            "x-kubernetes-list-type: map",
            "- name",
            "- type",
            "name: Action",
            "name: Ready",
            "name: Drift",
            "name: Age",
            "- scmp",
        ] {
            assert!(y.contains(needle), "CRD YAML is missing {needle:?}\n{y}");
        }
    }

    /// The committed CRD must be exactly what this type generates. To
    /// refresh it after changing the type:
    ///   KGUARDIAN_WRITE_CRD=1 cargo test crd_yaml_committed
    #[test]
    fn crd_yaml_committed_matches_generated() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../charts/kguardian/files/kguardian.dev_seccompprofiles.yaml");
        let generated = format!(
            "# Generated from controller/src/seccomp_crd.rs — do not edit.\n\
             # Refresh with: cd controller && KGUARDIAN_WRITE_CRD=1 cargo test crd_yaml_committed\n{}",
            crd_yaml()
        );
        if std::env::var_os("KGUARDIAN_WRITE_CRD").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &generated).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{} is missing ({e}); run KGUARDIAN_WRITE_CRD=1 cargo test crd_yaml_committed",
                path.display()
            )
        });
        assert_eq!(
            committed,
            generated,
            "{} is stale; run KGUARDIAN_WRITE_CRD=1 cargo test crd_yaml_committed",
            path.display()
        );
    }
}
