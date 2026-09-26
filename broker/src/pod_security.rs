//! Pod Security Standards analyser for the workload security profile
//! (#1533 P0-4).
//!
//! Pure: no database. Input is what the image inventory stores per
//! workload container (`workload_containers.security_context` /
//! `pod_security`, see `image_inventory.rs`); output is the PSS level
//! with the failing checks per container, posture findings, and a
//! minimal securityContext patch recommendation.
//!
//! # Source of the rules
//!
//! The check list follows the upstream Pod Security Standards exactly:
//! <https://kubernetes.io/docs/concepts/security/pod-security-standards/>,
//! as published from kubernetes/website `main` @ `2c1aa11c` (2026-08-02,
//! the Kubernetes v1.37 docs). [`PSS_VERSION`] carries that citation into
//! every response. The check ids below are the upstream control names.
//!
//! # What cannot be evaluated
//!
//! The controller ingests securityContext subsets, host namespaces and
//! service-account automount only. Volumes, container ports, probes,
//! AppArmor, SELinux, procMount, sysctls and Windows options are not
//! ingested, so nine of the eighteen checks are reported as unevaluated
//! ([`UNEVALUATED`]) and never as passing. A level is therefore an
//! upper bound unless a baseline check fails (then it is `privileged`,
//! which is the floor and certain). hostPath in particular is NOT
//! available and is never inferred.
//!
//! Linux is assumed (the controller runs on Linux/containerd). The
//! user-namespace relaxation of runAsNonRoot/runAsUser is behind an
//! alpha feature gate upstream and is not applied.

use crate::image_inventory::{ContainerSecurity, PodSecurity};
use serde::Serialize;
use std::collections::BTreeSet;

pub const PSS_VERSION: &str = "kubernetes/website@2c1aa11c (Kubernetes v1.37 docs)";

/// Every PSS control in upstream order, with its level.
pub const ALL_CHECKS: [(&str, Level); 18] = [
    ("hostProcess", Level::Baseline),
    ("hostNamespaces", Level::Baseline),
    ("privileged", Level::Baseline),
    ("capabilitiesBaseline", Level::Baseline),
    ("hostPathVolumes", Level::Baseline),
    ("hostPorts", Level::Baseline),
    ("hostProbesLifecycle", Level::Baseline),
    ("appArmor", Level::Baseline),
    ("seLinux", Level::Baseline),
    ("procMount", Level::Baseline),
    ("seccompBaseline", Level::Baseline),
    ("sysctls", Level::Baseline),
    ("volumeTypes", Level::Restricted),
    ("privilegeEscalation", Level::Restricted),
    ("runAsNonRoot", Level::Restricted),
    ("runAsUser", Level::Restricted),
    ("seccompRestricted", Level::Restricted),
    ("capabilitiesRestricted", Level::Restricted),
];

/// Checks whose fields the inventory does not carry.
pub const UNEVALUATED: [&str; 9] = [
    "hostProcess",
    "hostPathVolumes",
    "hostPorts",
    "hostProbesLifecycle",
    "appArmor",
    "seLinux",
    "procMount",
    "sysctls",
    "volumeTypes",
];

/// Baseline "Capabilities" allowed additions (upstream list).
pub const BASELINE_ALLOWED_CAPS: [&str; 13] = [
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "MKNOD",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
];

/// Seccomp types restricted accepts (baseline only forbids Unconfined).
const SECCOMP_OK: [&str; 2] = ["RuntimeDefault", "Localhost"];

/// PSS levels, ordered least to most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Privileged,
    Baseline,
    Restricted,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Privileged => "privileged",
            Level::Baseline => "baseline",
            Level::Restricted => "restricted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailingCheck {
    pub check: &'static str,
    pub level: Level,
    pub field: String,
    pub value: serde_json::Value,
    pub message: String,
}

/// Container securityContext as reported, every field present (null =
/// not set in the spec), per the contract's no-omitted-fields rule.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityContextView {
    pub privileged: Option<bool>,
    pub allow_privilege_escalation: Option<bool>,
    pub run_as_non_root: Option<bool>,
    pub run_as_user: Option<i64>,
    pub run_as_group: Option<i64>,
    pub read_only_root_filesystem: Option<bool>,
    pub capabilities_add: Option<Vec<String>>,
    pub capabilities_drop: Option<Vec<String>>,
    pub seccomp_profile_type: Option<String>,
}

impl From<&ContainerSecurity> for SecurityContextView {
    fn from(c: &ContainerSecurity) -> Self {
        SecurityContextView {
            privileged: c.privileged,
            allow_privilege_escalation: c.allow_privilege_escalation,
            run_as_non_root: c.run_as_non_root,
            run_as_user: c.run_as_user,
            run_as_group: c.run_as_group,
            read_only_root_filesystem: c.read_only_root_filesystem,
            capabilities_add: c.capabilities_add.clone(),
            capabilities_drop: c.capabilities_drop.clone(),
            seccomp_profile_type: c.seccomp_profile_type.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurityContextView {
    pub run_as_non_root: Option<bool>,
    pub run_as_user: Option<i64>,
    pub run_as_group: Option<i64>,
    pub fs_group: Option<i64>,
    pub seccomp_profile_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PodView {
    /// False when the pod-level block was missing or malformed in the
    /// inventory (older controller): every field below is then null and
    /// the checks that need it are listed in `unevaluatedChecks`.
    pub known: bool,
    pub service_account_name: Option<String>,
    pub automount_service_account_token: Option<bool>,
    pub host_network: Option<bool>,
    #[serde(rename = "hostPID")]
    pub host_pid: Option<bool>,
    #[serde(rename = "hostIPC")]
    pub host_ipc: Option<bool>,
    pub host_users: Option<bool>,
    pub security_context: PodSecurityContextView,
    /// Pod-level checks that fail (host namespaces, pod-level
    /// runAsNonRoot=false / runAsUser=0 / seccomp Unconfined).
    pub failing: Vec<FailingCheck>,
}

/// One container as input to the analyser.
#[derive(Debug, Clone)]
pub struct ContainerInput {
    pub name: String,
    /// `init | regular | ephemeral`.
    pub kind: String,
    /// `running | last_known` (a current container not running now, e.g.
    /// a completed init container).
    pub source: &'static str,
    pub digest: String,
    pub security: ContainerSecurity,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerResult {
    pub name: String,
    pub kind: String,
    pub source: &'static str,
    pub digest: String,
    pub security_context: SecurityContextView,
    pub level: Level,
    pub failing: Vec<FailingCheck>,
}

/// A posture finding; `container` is null for pod-level findings.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub severity: &'static str,
    pub title: String,
    pub detail: String,
    pub container: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recommendation {
    pub recommendation: bool,
    pub target_level: &'static str,
    pub format: &'static str,
    pub yaml: String,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    pub pss_version: &'static str,
    /// `None` when there are no containers to evaluate.
    pub level: Option<Level>,
    /// `confirmed` (only possible for `privileged`) or `upper_bound`;
    /// `None` alongside `level: None`.
    pub level_confidence: Option<&'static str>,
    pub unevaluated_checks: Vec<&'static str>,
    pub pod: PodView,
    pub containers: Vec<ContainerResult>,
    pub recommendation: Option<Recommendation>,
    #[serde(skip)]
    pub findings: Vec<Finding>,
}

fn field_path(kind: &str, name: &str, leaf: &str) -> String {
    let list = match kind {
        "init" => "initContainers",
        "ephemeral" => "ephemeralContainers",
        _ => "containers",
    };
    format!("spec.{list}[{name}].securityContext.{leaf}")
}

fn fail(
    check: &'static str,
    level: Level,
    field: String,
    value: serde_json::Value,
    message: &str,
) -> FailingCheck {
    FailingCheck {
        check,
        level,
        field,
        value,
        message: message.to_string(),
    }
}

fn json<T: Serialize>(v: &T) -> serde_json::Value {
    serde_json::to_value(v).unwrap_or(serde_json::Value::Null)
}

/// Pod-level checks.
pub fn check_pod(pod: &PodSecurity) -> Vec<FailingCheck> {
    let mut out = Vec::new();
    for (field, v) in [
        ("hostNetwork", pod.host_network),
        ("hostPID", pod.host_pid),
        ("hostIPC", pod.host_ipc),
    ] {
        if v == Some(true) {
            out.push(fail(
                "hostNamespaces",
                Level::Baseline,
                format!("spec.{field}"),
                json(&v),
                &format!("{field} must be unset or false"),
            ));
        }
    }
    let sc = pod.security_context.clone().unwrap_or_default();
    if sc.seccomp_profile_type.as_deref() == Some("Unconfined") {
        out.push(fail(
            "seccompBaseline",
            Level::Baseline,
            "spec.securityContext.seccompProfile.type".into(),
            json(&sc.seccomp_profile_type),
            "seccompProfile.type must not be Unconfined",
        ));
    }
    if sc.run_as_non_root == Some(false) {
        out.push(fail(
            "runAsNonRoot",
            Level::Restricted,
            "spec.securityContext.runAsNonRoot".into(),
            json(&sc.run_as_non_root),
            "runAsNonRoot must be true",
        ));
    }
    if sc.run_as_user == Some(0) {
        out.push(fail(
            "runAsUser",
            Level::Restricted,
            "spec.securityContext.runAsUser".into(),
            json(&sc.run_as_user),
            "runAsUser must not be 0",
        ));
    }
    out
}

/// Container-level checks, with the pod-level fields a container
/// inherits (runAsNonRoot, seccompProfile) applied per upstream.
///
/// `pod_known = false` (no usable pod-level block): a check that the
/// container leaves to the pod (runAsNonRoot, seccompProfile) cannot be
/// decided and is skipped, never failed or passed.
pub fn check_container(
    kind: &str,
    name: &str,
    c: &ContainerSecurity,
    pod: &PodSecurity,
    pod_known: bool,
) -> Vec<FailingCheck> {
    let psc = pod.security_context.clone().unwrap_or_default();
    let p = |leaf: &str| field_path(kind, name, leaf);
    let mut out = Vec::new();

    // Baseline: Privileged Containers.
    if c.privileged == Some(true) {
        out.push(fail(
            "privileged",
            Level::Baseline,
            p("privileged"),
            json(&c.privileged),
            "privileged must be unset or false",
        ));
    }
    // Baseline: Capabilities.
    let add = c.capabilities_add.clone().unwrap_or_default();
    let beyond: Vec<&String> = add
        .iter()
        .filter(|a| !BASELINE_ALLOWED_CAPS.contains(&a.as_str()))
        .collect();
    if !beyond.is_empty() {
        out.push(fail(
            "capabilitiesBaseline",
            Level::Baseline,
            p("capabilities.add"),
            json(&c.capabilities_add),
            &format!(
                "capabilities.add may only contain the baseline set; not allowed: {}",
                beyond
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    // Baseline: Seccomp (container field).
    if c.seccomp_profile_type.as_deref() == Some("Unconfined") {
        out.push(fail(
            "seccompBaseline",
            Level::Baseline,
            p("seccompProfile.type"),
            json(&c.seccomp_profile_type),
            "seccompProfile.type must not be Unconfined",
        ));
    }
    // Restricted: Privilege Escalation — must be explicitly false.
    if c.allow_privilege_escalation != Some(false) {
        out.push(fail(
            "privilegeEscalation",
            Level::Restricted,
            p("allowPrivilegeEscalation"),
            json(&c.allow_privilege_escalation),
            "allowPrivilegeEscalation must be set to false",
        ));
    }
    // Restricted: Running as Non-root. The container may leave it unset
    // only when the pod sets it true; an explicit false always fails.
    let non_root_ok = match c.run_as_non_root {
        Some(v) => Some(v),
        None if pod_known => Some(psc.run_as_non_root == Some(true)),
        None => None,
    };
    if non_root_ok == Some(false) {
        out.push(fail(
            "runAsNonRoot",
            Level::Restricted,
            p("runAsNonRoot"),
            json(&c.run_as_non_root),
            "runAsNonRoot must be true (on the container, or on the pod with the container unset)",
        ));
    }
    // Restricted: Running as Non-root user.
    if c.run_as_user == Some(0) {
        out.push(fail(
            "runAsUser",
            Level::Restricted,
            p("runAsUser"),
            json(&c.run_as_user),
            "runAsUser must not be 0",
        ));
    }
    // Restricted: Seccomp — the effective type (container, else pod)
    // must be RuntimeDefault or Localhost. An Unconfined container is
    // already a baseline failure above; it fails here too, as upstream.
    let effective = c
        .seccomp_profile_type
        .as_deref()
        .or(psc.seccomp_profile_type.as_deref());
    let decidable = pod_known || c.seccomp_profile_type.is_some();
    if decidable && !effective.is_some_and(|t| SECCOMP_OK.contains(&t)) {
        out.push(fail(
            "seccompRestricted",
            Level::Restricted,
            p("seccompProfile.type"),
            json(&effective),
            "seccompProfile.type must be RuntimeDefault or Localhost (on the container, or on the pod)",
        ));
    }
    // Restricted: Capabilities — drop ALL, add only NET_BIND_SERVICE.
    let drops_all = c
        .capabilities_drop
        .as_ref()
        .is_some_and(|d| d.iter().any(|x| x == "ALL"));
    if !drops_all {
        out.push(fail(
            "capabilitiesRestricted",
            Level::Restricted,
            p("capabilities.drop"),
            json(&c.capabilities_drop),
            "capabilities.drop must include ALL",
        ));
    }
    let extra_add: Vec<&String> = add.iter().filter(|a| *a != "NET_BIND_SERVICE").collect();
    if !extra_add.is_empty() {
        out.push(fail(
            "capabilitiesRestricted",
            Level::Restricted,
            p("capabilities.add"),
            json(&c.capabilities_add),
            "capabilities.add may only contain NET_BIND_SERVICE",
        ));
    }
    out
}

/// The level a set of failing checks allows.
pub fn level_of(failing: &[FailingCheck]) -> Level {
    if failing.iter().any(|f| f.level == Level::Baseline) {
        Level::Privileged
    } else if failing.iter().any(|f| f.level == Level::Restricted) {
        Level::Baseline
    } else {
        Level::Restricted
    }
}

fn finding(
    id: String,
    severity: &'static str,
    container: Option<&str>,
    title: String,
    detail: String,
) -> Finding {
    Finding {
        id,
        severity,
        title,
        detail,
        container: container.map(str::to_string),
    }
}

/// Posture findings (a superset of PSS failures: also readOnlyRootFilesystem
/// and service-account token automount, which PSS does not cover).
pub fn findings(pod: &PodSecurity, pod_known: bool, containers: &[ContainerInput]) -> Vec<Finding> {
    let mut out = Vec::new();
    let psc = pod.security_context.clone().unwrap_or_default();
    // With no usable pod-level block, pod-level findings are unknown, not
    // "unset", so none are emitted.
    let pod_fields: [(&str, Option<bool>); 3] = if pod_known {
        [
            ("hostNetwork", pod.host_network),
            ("hostPID", pod.host_pid),
            ("hostIPC", pod.host_ipc),
        ]
    } else {
        [("hostNetwork", None), ("hostPID", None), ("hostIPC", None)]
    };
    for (code, v) in pod_fields {
        if v == Some(true) {
            out.push(finding(
                format!("podSecurity.{code}"),
                "high",
                None,
                format!(
                    "Pod shares the node's {} namespace ({code}: true)",
                    &code[4..]
                ),
                format!("{code}: true gives the pod the node's namespace; baseline forbids it."),
            ));
        }
    }
    if psc.seccomp_profile_type.as_deref() == Some("Unconfined") {
        out.push(finding(
            "podSecurity.seccompUnconfined".into(),
            "high",
            None,
            "Pod seccomp profile is Unconfined".into(),
            "spec.securityContext.seccompProfile.type: Unconfined disables syscall filtering for every container that does not override it.".into(),
        ));
    }
    if pod_known && pod.automount_service_account_token != Some(false) {
        out.push(finding(
            "podSecurity.automountToken".into(),
            "low",
            None,
            "Service account token is mounted".into(),
            "automountServiceAccountToken is not false on the pod. The ServiceAccount's own setting is not visible to kguardian, so the token is assumed mounted; set it false if the app does not call the Kubernetes API.".into(),
        ));
    }
    for c in containers {
        let s = &c.security;
        let n = c.name.as_str();
        if s.privileged == Some(true) {
            out.push(finding(
                format!("podSecurity.privileged/{n}"),
                "high",
                Some(n),
                format!("Container {n} is privileged"),
                "privileged: true gives the container every capability and access to host devices."
                    .into(),
            ));
        }
        let add = s.capabilities_add.clone().unwrap_or_default();
        let beyond: Vec<&str> = add
            .iter()
            .map(String::as_str)
            .filter(|a| !BASELINE_ALLOWED_CAPS.contains(a))
            .collect();
        let within: Vec<&str> = add
            .iter()
            .map(String::as_str)
            .filter(|a| BASELINE_ALLOWED_CAPS.contains(a) && *a != "NET_BIND_SERVICE")
            .collect();
        if !beyond.is_empty() {
            out.push(finding(
                format!("podSecurity.capabilitiesAdded/{n}"),
                "high",
                Some(n),
                format!("Container {n} adds capabilities: {}", beyond.join(", ")),
                "These capabilities are outside the baseline set.".into(),
            ));
        } else if !within.is_empty() {
            out.push(finding(
                format!("podSecurity.capabilitiesAdded/{n}"),
                "low",
                Some(n),
                format!("Container {n} adds capabilities: {}", within.join(", ")),
                "Allowed by baseline but not by restricted.".into(),
            ));
        }
        if s.allow_privilege_escalation != Some(false) {
            out.push(finding(
                format!("podSecurity.allowPrivilegeEscalation/{n}"),
                "medium",
                Some(n),
                format!("Container {n} allows privilege escalation"),
                "allowPrivilegeEscalation is not set to false, so setuid binaries can gain privileges.".into(),
            ));
        }
        let uid = s.run_as_user.or(psc.run_as_user);
        let non_root = s.run_as_non_root.or(psc.run_as_non_root);
        if uid == Some(0) {
            out.push(finding(
                format!("podSecurity.runAsRoot/{n}"),
                "high",
                Some(n),
                format!("Container {n} runs as root (runAsUser: 0)"),
                "runAsUser is 0.".into(),
            ));
        } else if non_root != Some(true)
            && uid.is_none()
            && (pod_known || s.run_as_non_root.is_some())
        {
            out.push(finding(
                format!("podSecurity.mayRunAsRoot/{n}"),
                "medium",
                Some(n),
                format!("Container {n} may run as root"),
                "Neither runAsNonRoot: true nor a non-zero runAsUser is set, so the image's USER decides.".into(),
            ));
        }
        let eff_seccomp = s
            .seccomp_profile_type
            .as_deref()
            .or(psc.seccomp_profile_type.as_deref());
        if s.seccomp_profile_type.as_deref() == Some("Unconfined") {
            out.push(finding(
                format!("podSecurity.seccompUnconfined/{n}"),
                "high",
                Some(n),
                format!("Container {n} seccomp profile is Unconfined"),
                "Syscall filtering is disabled for this container.".into(),
            ));
        } else if eff_seccomp.is_none() && pod_known {
            out.push(finding(
                format!("podSecurity.seccompUnset/{n}"),
                "medium",
                Some(n),
                format!("Container {n} has no seccomp profile set"),
                "Without seccompProfile the container runtime's default applies only if the kubelet enables it; restricted requires RuntimeDefault or Localhost.".into(),
            ));
        }
        let drops_all = s
            .capabilities_drop
            .as_ref()
            .is_some_and(|d| d.iter().any(|x| x == "ALL"));
        if !drops_all {
            out.push(finding(
                format!("podSecurity.capabilitiesNotDropped/{n}"),
                "medium",
                Some(n),
                format!("Container {n} does not drop ALL capabilities"),
                "The runtime's default capability set stays granted.".into(),
            ));
        }
        if s.read_only_root_filesystem != Some(true) {
            out.push(finding(
                format!("podSecurity.readOnlyRootFilesystem/{n}"),
                "low",
                Some(n),
                format!("Container {n} root filesystem is writable"),
                "readOnlyRootFilesystem is not true (hardening; not required by PSS restricted)."
                    .into(),
            ));
        }
    }
    out
}

/// Pod template path for a workload kind.
fn template_indent(kind: &str) -> (Vec<&'static str>, usize) {
    match kind {
        "Pod" => (vec!["spec:"], 1),
        "CronJob" => (
            vec![
                "spec:",
                "  jobTemplate:",
                "    spec:",
                "      template:",
                "        spec:",
            ],
            5,
        ),
        _ => (vec!["spec:", "  template:", "    spec:"], 3),
    }
}

/// Minimal strategic-merge patch reaching `restricted` for the evaluated
/// checks. `None` when nothing evaluated fails restricted.
pub fn recommend(
    workload_kind: &str,
    pod: &PodSecurity,
    pod_known: bool,
    containers: &[ContainerInput],
    pod_failing: &[FailingCheck],
    per_container: &[Vec<FailingCheck>],
) -> Option<Recommendation> {
    let any_fail = !pod_failing.is_empty() || per_container.iter().any(|f| !f.is_empty());
    if !any_fail {
        return None;
    }
    let psc = pod.security_context.clone().unwrap_or_default();
    let has = |f: &[FailingCheck], c: &str| f.iter().any(|x| x.check == c);
    let (head, depth) = template_indent(workload_kind);
    let ind = |n: usize| "  ".repeat(n);
    let mut lines: Vec<String> = vec![
        "# kguardian recommendation, not applied. Review before use.".into(),
        "# Target: Pod Security Standards restricted (kubernetes.io/docs/concepts/security/pod-security-standards)".into(),
    ];
    lines.extend(head.iter().map(|s| s.to_string()));
    let header_len = lines.len();
    let d = depth;

    // Pod-level fields.
    let mut pod_lines: Vec<String> = Vec::new();
    for (field, v) in [
        ("hostNetwork", pod.host_network),
        ("hostPID", pod.host_pid),
        ("hostIPC", pod.host_ipc),
    ] {
        if v == Some(true) {
            pod_lines.push(format!("{}{field}: false", ind(d)));
        }
    }
    let patchable: Vec<(usize, &ContainerInput)> = containers
        .iter()
        .enumerate()
        .filter(|(_, c)| c.kind != "ephemeral")
        .collect();
    let any_c = |check: &str| {
        patchable
            .iter()
            .any(|(i, _)| has(&per_container[*i], check))
    };
    let mut psc_lines: Vec<String> = Vec::new();
    let pod_sets_non_root = psc.run_as_non_root != Some(false) && any_c("runAsNonRoot");
    if pod_sets_non_root || psc.run_as_non_root == Some(false) {
        psc_lines.push(format!("{}runAsNonRoot: true", ind(d + 1)));
    }
    if psc.run_as_user == Some(0) {
        psc_lines.push(format!(
            "{}runAsUser: null  # was 0: remove it, or set a non-zero UID the image supports",
            ind(d + 1)
        ));
    }
    let pod_seccomp_bad = !psc
        .seccomp_profile_type
        .as_deref()
        .is_some_and(|t| SECCOMP_OK.contains(&t));
    if pod_seccomp_bad && (any_c("seccompRestricted") || has(pod_failing, "seccompBaseline")) {
        psc_lines.push(format!("{}seccompProfile:", ind(d + 1)));
        psc_lines.push(format!("{}type: RuntimeDefault", ind(d + 2)));
    }
    if !psc_lines.is_empty() {
        pod_lines.push(format!("{}securityContext:", ind(d)));
        pod_lines.extend(psc_lines);
    }
    // No pod-level lines from a pod block kguardian could not read.
    if pod_known {
        lines.extend(pod_lines);
    }

    // Containers, grouped by list.
    for (list, kind) in [("initContainers", "init"), ("containers", "regular")] {
        let mut block: Vec<String> = Vec::new();
        for (i, c) in patchable.iter().filter(|(_, c)| c.kind == kind) {
            let f = &per_container[*i];
            let s = &c.security;
            let mut sc: Vec<String> = Vec::new();
            let e = ind(d + 2);
            if s.privileged == Some(true) {
                sc.push(format!("{e}privileged: false"));
            }
            if has(f, "privilegeEscalation") {
                sc.push(format!("{e}allowPrivilegeEscalation: false"));
            }
            if s.run_as_non_root == Some(false) {
                sc.push(format!("{e}runAsNonRoot: true"));
            }
            if s.run_as_user == Some(0) {
                sc.push(format!(
                    "{e}runAsUser: null  # was 0: remove it, or set a non-zero UID the image supports"
                ));
            }
            if s.seccomp_profile_type.as_deref() == Some("Unconfined") {
                sc.push(format!("{e}seccompProfile:"));
                sc.push(format!("{e}  type: RuntimeDefault"));
            }
            let add = s.capabilities_add.clone().unwrap_or_default();
            let bad_add = add.iter().any(|a| a != "NET_BIND_SERVICE");
            let drop_missing = !s
                .capabilities_drop
                .as_ref()
                .is_some_and(|d| d.iter().any(|x| x == "ALL"));
            if bad_add || drop_missing {
                sc.push(format!("{e}capabilities:"));
                if drop_missing {
                    sc.push(format!("{e}  drop: [\"ALL\"]"));
                }
                if bad_add {
                    if add.iter().any(|a| a == "NET_BIND_SERVICE") {
                        sc.push(format!("{e}  add: [\"NET_BIND_SERVICE\"]"));
                    } else {
                        sc.push(format!(
                            "{e}  add: null  # was {}; restricted allows only NET_BIND_SERVICE",
                            add.join(", ")
                        ));
                    }
                }
            }
            if !sc.is_empty() {
                block.push(format!("{}- name: {}", ind(d), c.name));
                block.push(format!("{}securityContext:", ind(d + 1)));
                block.extend(sc);
            }
        }
        if !block.is_empty() {
            lines.push(format!("{}{list}:", ind(d)));
            lines.extend(block);
        }
    }

    // Nothing patchable (e.g. only an ephemeral container fails): no patch
    // at all. A bare "spec: template: spec:" would be a null template,
    // which strategic merge reads as a deletion.
    if lines.len() == header_len {
        return None;
    }
    let body = lines[header_len..].join("\n");
    let mut caveats = vec![
        "Checks kguardian cannot see (hostPath and other volume types, hostPort, probe hosts, AppArmor, SELinux, procMount, sysctls) may still fail restricted.".to_string(),
    ];
    if body.contains("runAsNonRoot: true") {
        caveats.push("runAsNonRoot: true fails at container start if the image's USER is root; set runAsUser to a UID the image supports.".into());
    }
    if workload_kind == "DaemonSet" || pod.host_network == Some(true) {
        caveats.push("This looks like a node agent (DaemonSet or hostNetwork). CNI plugins, CSI drivers and node agents usually need privileges restricted forbids; a namespace-level PSS exemption is often the right answer instead of this patch.".into());
    }
    if body.contains("privileged: false") {
        caveats.push("privileged: false removes host device and kernel access; workloads that manage the node (CNI, CSI, device plugins, eBPF agents) will break.".into());
    }
    if ["hostNetwork: false", "hostPID: false", "hostIPC: false"]
        .iter()
        .any(|x| body.contains(x))
    {
        caveats.push("Turning off hostNetwork/hostPID/hostIPC breaks components that need the node's namespaces (CNI, node exporters, service meshes' node proxies); hostNetwork: false also changes the pod's IP and port bindings.".into());
    }
    if body.contains("drop: [\"ALL\"]") {
        caveats.push("drop: [\"ALL\"] also removes CHOWN, SETUID, SETGID, DAC_OVERRIDE and NET_BIND_SERVICE. Images that start as root and drop privileges, change file ownership at startup, or bind ports below 1024 may fail; add back NET_BIND_SERVICE only if the app needs it.".into());
    }
    let eph: BTreeSet<&str> = containers
        .iter()
        .enumerate()
        .filter(|(i, c)| c.kind == "ephemeral" && !per_container[*i].is_empty())
        .map(|(_, c)| c.name.as_str())
        .collect();
    if !eph.is_empty() {
        caveats.push(format!(
            "Ephemeral containers cannot be patched and still fail restricted: {}",
            eph.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    let mut yaml = lines.join("\n");
    yaml.push('\n');
    Some(Recommendation {
        recommendation: true,
        target_level: "restricted",
        format: "strategic-merge-patch",
        yaml,
        caveats,
    })
}

/// Analyse one workload. `pod = None` means the pod-level block was
/// missing or malformed: pod-level checks become unevaluated.
pub fn analyse(
    workload_kind: &str,
    pod: Option<&PodSecurity>,
    containers: &[ContainerInput],
) -> Analysis {
    let pod_known = pod.is_some();
    let empty = PodSecurity::default();
    let pod = pod.unwrap_or(&empty);
    let pod_failing = if pod_known {
        check_pod(pod)
    } else {
        Vec::new()
    };
    let per: Vec<Vec<FailingCheck>> = containers
        .iter()
        .map(|c| check_container(&c.kind, &c.name, &c.security, pod, pod_known))
        .collect();
    let results: Vec<ContainerResult> = containers
        .iter()
        .zip(per.iter())
        .map(|(c, f)| ContainerResult {
            name: c.name.clone(),
            kind: c.kind.clone(),
            source: c.source,
            digest: c.digest.clone(),
            security_context: SecurityContextView::from(&c.security),
            level: level_of(f),
            failing: f.clone(),
        })
        .collect();
    let level = if containers.is_empty() {
        None
    } else {
        let pod_level = level_of(&pod_failing);
        Some(
            results
                .iter()
                .map(|r| r.level)
                .chain(std::iter::once(pod_level))
                .min()
                .unwrap_or(Level::Restricted),
        )
    };
    let level_confidence = level.map(|l| {
        if l == Level::Privileged {
            "confirmed"
        } else {
            "upper_bound"
        }
    });
    let mut unevaluated: Vec<&'static str> = UNEVALUATED.to_vec();
    if !pod_known && !containers.is_empty() {
        unevaluated.push("hostNamespaces");
        if containers
            .iter()
            .any(|c| c.security.run_as_non_root.is_none())
        {
            unevaluated.push("runAsNonRoot");
        }
        if containers
            .iter()
            .any(|c| c.security.seccomp_profile_type.is_none())
        {
            unevaluated.push("seccompRestricted");
        }
    }
    let psc = pod.security_context.clone().unwrap_or_default();
    let recommendation = if containers.is_empty() {
        None
    } else {
        recommend(
            workload_kind,
            pod,
            pod_known,
            containers,
            &pod_failing,
            &per,
        )
    };
    Analysis {
        pss_version: PSS_VERSION,
        level,
        level_confidence,
        unevaluated_checks: unevaluated,
        pod: PodView {
            known: pod_known,
            service_account_name: pod.service_account_name.clone(),
            automount_service_account_token: pod.automount_service_account_token,
            host_network: pod.host_network,
            host_pid: pod.host_pid,
            host_ipc: pod.host_ipc,
            host_users: pod.host_users,
            security_context: PodSecurityContextView {
                run_as_non_root: psc.run_as_non_root,
                run_as_user: psc.run_as_user,
                run_as_group: psc.run_as_group,
                fs_group: psc.fs_group,
                seccomp_profile_type: psc.seccomp_profile_type,
            },
            failing: pod_failing,
        },
        containers: results,
        recommendation,
        findings: if containers.is_empty() {
            Vec::new()
        } else {
            findings(pod, pod_known, containers)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_inventory::PodSecurityFields;

    fn restricted_sc() -> ContainerSecurity {
        ContainerSecurity {
            allow_privilege_escalation: Some(false),
            run_as_non_root: Some(true),
            capabilities_drop: Some(vec!["ALL".into()]),
            seccomp_profile_type: Some("RuntimeDefault".into()),
            read_only_root_filesystem: Some(true),
            ..Default::default()
        }
    }

    fn ids(f: &[FailingCheck]) -> Vec<&'static str> {
        f.iter().map(|x| x.check).collect()
    }

    fn one(sc: ContainerSecurity) -> Vec<&'static str> {
        ids(&check_container(
            "regular",
            "app",
            &sc,
            &PodSecurity::default(),
            true,
        ))
    }

    fn input(name: &str, kind: &str, sc: ContainerSecurity) -> ContainerInput {
        ContainerInput {
            name: name.into(),
            kind: kind.into(),
            source: "running",
            digest: format!("sha256:{}", "a".repeat(64)),
            security: sc,
        }
    }

    #[test]
    fn check_table_is_the_upstream_list() {
        assert_eq!(ALL_CHECKS.len(), 18);
        assert_eq!(
            ALL_CHECKS
                .iter()
                .filter(|(_, l)| *l == Level::Baseline)
                .count(),
            12
        );
        for u in UNEVALUATED {
            assert!(ALL_CHECKS.iter().any(|(c, _)| *c == u), "{u}");
        }
        // hostPath is never evaluated: the inventory has no volumes.
        assert!(UNEVALUATED.contains(&"hostPathVolumes"));
    }

    #[test]
    fn a_fully_restricted_container_passes_every_evaluated_check() {
        assert!(one(restricted_sc()).is_empty());
    }

    // ---- one table test per evaluated check ------------------------------

    #[test]
    fn host_namespaces() {
        type Case = (Option<bool>, Option<bool>, Option<bool>, usize);
        let cases: [Case; 5] = [
            (None, None, None, 0),
            (Some(false), Some(false), Some(false), 0),
            (Some(true), None, None, 1),
            (None, Some(true), None, 1),
            (Some(true), Some(true), Some(true), 3),
        ];
        for (net, pid, ipc, want) in cases {
            let pod = PodSecurity {
                host_network: net,
                host_pid: pid,
                host_ipc: ipc,
                ..Default::default()
            };
            let f = check_pod(&pod);
            assert_eq!(
                f.iter().filter(|x| x.check == "hostNamespaces").count(),
                want,
                "{net:?} {pid:?} {ipc:?}"
            );
            assert!(f.iter().all(|x| x.level == Level::Baseline));
        }
    }

    #[test]
    fn privileged() {
        for (v, fails) in [(None, false), (Some(false), false), (Some(true), true)] {
            let sc = ContainerSecurity {
                privileged: v,
                ..restricted_sc()
            };
            assert_eq!(one(sc).contains(&"privileged"), fails, "{v:?}");
        }
    }

    #[test]
    fn capabilities_baseline() {
        let cases: [(&[&str], bool); 5] = [
            (&[], false),
            (&["NET_BIND_SERVICE"], false),
            (&["CHOWN", "KILL", "SYS_CHROOT"], false),
            (&["SYS_ADMIN"], true),
            (&["NET_RAW"], true),
        ];
        for (add, fails) in cases {
            let sc = ContainerSecurity {
                capabilities_add: (!add.is_empty())
                    .then(|| add.iter().map(|s| s.to_string()).collect()),
                ..restricted_sc()
            };
            assert_eq!(one(sc).contains(&"capabilitiesBaseline"), fails, "{add:?}");
        }
    }

    #[test]
    fn seccomp_baseline() {
        let cases = [
            (None, None, false),
            (Some("RuntimeDefault"), None, false),
            (Some("Localhost"), None, false),
            (Some("Unconfined"), None, true),
            (None, Some("Unconfined"), true),
        ];
        for (container, pod_t, fails) in cases {
            let sc = ContainerSecurity {
                seccomp_profile_type: container.map(String::from),
                ..restricted_sc()
            };
            let pod = PodSecurity {
                security_context: Some(PodSecurityFields {
                    seccomp_profile_type: pod_t.map(String::from),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let mut all = check_container("regular", "app", &sc, &pod, true);
            all.extend(check_pod(&pod));
            assert_eq!(
                ids(&all).contains(&"seccompBaseline"),
                fails,
                "{container:?} {pod_t:?}"
            );
        }
    }

    #[test]
    fn privilege_escalation_must_be_explicitly_false() {
        for (v, fails) in [(None, true), (Some(true), true), (Some(false), false)] {
            let sc = ContainerSecurity {
                allow_privilege_escalation: v,
                ..restricted_sc()
            };
            assert_eq!(one(sc).contains(&"privilegeEscalation"), fails, "{v:?}");
        }
    }

    #[test]
    fn run_as_non_root_container_or_pod() {
        // (container, pod, fails)
        let cases = [
            (Some(true), None, false),
            (None, Some(true), false),
            (None, None, true),
            (Some(false), Some(true), true),
            (None, Some(false), true),
            (Some(true), Some(false), false),
        ];
        for (c, p, fails) in cases {
            let sc = ContainerSecurity {
                run_as_non_root: c,
                ..restricted_sc()
            };
            let pod = PodSecurity {
                security_context: Some(PodSecurityFields {
                    run_as_non_root: p,
                    ..Default::default()
                }),
                ..Default::default()
            };
            let got = ids(&check_container("regular", "app", &sc, &pod, true));
            assert_eq!(got.contains(&"runAsNonRoot"), fails, "{c:?} {p:?}");
        }
        // Pod-level explicit false is itself a failing pod field.
        let pod = PodSecurity {
            security_context: Some(PodSecurityFields {
                run_as_non_root: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(ids(&check_pod(&pod)).contains(&"runAsNonRoot"));
    }

    #[test]
    fn run_as_user() {
        for (v, fails) in [(None, false), (Some(1000), false), (Some(0), true)] {
            let sc = ContainerSecurity {
                run_as_user: v,
                ..restricted_sc()
            };
            assert_eq!(one(sc).contains(&"runAsUser"), fails, "{v:?}");
        }
        let pod = PodSecurity {
            security_context: Some(PodSecurityFields {
                run_as_user: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(ids(&check_pod(&pod)).contains(&"runAsUser"));
    }

    #[test]
    fn seccomp_restricted_effective_type() {
        // (container, pod, fails)
        let cases = [
            (Some("RuntimeDefault"), None, false),
            (Some("Localhost"), None, false),
            (None, Some("RuntimeDefault"), false),
            (None, None, true),
            (Some("Unconfined"), Some("RuntimeDefault"), true),
            (None, Some("Unconfined"), true),
        ];
        for (c, p, fails) in cases {
            let sc = ContainerSecurity {
                seccomp_profile_type: c.map(String::from),
                ..restricted_sc()
            };
            let pod = PodSecurity {
                security_context: Some(PodSecurityFields {
                    seccomp_profile_type: p.map(String::from),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let got = ids(&check_container("regular", "app", &sc, &pod, true));
            assert_eq!(got.contains(&"seccompRestricted"), fails, "{c:?} {p:?}");
        }
    }

    #[test]
    fn capabilities_restricted() {
        // (drop, add, fails)
        type Case<'a> = (Option<&'a [&'a str]>, &'a [&'a str], bool);
        let cases: [Case; 6] = [
            (Some(&["ALL"]), &[], false),
            (Some(&["ALL"]), &["NET_BIND_SERVICE"], false),
            (None, &[], true),
            (Some(&["NET_RAW"]), &[], true),
            (Some(&["ALL"]), &["CHOWN"], true),
            (Some(&["ALL"]), &["SYS_ADMIN"], true),
        ];
        for (drop, add, fails) in cases {
            let sc = ContainerSecurity {
                capabilities_drop: drop.map(|d| d.iter().map(|s| s.to_string()).collect()),
                capabilities_add: (!add.is_empty())
                    .then(|| add.iter().map(|s| s.to_string()).collect()),
                ..restricted_sc()
            };
            assert_eq!(
                one(sc).contains(&"capabilitiesRestricted"),
                fails,
                "{drop:?} {add:?}"
            );
        }
    }

    // ---- levels ------------------------------------------------------------

    #[test]
    fn level_and_confidence() {
        let pod = PodSecurity::default();
        let a = analyse(
            "Deployment",
            Some(&pod),
            &[input("app", "regular", restricted_sc())],
        );
        assert_eq!(a.level, Some(Level::Restricted));
        assert_eq!(a.level_confidence, Some("upper_bound"));
        assert!(a.recommendation.is_none());

        let a = analyse(
            "Deployment",
            Some(&pod),
            &[input("app", "regular", ContainerSecurity::default())],
        );
        assert_eq!(a.level, Some(Level::Baseline));
        assert_eq!(a.level_confidence, Some("upper_bound"));

        let a = analyse(
            "Deployment",
            Some(&pod),
            &[
                input("app", "regular", restricted_sc()),
                input(
                    "debug",
                    "init",
                    ContainerSecurity {
                        privileged: Some(true),
                        ..restricted_sc()
                    },
                ),
            ],
        );
        assert_eq!(a.level, Some(Level::Privileged));
        assert_eq!(a.level_confidence, Some("confirmed"));
        assert_eq!(a.containers[0].level, Level::Restricted);
        assert_eq!(a.containers[1].level, Level::Privileged);

        // Pod-level failure lowers every container's workload level.
        let host = PodSecurity {
            host_network: Some(true),
            ..Default::default()
        };
        let a = analyse(
            "Deployment",
            Some(&host),
            &[input("app", "regular", restricted_sc())],
        );
        assert_eq!(a.level, Some(Level::Privileged));

        let a = analyse("Deployment", Some(&pod), &[]);
        assert_eq!(a.level, None);
        assert_eq!(a.level_confidence, None);
        assert!(a.findings.is_empty());
    }

    // ---- findings ----------------------------------------------------------

    #[test]
    fn findings_cover_the_posture_list() {
        let pod = PodSecurity {
            host_pid: Some(true),
            automount_service_account_token: None,
            ..Default::default()
        };
        let sc = ContainerSecurity {
            privileged: Some(true),
            run_as_user: Some(0),
            capabilities_add: Some(vec!["SYS_ADMIN".into()]),
            ..Default::default()
        };
        let f = findings(&pod, true, &[input("app", "regular", sc)]);
        let got: BTreeSet<&str> = f.iter().map(|x| x.id.as_str()).collect();
        for want in [
            "podSecurity.hostPID",
            "podSecurity.automountToken",
            "podSecurity.privileged/app",
            "podSecurity.capabilitiesAdded/app",
            "podSecurity.allowPrivilegeEscalation/app",
            "podSecurity.runAsRoot/app",
            "podSecurity.seccompUnset/app",
            "podSecurity.capabilitiesNotDropped/app",
            "podSecurity.readOnlyRootFilesystem/app",
        ] {
            assert!(got.contains(want), "missing {want}: {got:?}");
        }
        assert!(!got.contains("podSecurity.mayRunAsRoot/app"));

        let clean = PodSecurity {
            automount_service_account_token: Some(false),
            ..Default::default()
        };
        assert!(findings(&clean, true, &[input("app", "regular", restricted_sc())]).is_empty());

        let maybe = ContainerSecurity {
            run_as_non_root: None,
            ..restricted_sc()
        };
        let f = findings(&clean, true, &[input("app", "regular", maybe)]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "podSecurity.mayRunAsRoot/app");
    }

    // ---- recommendation ----------------------------------------------------

    #[test]
    fn recommendation_patches_only_failing_fields_under_the_template_path() {
        let pod = PodSecurity::default();
        let cs = [
            input("app", "regular", restricted_sc()),
            input("migrate", "init", ContainerSecurity::default()),
        ];
        let a = analyse("Deployment", Some(&pod), &cs);
        let r = a.recommendation.expect("init container fails restricted");
        assert!(r.recommendation);
        assert_eq!(r.target_level, "restricted");
        let y = &r.yaml;
        assert!(y.starts_with("# kguardian recommendation, not applied."));
        assert!(y.contains("spec:\n  template:\n    spec:\n"));
        assert!(y.contains("      initContainers:\n      - name: migrate\n"));
        assert!(y.contains("allowPrivilegeEscalation: false"));
        assert!(y.contains("drop: [\"ALL\"]"));
        // The passing container is not in the patch.
        assert!(!y.contains("name: app"));
        // runAsNonRoot and seccomp are set once at pod level.
        assert!(y.contains("      securityContext:\n        runAsNonRoot: true\n        seccompProfile:\n          type: RuntimeDefault\n"));
    }

    #[test]
    fn recommendation_paths_per_kind_and_host_namespaces() {
        let pod = PodSecurity {
            host_network: Some(true),
            ..Default::default()
        };
        let cs = [input("app", "regular", restricted_sc())];
        let cron = analyse("CronJob", Some(&pod), &cs)
            .recommendation
            .unwrap()
            .yaml;
        assert!(cron.contains("spec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          hostNetwork: false\n"));
        let bare = analyse("Pod", Some(&pod), &cs).recommendation.unwrap().yaml;
        assert!(bare.contains("\nspec:\n  hostNetwork: false\n"));
    }

    #[test]
    fn recommendation_never_patches_ephemeral_containers() {
        let pod = PodSecurity {
            security_context: Some(PodSecurityFields {
                run_as_non_root: Some(true),
                seccomp_profile_type: Some("RuntimeDefault".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cs = [
            input("app", "regular", restricted_sc()),
            input("debugger", "ephemeral", ContainerSecurity::default()),
        ];
        // Only the ephemeral container fails: nothing patchable, so no
        // patch at all (never a bare, null pod template).
        assert!(analyse("Deployment", Some(&pod), &cs)
            .recommendation
            .is_none());

        // With a patchable failure too, the ephemeral one is named in the
        // caveats and never patched.
        let cs = [
            input("app", "regular", ContainerSecurity::default()),
            input("debugger", "ephemeral", ContainerSecurity::default()),
        ];
        let r = analyse("Deployment", Some(&pod), &cs)
            .recommendation
            .unwrap();
        assert!(!r.yaml.contains("debugger"));
        assert!(r.caveats.iter().any(|c| c.contains("debugger")));
    }

    #[test]
    fn recommendation_caveats_for_risky_patch_lines() {
        let pod = PodSecurity {
            host_network: Some(true),
            ..Default::default()
        };
        let sc = ContainerSecurity {
            privileged: Some(true),
            ..Default::default()
        };
        let r = analyse("DaemonSet", Some(&pod), &[input("agent", "regular", sc)])
            .recommendation
            .unwrap();
        let all = r.caveats.join("\n");
        assert!(all.contains("node agent"));
        assert!(all.contains("privileged: false"));
        assert!(all.contains("hostNetwork"));
        assert!(all.contains("NET_BIND_SERVICE"));
        // readOnlyRootFilesystem stays out of the patch.
        assert!(!r.yaml.contains("readOnlyRootFilesystem"));
    }

    #[test]
    fn recommendation_strips_disallowed_caps_and_root_uid() {
        let sc = ContainerSecurity {
            capabilities_add: Some(vec!["NET_ADMIN".into()]),
            run_as_user: Some(0),
            ..restricted_sc()
        };
        let r = analyse(
            "StatefulSet",
            Some(&PodSecurity::default()),
            &[input("db", "regular", sc)],
        )
        .recommendation
        .unwrap();
        assert!(r.yaml.contains("add: null  # was NET_ADMIN"));
        assert!(r.yaml.contains("runAsUser: null  # was 0"));
    }
}
