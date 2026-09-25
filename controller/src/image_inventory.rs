//! Image identity and security context, extracted from a Pod for the
//! broker's image inventory (`images` / `workload_containers`).
//!
//! The controller already holds every Pod it watches, and posts it to
//! `/pod/spec` as `pod_obj` — but the broker compacts that manifest down
//! to labels and `hostNetwork` before storage, so image references,
//! `imageID` digests and securityContext never survived ingest. This
//! module extracts a small, typed subset instead: one entry per
//! container plus a handful of pod-level fields. It is deliberately NOT
//! the whole pod — an unbounded manifest in a stored row is what took
//! `/pod/info` to 72 MB.
//!
//! Everything here is a pure function of the Pod, so it is unit-tested
//! without an apiserver.

use k8s_openapi::api::core::v1::{
    ContainerStatus, Pod, PodSecurityContext, SeccompProfile, SecurityContext,
};
use serde::Serialize;
use serde_derive::Deserialize;

/// Upper bound on containers reported per pod. Real pods have a handful;
/// the cap exists so a pathological spec cannot inflate one `/pod/spec`
/// body. The broker enforces its own bound as well.
pub const MAX_CONTAINERS: usize = 64;

/// Which list in the pod spec a container came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerKind {
    Init,
    Regular,
    Ephemeral,
}

/// Where a container's digest came from, which decides what it can be
/// used for downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestKind {
    /// `repo@sha256:…` from `status.imageID` (containerd, CRI-O, and
    /// dockershim's `docker-pullable://` form). The manifest (or index)
    /// digest the kubelet resolved: usable for registry, SBOM and
    /// attestation lookups.
    Repo,
    /// A bare `sha256:…` from `status.imageID` (or `docker://sha256:…`):
    /// the image CONFIG digest. Seen for images with no repo digest —
    /// locally loaded, `kind load`, `imagePullPolicy: Never`. Identifies
    /// the content on the node but cannot be looked up in a registry.
    Config,
    /// No usable `imageID` yet (the container has not started), but the
    /// spec pins the image by digest (`repo@sha256:…`). Replaced by a
    /// `repo` digest as soon as the kubelet reports one.
    Pinned,
}

/// The container-level securityContext subset the posture analysis
/// needs. Field names mirror the Kubernetes API (camelCase) so the stored
/// JSON reads like the spec it came from. `None`/empty fields are
/// omitted: absent means "not set in the spec", which is not the same as
/// `false` for most of these.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerSecurity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_privilege_escalation: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_non_root: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_group: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_root_filesystem: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities_add: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities_drop: Vec<String>,
    /// `seccompProfile.type`: `RuntimeDefault` | `Localhost` | `Unconfined`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp_profile_type: Option<String>,
}

/// One container's identity, as reported on `/pod/spec`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerInventory {
    pub name: String,
    pub kind: ContainerKind,
    /// `image` exactly as written in the spec, e.g. `nginx:1.27`.
    pub image: String,
    /// Raw `status.imageID`, when the kubelet has reported one. Kept
    /// verbatim so a parse this module gets wrong is recoverable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,
    /// `sha256:<hex>` (or `sha512:<hex>`), parsed from `image_id`, or
    /// from the spec when it pins a digest and no `image_id` exists yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_kind: Option<DigestKind>,
    /// Normalised repository (`docker.io/library/nginx`), from the
    /// `imageID` when it names one, else from the spec reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Tag from the spec reference; `latest` when the reference has
    /// neither tag nor digest (what the kubelet pulls). `None` for a
    /// digest-only reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default)]
    pub security_context: ContainerSecurity,
}

/// Pod securityContext subset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurityFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_non_root: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_group: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_group: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp_profile_type: Option<String>,
}

/// Pod-level fields that shape every container's posture.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automount_service_account_token: Option<bool>,
    #[serde(default, rename = "hostPID", skip_serializing_if = "Option::is_none")]
    pub host_pid: Option<bool>,
    #[serde(default, rename = "hostIPC", skip_serializing_if = "Option::is_none")]
    pub host_ipc: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_users: Option<bool>,
    #[serde(default)]
    pub security_context: PodSecurityFields,
}

/// A digest parsed out of an `imageID` or image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedImageId {
    /// Normalised repository, when the value named one.
    pub repository: Option<String>,
    pub digest: String,
    pub kind: DigestKind,
}

/// `algo:hex` with a known algorithm and the right hex length. Anything
/// else is not a digest we can key on.
pub fn is_valid_digest(s: &str) -> bool {
    let Some((algo, hex)) = s.split_once(':') else {
        return false;
    };
    let want = match algo {
        "sha256" => 64,
        "sha512" => 128,
        _ => return false,
    };
    hex.len() == want
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parse `status.imageID`. The runtime decides the spelling:
///
/// | runtime / case                     | imageID                                   | kind   |
/// |------------------------------------|-------------------------------------------|--------|
/// | containerd, CRI-O                  | `docker.io/library/nginx@sha256:…`        | repo   |
/// | dockershim (pulled)                | `docker-pullable://nginx@sha256:…`        | repo   |
/// | image with no repo digest          | `sha256:…`                                | config |
/// | dockershim (not pulled)            | `docker://sha256:…`                       | config |
/// | container not started              | `""`                                      | —      |
///
/// Returns `None` for an empty or unrecognised value.
pub fn parse_image_id(raw: &str) -> Option<ParsedImageId> {
    let s = raw.trim();
    let s = s
        .strip_prefix("docker-pullable://")
        .or_else(|| s.strip_prefix("docker://"))
        .unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    if let Some((repo, digest)) = s.rsplit_once('@') {
        if !is_valid_digest(digest) || repo.is_empty() {
            return None;
        }
        return Some(ParsedImageId {
            repository: Some(normalise_repository(repo)),
            digest: digest.to_string(),
            kind: DigestKind::Repo,
        });
    }
    if is_valid_digest(s) {
        return Some(ParsedImageId {
            repository: None,
            digest: s.to_string(),
            kind: DigestKind::Config,
        });
    }
    None
}

/// An image reference split into its parts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageRef {
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

/// Split a spec image reference (`[registry/]path[:tag][@digest]`).
///
/// The tag separator is the last `:` AFTER the last `/`, so a registry
/// port (`registry:5000/app`) is not mistaken for a tag. A reference
/// with neither tag nor digest gets `latest`, which is what the kubelet
/// pulls. A digest that is not a valid `algo:hex` is dropped.
pub fn parse_image_ref(raw: &str) -> ImageRef {
    let s = raw.trim();
    let (name, digest) = match s.rsplit_once('@') {
        Some((n, d)) => (n, is_valid_digest(d).then(|| d.to_string())),
        None => (s, None),
    };
    let last_slash = name.rfind('/').map_or(0, |i| i + 1);
    let (repo, tag) = match name[last_slash..].rfind(':') {
        Some(i) => {
            let at = last_slash + i;
            (&name[..at], Some(name[at + 1..].to_string()))
        }
        None => (name, None),
    };
    let tag = match (tag, &digest) {
        (Some(t), _) if !t.is_empty() => Some(t),
        (_, Some(_)) => None,
        _ => Some("latest".to_string()),
    };
    ImageRef {
        repository: normalise_repository(repo),
        tag,
        digest,
    }
}

/// Normalise a repository to its fully-qualified form, the way the
/// container runtime resolves it: a first path component without a `.`
/// or `:` (and not `localhost`) is a Docker Hub path, so `nginx` becomes
/// `docker.io/library/nginx` and `bitnami/redis` becomes
/// `docker.io/bitnami/redis`. Lower-cased registry host; the path is kept
/// as written (it is already required to be lower case). This makes the
/// spec form and containerd's `imageID` form agree.
pub fn normalise_repository(repo: &str) -> String {
    let repo = repo.trim();
    let (first, rest) = match repo.split_once('/') {
        Some((f, r)) => (f, Some(r)),
        None => (repo, None),
    };
    let is_registry = first.contains('.') || first.contains(':') || first == "localhost";
    match (is_registry, rest) {
        // Docker Hub spelled out: `docker.io/nginx` and
        // `index.docker.io/nginx` are both `docker.io/library/nginx`.
        (true, Some(rest))
            if matches!(
                first.to_ascii_lowercase().as_str(),
                "docker.io" | "index.docker.io"
            ) =>
        {
            if rest.contains('/') {
                format!("docker.io/{rest}")
            } else {
                format!("docker.io/library/{rest}")
            }
        }
        (true, Some(rest)) => format!("{}/{}", first.to_ascii_lowercase(), rest),
        (false, Some(_)) => format!("docker.io/{repo}"),
        (_, None) => format!("docker.io/library/{repo}"),
    }
}

fn seccomp_type(p: Option<&SeccompProfile>) -> Option<String> {
    p.map(|p| p.type_.clone()).filter(|t| !t.is_empty())
}

/// Map a container's `securityContext` to the reported subset.
pub fn container_security(sc: Option<&SecurityContext>) -> ContainerSecurity {
    let Some(sc) = sc else {
        return ContainerSecurity::default();
    };
    let caps = sc.capabilities.as_ref();
    ContainerSecurity {
        privileged: sc.privileged,
        allow_privilege_escalation: sc.allow_privilege_escalation,
        run_as_non_root: sc.run_as_non_root,
        run_as_user: sc.run_as_user,
        run_as_group: sc.run_as_group,
        read_only_root_filesystem: sc.read_only_root_filesystem,
        capabilities_add: caps.and_then(|c| c.add.clone()).unwrap_or_default(),
        capabilities_drop: caps.and_then(|c| c.drop.clone()).unwrap_or_default(),
        seccomp_profile_type: seccomp_type(sc.seccomp_profile.as_ref()),
    }
}

fn pod_security_fields(sc: Option<&PodSecurityContext>) -> PodSecurityFields {
    let Some(sc) = sc else {
        return PodSecurityFields::default();
    };
    PodSecurityFields {
        run_as_non_root: sc.run_as_non_root,
        run_as_user: sc.run_as_user,
        run_as_group: sc.run_as_group,
        fs_group: sc.fs_group,
        seccomp_profile_type: seccomp_type(sc.seccomp_profile.as_ref()),
    }
}

/// Pod-level posture fields.
pub fn pod_security(pod: &Pod) -> PodSecurity {
    let Some(spec) = pod.spec.as_ref() else {
        return PodSecurity::default();
    };
    PodSecurity {
        // `serviceAccount` is the deprecated alias; the API server fills
        // `serviceAccountName` from it, but read both for safety.
        service_account_name: spec
            .service_account_name
            .clone()
            .or_else(|| spec.service_account.clone())
            .filter(|s| !s.is_empty()),
        automount_service_account_token: spec.automount_service_account_token,
        host_pid: spec.host_pid,
        host_ipc: spec.host_ipc,
        host_network: spec.host_network,
        host_users: spec.host_users,
        security_context: pod_security_fields(spec.security_context.as_ref()),
    }
}

fn one_container(
    name: &str,
    kind: ContainerKind,
    image: Option<&str>,
    sc: Option<&SecurityContext>,
    statuses: Option<&Vec<ContainerStatus>>,
) -> ContainerInventory {
    let image = image.unwrap_or_default().trim().to_string();
    let spec_ref = parse_image_ref(&image);
    let image_id = statuses
        .and_then(|ss| ss.iter().find(|s| s.name == name))
        .map(|s| s.image_id.trim().to_string())
        .filter(|s| !s.is_empty());
    let parsed = image_id.as_deref().and_then(parse_image_id);

    let (digest, digest_kind, repository) = match parsed {
        Some(p) => {
            let repo = p
                .repository
                .or_else(|| (!image.is_empty()).then(|| spec_ref.repository.clone()));
            (Some(p.digest), Some(p.kind), repo)
        }
        None => {
            let repo = (!image.is_empty()).then(|| spec_ref.repository.clone());
            match &spec_ref.digest {
                Some(d) => (Some(d.clone()), Some(DigestKind::Pinned), repo),
                None => (None, None, repo),
            }
        }
    };

    ContainerInventory {
        name: name.to_string(),
        kind,
        tag: if image.is_empty() { None } else { spec_ref.tag },
        image,
        image_id,
        digest,
        digest_kind,
        repository,
        security_context: container_security(sc),
    }
}

/// Every container in the pod — init, regular, then ephemeral — with its
/// image identity and securityContext subset. Capped at
/// [`MAX_CONTAINERS`].
pub fn pod_containers(pod: &Pod) -> Vec<ContainerInventory> {
    let Some(spec) = pod.spec.as_ref() else {
        return Vec::new();
    };
    let status = pod.status.as_ref();
    let mut out = Vec::new();
    for c in spec.init_containers.iter().flatten() {
        out.push(one_container(
            &c.name,
            ContainerKind::Init,
            c.image.as_deref(),
            c.security_context.as_ref(),
            status.and_then(|s| s.init_container_statuses.as_ref()),
        ));
    }
    for c in &spec.containers {
        out.push(one_container(
            &c.name,
            ContainerKind::Regular,
            c.image.as_deref(),
            c.security_context.as_ref(),
            status.and_then(|s| s.container_statuses.as_ref()),
        ));
    }
    for c in spec.ephemeral_containers.iter().flatten() {
        out.push(one_container(
            &c.name,
            ContainerKind::Ephemeral,
            c.image.as_deref(),
            c.security_context.as_ref(),
            status.and_then(|s| s.ephemeral_container_statuses.as_ref()),
        ));
    }
    out.truncate(MAX_CONTAINERS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const D2: &str = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #[test]
    fn digest_validation() {
        assert!(is_valid_digest(D));
        assert!(is_valid_digest(&format!("sha512:{}", "a".repeat(128))));
        assert!(!is_valid_digest("sha256:abc"));
        assert!(!is_valid_digest(&D.to_uppercase()));
        assert!(!is_valid_digest(&format!("md5:{}", "a".repeat(64))));
        assert!(!is_valid_digest("nginx:1.27"));
        assert!(!is_valid_digest(""));
    }

    #[test]
    fn image_id_containerd_repo_digest() {
        let p = parse_image_id(&format!("docker.io/library/nginx@{D}")).unwrap();
        assert_eq!(p.digest, D);
        assert_eq!(p.kind, DigestKind::Repo);
        assert_eq!(p.repository.as_deref(), Some("docker.io/library/nginx"));
    }

    #[test]
    fn image_id_dockershim_pullable() {
        let p = parse_image_id(&format!("docker-pullable://nginx@{D}")).unwrap();
        assert_eq!(p.kind, DigestKind::Repo);
        assert_eq!(p.digest, D);
        assert_eq!(p.repository.as_deref(), Some("docker.io/library/nginx"));
    }

    #[test]
    fn image_id_bare_config_digest() {
        let p = parse_image_id(D).unwrap();
        assert_eq!(p.kind, DigestKind::Config);
        assert_eq!(p.repository, None);
        let p = parse_image_id(&format!("docker://{D}")).unwrap();
        assert_eq!(p.kind, DigestKind::Config);
        assert_eq!(p.digest, D);
    }

    #[test]
    fn image_id_registry_with_port() {
        let p = parse_image_id(&format!("registry.local:5000/team/app@{D}")).unwrap();
        assert_eq!(
            p.repository.as_deref(),
            Some("registry.local:5000/team/app")
        );
    }

    #[test]
    fn image_id_rejects_empty_and_garbage() {
        assert_eq!(parse_image_id(""), None);
        assert_eq!(parse_image_id("   "), None);
        assert_eq!(parse_image_id("nginx:1.27"), None);
        assert_eq!(parse_image_id("nginx@sha256:short"), None);
        assert_eq!(parse_image_id(&format!("@{D}")), None);
    }

    #[test]
    fn image_ref_forms() {
        let r = parse_image_ref("nginx:1.27");
        assert_eq!(r.repository, "docker.io/library/nginx");
        assert_eq!(r.tag.as_deref(), Some("1.27"));
        assert_eq!(r.digest, None);

        let r = parse_image_ref("nginx");
        assert_eq!(r.tag.as_deref(), Some("latest"));

        let r = parse_image_ref("registry.local:5000/team/app");
        assert_eq!(r.repository, "registry.local:5000/team/app");
        assert_eq!(r.tag.as_deref(), Some("latest"));

        let r = parse_image_ref(&format!("ghcr.io/org/app:v1@{D}"));
        assert_eq!(r.repository, "ghcr.io/org/app");
        assert_eq!(r.tag.as_deref(), Some("v1"));
        assert_eq!(r.digest.as_deref(), Some(D));

        let r = parse_image_ref(&format!("ghcr.io/org/app@{D}"));
        assert_eq!(r.tag, None);
        assert_eq!(r.digest.as_deref(), Some(D));

        let r = parse_image_ref("bitnami/redis:7");
        assert_eq!(r.repository, "docker.io/bitnami/redis");

        let r = parse_image_ref("localhost/app:dev");
        assert_eq!(r.repository, "localhost/app");

        let r = parse_image_ref("docker.io/library/nginx:1");
        assert_eq!(r.repository, "docker.io/library/nginx");
        assert_eq!(
            parse_image_ref("docker.io/nginx").repository,
            "docker.io/library/nginx"
        );
        assert_eq!(
            parse_image_ref("index.docker.io/bitnami/redis").repository,
            "docker.io/bitnami/redis"
        );
    }

    fn pod(v: serde_json::Value) -> Pod {
        serde_json::from_value(v).expect("valid pod")
    }

    #[test]
    fn pod_containers_matches_status_by_name_and_kind() {
        let p = pod(json!({
            "metadata": {"name": "web-1", "namespace": "prod"},
            "spec": {
                "initContainers": [{"name": "migrate", "image": "ghcr.io/org/migrate:v2"}],
                "containers": [
                    {"name": "app", "image": "nginx:1.27",
                     "securityContext": {
                        "privileged": false,
                        "allowPrivilegeEscalation": false,
                        "runAsNonRoot": true,
                        "runAsUser": 1000,
                        "readOnlyRootFilesystem": true,
                        "capabilities": {"add": ["NET_BIND_SERVICE"], "drop": ["ALL"]},
                        "seccompProfile": {"type": "RuntimeDefault"}
                     }},
                    {"name": "sidecar", "image": format!("ghcr.io/org/side@{D2}")}
                ],
                "ephemeralContainers": [{"name": "debugger", "image": "busybox"}]
            },
            "status": {
                "initContainerStatuses": [{"name": "migrate", "image": "", "imageID": D,
                    "ready": false, "restartCount": 0}],
                "containerStatuses": [
                    {"name": "sidecar", "image": "", "imageID": "", "ready": false, "restartCount": 0},
                    {"name": "app", "image": "", "imageID": format!("docker.io/library/nginx@{D}"),
                     "ready": true, "restartCount": 0}
                ]
            }
        }));
        let cs = pod_containers(&p);
        assert_eq!(
            cs.iter()
                .map(|c| (c.name.as_str(), c.kind))
                .collect::<Vec<_>>(),
            vec![
                ("migrate", ContainerKind::Init),
                ("app", ContainerKind::Regular),
                ("sidecar", ContainerKind::Regular),
                ("debugger", ContainerKind::Ephemeral),
            ]
        );

        let migrate = &cs[0];
        assert_eq!(migrate.digest.as_deref(), Some(D));
        assert_eq!(migrate.digest_kind, Some(DigestKind::Config));
        // A config digest names no repo, so the spec's is used.
        assert_eq!(migrate.repository.as_deref(), Some("ghcr.io/org/migrate"));
        assert_eq!(migrate.tag.as_deref(), Some("v2"));

        let app = &cs[1];
        assert_eq!(app.image, "nginx:1.27");
        assert_eq!(app.digest.as_deref(), Some(D));
        assert_eq!(app.digest_kind, Some(DigestKind::Repo));
        assert_eq!(app.repository.as_deref(), Some("docker.io/library/nginx"));
        assert_eq!(
            app.security_context,
            ContainerSecurity {
                privileged: Some(false),
                allow_privilege_escalation: Some(false),
                run_as_non_root: Some(true),
                run_as_user: Some(1000),
                run_as_group: None,
                read_only_root_filesystem: Some(true),
                capabilities_add: vec!["NET_BIND_SERVICE".into()],
                capabilities_drop: vec!["ALL".into()],
                seccomp_profile_type: Some("RuntimeDefault".into()),
            }
        );

        // Not started: empty imageID, but the spec pins a digest.
        let side = &cs[2];
        assert_eq!(side.image_id, None);
        assert_eq!(side.digest.as_deref(), Some(D2));
        assert_eq!(side.digest_kind, Some(DigestKind::Pinned));
        assert_eq!(side.tag, None);

        // No status at all and no pinned digest.
        let dbg = &cs[3];
        assert_eq!(dbg.digest, None);
        assert_eq!(dbg.digest_kind, None);
        assert_eq!(dbg.repository.as_deref(), Some("docker.io/library/busybox"));
        assert_eq!(dbg.security_context, ContainerSecurity::default());
    }

    #[test]
    fn pod_security_subset() {
        let p = pod(json!({
            "metadata": {"name": "x"},
            "spec": {
                "serviceAccountName": "web",
                "automountServiceAccountToken": false,
                "hostPID": true,
                "hostIPC": false,
                "hostNetwork": true,
                "securityContext": {"runAsNonRoot": true, "runAsUser": 65532, "fsGroup": 2000,
                    "seccompProfile": {"type": "Localhost", "localhostProfile": "p.json"},
                    "sysctls": [{"name": "net.core.somaxconn", "value": "1024"}]},
                "containers": [{"name": "a", "image": "a"}]
            }
        }));
        let s = pod_security(&p);
        assert_eq!(s.service_account_name.as_deref(), Some("web"));
        assert_eq!(s.automount_service_account_token, Some(false));
        assert_eq!(s.host_pid, Some(true));
        assert_eq!(s.host_ipc, Some(false));
        assert_eq!(s.host_network, Some(true));
        assert_eq!(s.security_context.run_as_user, Some(65532));
        assert_eq!(s.security_context.fs_group, Some(2000));
        assert_eq!(
            s.security_context.seccomp_profile_type.as_deref(),
            Some("Localhost")
        );
        // Wire names match the Kubernetes API spelling.
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["hostPID"], json!(true));
        assert_eq!(v["hostIPC"], json!(false));
        assert_eq!(v["serviceAccountName"], json!("web"));
        assert_eq!(v["automountServiceAccountToken"], json!(false));
        assert_eq!(v["securityContext"]["runAsNonRoot"], json!(true));
        // Unset fields are omitted, not sent as null.
        assert!(v.get("hostUsers").is_none());
    }

    #[test]
    fn container_wire_shape() {
        let p = pod(json!({
            "metadata": {"name": "x"},
            "spec": {"containers": [{"name": "a", "image": "nginx",
                "securityContext": {"capabilities": {"drop": ["ALL"]}}}]},
            "status": {"containerStatuses": [{"name": "a", "image": "",
                "imageID": format!("docker.io/library/nginx@{D}"), "ready": true, "restartCount": 0}]}
        }));
        let v = serde_json::to_value(pod_containers(&p)).unwrap();
        assert_eq!(
            v,
            json!([{
                "name": "a",
                "kind": "regular",
                "image": "nginx",
                "image_id": format!("docker.io/library/nginx@{D}"),
                "digest": D,
                "digest_kind": "repo",
                "repository": "docker.io/library/nginx",
                "tag": "latest",
                "security_context": {"capabilitiesDrop": ["ALL"]}
            }])
        );
    }

    #[test]
    fn pod_without_spec_reports_nothing() {
        let p = pod(json!({"metadata": {"name": "x"}}));
        assert!(pod_containers(&p).is_empty());
        assert_eq!(pod_security(&p), PodSecurity::default());
    }

    #[test]
    fn container_count_is_capped() {
        let containers: Vec<_> = (0..(MAX_CONTAINERS + 10))
            .map(|i| json!({"name": format!("c{i}"), "image": "a"}))
            .collect();
        let p = pod(json!({"metadata": {"name": "x"}, "spec": {"containers": containers}}));
        assert_eq!(pod_containers(&p).len(), MAX_CONTAINERS);
    }
}
