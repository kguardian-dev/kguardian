use crate::network::canonicalize_ip;
use crate::{api_post_call, Error, SvcDetail};
use chrono::Utc;
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::{
    runtime::{watcher, WatchStreamExt},
    Api, Client, ResourceExt,
};
use serde_json::json;
use tracing::{debug, error, warn};

pub async fn watch_service() -> Result<(), Error> {
    let c = Client::try_default().await?;
    let svc: Api<Service> = Api::all(c.clone());
    let wc = watcher::Config::default();
    watcher(svc, wc)
        .applied_objects()
        .default_backoff()
        .try_for_each(|p| {
            async move {
                if let Some(unready_reason) = svc_unready(&p) {
                    warn!("{}", unready_reason);
                } else {
                    // debug not info — fires for every Service watch
                    // event including the full re-sync on startup
                    // (one line per Service in the cluster). Same
                    // noise class as the per-pod-event info logs
                    // dropped in becf12c7 / da590498 / faf10771. The
                    // controller is correctly tracking Services
                    // either way; operators don't need the per-event
                    // confirmation at INFO. Symmetric with the broker
                    // side's add_svc_details info → debug in 482cae24.
                    debug!("SVC  {} Ready", p.name_any());

                    let ep = update_serviceinfo(p).await;
                    // log the error and proceed
                    if let Err(e) = ep {
                        error!(
                            "Failed while updating the endpoint slice info {}",
                            e.to_string()
                        );
                    }
                }
                Ok(())
            }
        })
        .await?;

    Ok(())
}

async fn update_serviceinfo(svc: Service) -> Result<(), Error> {
    let svc_name = svc.name_any();
    let svc_namespace = svc.metadata.namespace.to_owned();

    let spec = svc.spec.as_ref();
    let svc_ips = routable_cluster_ips(
        spec.and_then(|s| s.cluster_ip.as_deref()),
        spec.and_then(|s| s.cluster_ips.as_deref()),
    );

    if svc_ips.is_empty() {
        warn!("Service {} has no usable cluster IP", svc_name);
        return Ok(());
    }

    // svc_details is keyed on svc_ip, so a dual-stack Service simply
    // gets one row per address — no schema change needed, and either
    // address resolves back to the same Service name/namespace.
    let service_spec = json!(svc);
    for svc_ip in svc_ips {
        let svc_details = SvcDetail {
            svc_ip,
            svc_name: svc_name.to_owned(),
            svc_namespace: svc_namespace.to_owned(),
            service_spec: Some(service_spec.clone()),
            time_stamp: Utc::now().naive_utc(),
        };
        if let Err(e) = api_post_call(json!(svc_details), "svc/spec").await {
            error!("Failed to post Service details: {}", e);
        }
    }
    Ok(())
}

/// Every cluster IP worth storing for a Service, canonicalised and
/// de-duplicated, primary (`spec.clusterIP`) first.
///
/// `spec.clusterIPs` holds both addresses of a dual-stack Service;
/// reading only `spec.clusterIP` meant the secondary-family address was
/// never registered, so eBPF flows to it correlated to no Service.
/// `clusterIPs` is absent on single-stack/older clusters, hence the
/// `clusterIP` seed.
///
/// Filtering is applied per address — same two cases as before:
///
/// - `"None"` → headless service. All headless services would otherwise
///   share the same `svc_ip="None"` row and collide on the broker's
///   primary key, with the most-recent insert silently winning.
/// - `""` → ExternalName / unassigned. An empty PK is rejected by
///   Postgres on a NOT NULL column, and the row would be wasted
///   overhead even if accepted.
fn routable_cluster_ips(cluster_ip: Option<&str>, cluster_ips: Option<&[String]>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |raw: &str| {
        if !is_routable_cluster_ip(raw) {
            return;
        }
        // Canonical spelling so the broker's IP-keyed lookups match
        // what the eBPF path reports. See network::canonicalize_ip.
        let ip = canonicalize_ip(raw);
        if !out.contains(&ip) {
            out.push(ip);
        }
    };

    if let Some(primary) = cluster_ip {
        push(primary);
    }
    for ip in cluster_ips.unwrap_or_default() {
        push(ip);
    }
    out
}

/// True when the given Service.spec.clusterIP value is a real IP that
/// makes sense as a key in the broker's IP-keyed svc_details table.
/// Excludes the literal "None" (headless) and empty (ExternalName).
fn is_routable_cluster_ip(s: &str) -> bool {
    !s.is_empty() && s != "None"
}

/// Returns Some(reason) when a Service is reporting an unready
/// condition. None when the Service has no status yet (transient
/// state for freshly-created Services — kubelet hasn't filled it in)
/// or has no Ready=False conditions.
///
/// Previously called .status.as_ref().unwrap(), which panicked the
/// watcher task — and therefore the whole controller — every time a
/// Service was observed mid-creation.
fn svc_unready(p: &Service) -> Option<String> {
    let status = p.status.as_ref()?;
    // debug not info — this runs on every Service event including the
    // full re-sync on controller startup. INFO floods the log with the
    // entire ServiceStatus debug-print on every Service in the cluster,
    // drowning real signals at the noise level operators are most
    // likely to scan first. The actual condition message (when a
    // Service is unready) is still surfaced via the warn! at the
    // caller site.
    debug!("Service Status {:?}", status);
    let conds = status.conditions.as_ref()?;
    let failed = conds
        .iter()
        .filter(|c| c.type_ == "Ready" && c.status == "False")
        .map(|c| c.message.clone())
        .collect::<Vec<_>>()
        .join(",");
    if !failed.is_empty() {
        Some(format!("Unready Service {}: {}", p.name_any(), failed))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ServiceStatus;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

    fn ips(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn cluster_ips_single_stack_yields_one_row() {
        assert_eq!(
            routable_cluster_ips(Some("10.96.0.1"), Some(&ips(&["10.96.0.1"]))),
            vec!["10.96.0.1".to_string()]
        );
    }

    #[test]
    fn cluster_ips_dual_stack_yields_a_row_per_family() {
        // The regression this guards: reading only spec.clusterIP
        // dropped the IPv6 address, so IPv6 flows to this Service
        // correlated to nothing.
        assert_eq!(
            routable_cluster_ips(
                Some("10.96.0.1"),
                Some(&ips(&["10.96.0.1", "fd00:10:96::1"]))
            ),
            vec!["10.96.0.1".to_string(), "fd00:10:96::1".to_string()]
        );
    }

    #[test]
    fn cluster_ips_falls_back_to_singular_when_list_absent() {
        assert_eq!(
            routable_cluster_ips(Some("10.96.0.1"), None),
            vec!["10.96.0.1".to_string()]
        );
    }

    #[test]
    fn cluster_ips_filters_headless_and_empty_per_entry() {
        assert!(routable_cluster_ips(Some("None"), Some(&ips(&["None"]))).is_empty());
        assert!(routable_cluster_ips(Some(""), None).is_empty());
        assert!(routable_cluster_ips(None, None).is_empty());
        // A junk entry alongside a real one must not take the real one down.
        assert_eq!(
            routable_cluster_ips(Some("10.96.0.1"), Some(&ips(&["None", "fd00::1"]))),
            vec!["10.96.0.1".to_string(), "fd00::1".to_string()]
        );
    }

    #[test]
    fn cluster_ips_canonicalises_and_dedupes() {
        // Same address spelled two ways must produce ONE row, or the
        // broker ends up with duplicate keys for one Service.
        assert_eq!(
            routable_cluster_ips(
                Some("FD00:0:0:0:0:0:0:1"),
                Some(&ips(&["fd00::1", "fd00:0::0:1"]))
            ),
            vec!["fd00::1".to_string()]
        );
    }

    fn svc(status: Option<ServiceStatus>) -> Service {
        Service {
            status,
            ..Service::default()
        }
    }

    #[test]
    fn no_status_returns_none() {
        // Regression test for the unwrap panic. A freshly-created
        // Service has no status populated yet; the watcher must not
        // panic on it.
        assert!(svc_unready(&svc(None)).is_none());
    }

    #[test]
    fn status_with_no_conditions_returns_none() {
        let st = ServiceStatus {
            conditions: None,
            ..Default::default()
        };
        assert!(svc_unready(&svc(Some(st))).is_none());
    }

    #[test]
    fn ready_true_condition_returns_none() {
        let cond = Condition {
            type_: "Ready".into(),
            status: "True".into(),
            message: "service ready".into(),
            reason: String::new(),
            observed_generation: None,
            last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::default(),
            ),
        };
        let st = ServiceStatus {
            conditions: Some(vec![cond]),
            ..Default::default()
        };
        assert!(svc_unready(&svc(Some(st))).is_none());
    }

    #[test]
    fn ready_false_condition_returns_message() {
        let cond = Condition {
            type_: "Ready".into(),
            status: "False".into(),
            message: "endpoint slice missing".into(),
            reason: String::new(),
            observed_generation: None,
            last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::default(),
            ),
        };
        let st = ServiceStatus {
            conditions: Some(vec![cond]),
            ..Default::default()
        };
        let got = svc_unready(&svc(Some(st)));
        assert!(got.is_some(), "Ready=False must produce an unready reason");
        assert!(got.unwrap().contains("endpoint slice missing"));
    }

    #[test]
    fn unrelated_failed_condition_does_not_count() {
        // Only Ready=False matters; other failed conditions are noise.
        let cond = Condition {
            type_: "MemoryPressure".into(),
            status: "False".into(),
            message: "ok".into(),
            reason: String::new(),
            observed_generation: None,
            last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::default(),
            ),
        };
        let st = ServiceStatus {
            conditions: Some(vec![cond]),
            ..Default::default()
        };
        assert!(svc_unready(&svc(Some(st))).is_none());
    }

    // is_routable_cluster_ip pins the post-fix contract: only real
    // IPs should drive the broker's svc_details upsert path. A
    // regression here would either (a) re-collide every headless
    // service on a single "None" row, or (b) bounce empty-string
    // inserts against a NOT NULL column.

    #[test]
    fn routable_cluster_ip_accepts_real_ips() {
        // The 10.x range is the typical cluster-IP allocation; some
        // distros use 192.168.x; IPv6 cluster IPs look like fd00:...
        assert!(is_routable_cluster_ip("10.96.0.1"));
        assert!(is_routable_cluster_ip("192.168.1.100"));
        assert!(is_routable_cluster_ip("172.20.0.10"));
        assert!(is_routable_cluster_ip("fd00::1"));
    }

    #[test]
    fn routable_cluster_ip_rejects_headless_sentinel() {
        // The bug case: headless services use the literal string
        // "None". Without this filter every headless service in the
        // cluster would collide on svc_ip="None" in the broker.
        assert!(!is_routable_cluster_ip("None"));
    }

    #[test]
    fn routable_cluster_ip_rejects_empty() {
        // ExternalName services / pre-allocation state. Empty string
        // as a primary key is wasted overhead at best, a NOT NULL
        // violation at worst.
        assert!(!is_routable_cluster_ip(""));
    }

    #[test]
    fn routable_cluster_ip_is_case_sensitive_on_none() {
        // "none" / "NONE" are NOT the headless sentinel in the
        // Kubernetes API — they'd be malformed values that shouldn't
        // exist, but if they did, they'd fail real-IP parsing later
        // anyway. Pin the literal match so a refactor doesn't relax
        // to a case-insensitive compare that swallows other typos.
        assert!(is_routable_cluster_ip("none"));
        assert!(is_routable_cluster_ip("NONE"));
    }
}
