use crate::{api_post_call, Error, SvcDetail};
use chrono::Utc;
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::{
    runtime::{watcher, WatchStreamExt},
    Api, Client, ResourceExt,
};
use serde_json::json;
use tracing::info;
use tracing::{error, warn};

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
                    info!("SVC  {} Ready", p.name_any());

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

    let Some(svc_ip) = svc.spec.as_ref().and_then(|spec| spec.cluster_ip.as_ref()) else {
        warn!("Service {} has no cluster IP", svc_name);
        return Ok(());
    };

    let svc_details = SvcDetail {
        svc_ip: svc_ip.to_owned(),
        svc_name: svc_name.to_owned(),
        svc_namespace: svc_namespace.to_owned(),
        service_spec: Some(json!(svc)),
        time_stamp: Utc::now().naive_utc(),
    };
    if let Err(e) = api_post_call(json!(svc_details), "svc/spec").await {
        error!("Failed to post Service details: {}", e);
    }
    Ok(())
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
    info!("Service Status {:?}", status);
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

    fn svc(status: Option<ServiceStatus>) -> Service {
        let mut s = Service::default();
        s.status = status;
        s
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
        let st = ServiceStatus { conditions: None, ..Default::default() };
        assert!(svc_unready(&svc(Some(st))).is_none());
    }

    #[test]
    fn ready_true_condition_returns_none() {
        let cond = Condition {
            type_: "Ready".into(),
            status: "True".into(),
            message: "service ready".into(),
            ..Default::default()
        };
        let st = ServiceStatus { conditions: Some(vec![cond]), ..Default::default() };
        assert!(svc_unready(&svc(Some(st))).is_none());
    }

    #[test]
    fn ready_false_condition_returns_message() {
        let cond = Condition {
            type_: "Ready".into(),
            status: "False".into(),
            message: "endpoint slice missing".into(),
            ..Default::default()
        };
        let st = ServiceStatus { conditions: Some(vec![cond]), ..Default::default() };
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
            ..Default::default()
        };
        let st = ServiceStatus { conditions: Some(vec![cond]), ..Default::default() };
        assert!(svc_unready(&svc(Some(st))).is_none());
    }
}
