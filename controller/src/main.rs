use anyhow::Result;
use dashmap::DashMap;
use std::{env, sync::Arc};
use tokio::sync::mpsc;

use tracing::info;

use kguardian::bpf::ebpf_handle;
use kguardian::compute_config::ComputeConfig;
use kguardian::compute_sampler::{
    run as run_compute_sampler, run_heartbeat as run_compute_heartbeat, ContentionSource,
};
use kguardian::log::init_logger;
use kguardian::network::{handle_network_events, handle_policy_drop_events, PolicyDropEvent};
use kguardian::pod_watcher::ComputeContext;
use kguardian::seccomp_denial::{
    run as run_seccomp_denials, wire_registry, DenialMaps, RegistryWiring, SeccompDenialConfig,
};
use kguardian::seccomp_distributor::run as run_seccomp_distributor;
use kguardian::service_watcher::watch_service;
use kguardian::supervisor::{report, shut_down, Draining, Subsystem, Supervisor};
use kguardian::syscall::{
    handle_syscall_events, send_syscall_cache_periodically, StartupCapture, SyscallEventData,
};
use kguardian::{
    error::Error, models::ContainerMap, network::NetworkEventData,
    pod_reconciler::reconcile_pods_task, pod_watcher::watch_pods,
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    init_logger();

    // Trim whitespace from required URL/identity env vars. Common
    // operator pastes embed a trailing newline or surrounding spaces;
    // pre-trim defends every downstream consumer instead of forcing
    // each (api_post_call, the reconciler, the pod_watcher, etc.) to
    // remember the same hardening. An empty-after-trim value still
    // counts as "not set" → clear error message.
    let node_name = env::var("CURRENT_NODE")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Custom("CURRENT_NODE environment variable not set".to_string()))?;

    let broker_url = env::var("API_ENDPOINT")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Custom("API_ENDPOINT environment variable not set".to_string()))?;

    // One-shot, fire-and-forget: derive this node's environment facts
    // (provider/distro/CNI/IP family/OS) and report them to the broker
    // for the anonymous telemetry check-in. Deliberately unsupervised —
    // telemetry must never take capture down, and it is expected to
    // finish.
    tokio::spawn(kguardian::node_facts::report_node_facts(
        node_name.clone(),
        broker_url.clone(),
    ));

    let excluded_namespaces: Vec<String> = kguardian::pod_watcher::parse_excluded_namespaces(
        &env::var("EXCLUDED_NAMESPACES").unwrap_or_else(|_| "kube-system,kguardian".to_string()),
    );

    // bool::from_str is strict — only lowercase "true"/"false".
    // parse_lenient_bool accepts case-insensitive variants and
    // tolerates surrounding whitespace, so "False"/"FALSE"/" true\n"
    // all do the right thing instead of silently falling back to
    // the default. Operator setting IGNORE_DAEMONSET_TRAFFIC=False
    // (intending to disable) used to flip back to the default true
    // — the opposite of their intent.
    let ignore_daemonset_traffic = kguardian::pod_watcher::parse_lenient_bool(
        &env::var("IGNORE_DAEMONSET_TRAFFIC").unwrap_or_default(),
        true,
    );

    // Syscall capture tier (SYSCALL_CAPTURE_LEVEL, default full) and the
    // names behind `custom` (SYSCALL_CUSTOM_LIST). Resolved to numbers
    // for THIS architecture here, once, and logged, so an operator can
    // see what each tier means on the node. Every tier is resolved
    // regardless of the cluster default because a pod annotation can
    // raise any workload to any tier.
    let capture_config = kguardian::capture_tiers::CaptureConfig::from_env();
    info!(
        level = %capture_config.level,
        custom_names = capture_config.custom_names.len(),
        "syscall capture level"
    );
    let cluster_capture_level = capture_config.level;
    let resolved_tiers = capture_config.resolve();

    // Kernel seccomp verdicts (SECCOMP_DENIAL_*). Read here rather than
    // beside its own spawn site because the container registry below is
    // built for this feature too — see there.
    let seccomp_denial_config = SeccompDenialConfig::from_env();
    info!(
        enabled = seccomp_denial_config.enabled,
        interval_secs = seccomp_denial_config.interval.as_secs(),
        "seccomp denial capture"
    );

    // Compute gauges (COMPUTE_*). Off means nothing is SAMPLED and no
    // envelope is ever posted. The registry is shared between the pod
    // watcher (writer) and the sampler (reader); its registration
    // channel feeds the contention probe's `tracked_cgroups` map, so
    // it is subscribed BEFORE the watcher can emit anything.
    let compute_config = ComputeConfig::from_env();
    info!(
        enabled = compute_config.enabled,
        interval_secs = compute_config.sample_interval.as_secs(),
        contention = compute_config.contention_enabled,
        min_runq_latency_us = compute_config.min_runq_latency_us,
        "compute gauges"
    );
    // Who gets the container registry is NOT decided here, and that is
    // the point. The registry is not gated on `compute.enabled` alone:
    // seccomp denial capture attributes a hostNetwork pod's verdicts by
    // cgroup id and has nowhere else to resolve one, so gating it on the
    // gauges meant switching off an unrelated observability feature
    // silently switched off denial reporting for every hostNetwork
    // workload on the node — in the direction that reads as "clean".
    //
    // That decision lived here, in a file with no tests, and two
    // one-line reversals of it were each shown to leave the whole suite
    // green. It now lives in `seccomp_denial::wire_registry`, which is
    // pinned by a test; this file destructures the answer and has
    // nothing left to get wrong. The chart mounts the host cgroupfs
    // under the matching condition
    // (`templates/controller/daemonset.yaml`) — without that mount there
    // is nothing to resolve a cgroup path against, so the two must agree.
    let RegistryWiring {
        registry: compute_map,
        compute_events,
        denial_cgroups: seccomp_denial_cgroups,
    } = wire_registry(&compute_config, &seccomp_denial_config);
    let compute_ctx = compute_map.as_ref().map(|m| ComputeContext {
        map: Arc::clone(m),
        cgroup_root: compute_config.cgroup_root.clone(),
        host_proc: compute_config.host_proc.clone(),
        node: node_name.clone(),
    });
    // The scheduler-contention probe is a second switch beneath
    // compute.enabled (D9). A load failure is not fatal: the gauges
    // still run and every node sample says contention_loaded=false so
    // the UI can explain the missing blame.
    let contention_probe: Option<Box<dyn ContentionSource>> =
        if compute_config.enabled && compute_config.contention_enabled {
            match kguardian::contention::ContentionProbe::load(compute_config.min_runq_latency_us) {
                Ok(p) => {
                    info!("scheduler contention probe loaded");
                    Some(Box::new(p))
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "scheduler contention probe failed to load; compute gauges continue \
                         without blame (contention_loaded=false)"
                    );
                    None
                }
            }
        } else {
            None
        };

    let (tx, rx) = mpsc::channel(1000); // Use tokio's mpsc channel

    let (sender_ip, recv_ip) = mpsc::channel(1000); // Use tokio's mpsc channel

    // Shared inode -> pod map. NOTE: DashMap is sharded RwLocks, not lock-free.
    // A shard guard held across an .await blocks every subsystem that
    // touches this map, and on a busy node that is most of them. Each
    // subsystem has its own task now, so the blast radius is smaller
    // than it was — but a held guard is still a cross-task deadlock,
    // not a local stall. Read it only via models::lookup_pod. See
    // ContainerMap for the detail.
    let container_map: ContainerMap = Arc::new(DashMap::new());
    let pod_c = Arc::clone(&container_map);
    let network_map = Arc::clone(&container_map);
    let syscall_map = Arc::clone(&container_map);

    info!("Ignoring namespaces: {:?}", excluded_namespaces);

    let (network_event_sender, network_event_receiver) = mpsc::channel::<NetworkEventData>(1000);
    let (syscall_event_sender, syscall_event_receiver) = mpsc::channel::<SyscallEventData>(1000);
    let (netpolicy_drop_sender, netpolicy_drop_receiver) = mpsc::channel::<PolicyDropEvent>(1000);
    // Startup capture (early_capture): cgroup creations from the kernel,
    // and the cgroup ids userspace is done with going back to it.
    let (cgroup_event_sender, cgroup_event_receiver) = mpsc::channel::<(u64, String)>(1000);
    let (forget_pending_sender, forget_pending_receiver) = mpsc::channel::<u64>(4096);
    let startup_capture = StartupCapture {
        cgroup_events: cgroup_event_receiver,
        forget: forget_pending_sender,
        tiers: resolved_tiers.clone(),
    };

    // The denial probe is loaded by the eBPF loader alongside the other
    // three — it needs the pod registration stream, which only that loop
    // consumes — and hands its map descriptors back over this channel.
    // `None` means the feature is switched off and nothing is loaded at
    // all; a sender that is dropped without a value means the loader
    // decided this kernel cannot carry the probe, which the drain task
    // treats as a clean retirement.
    let (seccomp_denial_maps_sender, seccomp_denial_maps_receiver) =
        tokio::sync::oneshot::channel::<DenialMaps>();
    let seccomp_denial_maps_sender = seccomp_denial_config
        .enabled
        .then_some(seccomp_denial_maps_sender);

    // Spawned before anything is supervised: `ebpf_handle` is a
    // `spawn_blocking` that starts loading and attaching programs the
    // moment it is called, and its `JoinHandle` is what the supervised
    // future below awaits.
    let ebpf_handle = ebpf_handle(
        network_event_sender,
        syscall_event_sender,
        netpolicy_drop_sender,
        rx,
        recv_ip,
        ignore_daemonset_traffic,
        resolved_tiers,
        seccomp_denial_maps_sender,
        cgroup_event_sender,
        forget_pending_receiver,
    );

    let seccomp_denial_map = Arc::clone(&container_map);
    let seccomp_denial_node = node_name.clone();

    // One task per subsystem.
    //
    // These nine used to be composed with `tokio::try_join!`, which is
    // nine futures on ONE task. A task is polled by at most one worker
    // and cannot be stolen mid-poll, so a blocking call in any of them
    // froze all nine — measured on this 14-worker runtime: the in-join
    // heartbeat stopped for good while a separately spawned task kept
    // ticking — and all nine drained a single 128-operation cooperative
    // budget between them. See the supervisor module docs.
    //
    // Almost everything here is `Required`: these subsystems are meant
    // to run until the process does, and any of them stopping —
    // including returning `Ok(())` — ends the Controller non-zero. That
    // is not a new severity, it is the one `try_join!` already had for
    // `Err`, extended to cover the clean exits it ignored:
    // `handle_syscall_events`, `handle_network_events` and
    // `handle_policy_drop_events` all return `Ok(())` when their
    // channel closes, and `try_join!` went on waiting for the other
    // eight — a live, healthy-looking, partially-blind Controller.
    //
    // Keeping them `Required` also keeps a second signal that per-task
    // supervision makes easy to lose. Each of the three subsystems that
    // builds a kube client can `?` out of that build when the apiserver
    // is unreachable at boot; today that exits non-zero and the kubelet
    // backs off, and with no liveness, readiness or startup probe on
    // this DaemonSet that CrashLoopBackOff is the only thing an
    // operator sees. It must not become an invisible in-process retry.
    //
    // `ebpf-loader` in particular keeps the property PR #1473 argued
    // for: a Controller whose eBPF loader has died is not degraded, it
    // is blind, and a blind Controller that stays up turns
    // observed-absence-means-safe-to-deny into a lie that nothing
    // marks. Isolating the subsystems from each other's stalls must not
    // isolate the operator from their deaths.
    let mut supervisor = Supervisor::new();
    let node_name_for_compute = node_name.clone();

    supervisor.spawn(
        Subsystem::PodWatcher,
        watch_pods(
            node_name.clone(),
            tx,
            pod_c,
            excluded_namespaces,
            sender_ip,
            ignore_daemonset_traffic,
            cluster_capture_level,
            compute_ctx,
        ),
    );
    supervisor.spawn(Subsystem::ServiceWatch, watch_service());
    supervisor.spawn(
        Subsystem::NetworkEvents,
        handle_network_events(network_event_receiver, network_map),
    );
    supervisor.spawn(
        Subsystem::SyscallEvents,
        handle_syscall_events(syscall_event_receiver, syscall_map, startup_capture),
    );
    supervisor.spawn(
        Subsystem::NetpolicyDropEvents,
        handle_policy_drop_events(netpolicy_drop_receiver, Arc::clone(&container_map)),
    );
    supervisor.spawn(
        Subsystem::SyscallRecorder,
        send_syscall_cache_periodically(),
    );
    supervisor.spawn(
        Subsystem::PodReconciler,
        reconcile_pods_task(node_name, broker_url),
    );
    // Writes broker-generated per-workload seccomp profiles onto this
    // node. The one subsystem allowed to retire: `run` returns `Ok(())`
    // straight away unless SECCOMP_DISTRIBUTE=true, which is the
    // default install, so alarming on that would cry wolf everywhere.
    //
    // `MayRetire` exempts the clean `Ok` and nothing else — an `Err`
    // from this subsystem is still a fault that ends the process.
    // `run` has no `?` and no `return Err` today, so that is
    // unreachable; if you add one, that is the behaviour you are
    // choosing, and "best-effort" will no longer describe it.
    supervisor.spawn(Subsystem::SeccompDistributor, run_seccomp_distributor());
    // Kernel seccomp verdicts. `MayRetire` for the same reason as the
    // distributor: `run` returns `Ok(())` immediately when
    // SECCOMP_DENIAL_CAPTURE is off. A kernel that cannot carry the probe
    // does NOT retire — it keeps posting `capturing: false` heartbeats so
    // the broker can tell a blind node from a quiet one.
    //
    // Supervised rather than a bare `tokio::spawn` specifically because
    // tokio swallows a panic in a spawned task. Unsupervised, a panic in
    // the drain loop would end denial capture on this node with no log
    // line at all; the chain downstream still fails safe (no heartbeat →
    // the broker's TTL expires → `Unknown` rather than a false
    // all-clear), but "fails safe and tells nobody why" leaves an
    // operator unable to tell a crashed task from a kernel without the
    // probe. The inner `if let Err` stays: the supervisor's fault report
    // and the task naming what stopped are different messages.
    supervisor.spawn(Subsystem::SeccompDenials, async move {
        let outcome = run_seccomp_denials(
            seccomp_denial_config,
            seccomp_denial_node,
            seccomp_denial_map,
            seccomp_denial_cgroups,
            seccomp_denial_maps_receiver,
        )
        .await;
        if let Err(e) = &outcome {
            tracing::error!(
                error = %e,
                "seccomp denial capture stopped; kernel verdicts are no longer being \
                 reported from this node"
            );
        }
        outcome
    });
    // Compute sampler, `MayRetire` for the same reason as the distributor.
    // With COMPUTE_ENABLED=false there is no sampler; the same roster
    // slot runs a five-minute node-only heartbeat so the broker can show
    // the node as "off" rather than "pending" (D10). The registry may
    // still exist in that case — seccomp denial capture resolves
    // hostNetwork pods through it — which is why `compute_events` and
    // not `compute_map` is what decides: it is subscribed only when the
    // gauges are on.
    match (compute_map, compute_events) {
        (Some(map), Some(events)) => supervisor.spawn(
            Subsystem::ComputeSampler,
            run_compute_sampler(
                compute_config,
                node_name_for_compute,
                map,
                contention_probe,
                events,
            ),
        ),
        _ => supervisor.spawn(
            Subsystem::ComputeSampler,
            run_compute_heartbeat(compute_config, node_name_for_compute),
        ),
    }
    supervisor.spawn(Subsystem::EbpfLoader, async move { ebpf_handle.await? });

    // Graceful shutdown on SIGTERM/SIGINT
    let shutdown = async {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");
        let sigint = tokio::signal::ctrl_c();
        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM, shutting down"),
            _ = sigint => info!("Received SIGINT, shutting down"),
        }
    };

    // Run until a subsystem faults or the kubelet asks us to stop.
    //
    // The watches and the event consumers are infinite by construction,
    // so the shutdown arm is the ordinary way this process ends; the
    // supervision arm is the incident.
    //
    // `Supervisor::watch` is cancel-safe, so losing this select! costs
    // nothing: the tasks live in the JoinSet, not in this future.
    let fault = tokio::select! {
        fault = supervisor.watch() => Some(fault),
        _ = shutdown => None,
    };

    // Stop the eBPF poll loop first, then abort and drain the rest.
    // `shut_down` owns that ordering and explains why it is not
    // negotiable; it is a function rather than two lines here so the
    // sequence is covered by a test (`bpf::tests::
    // the_controller_shutdown_sequence_raises_the_ebpf_flag`) instead
    // of living in `main`, which has none.
    //
    // Draining also recovers faults that were already queued when we
    // aborted. That matters on the fault path: when the eBPF loader
    // dies it closes the event channels on its way out, so a consumer's
    // clean `Ok` can win the race to be reported and the loader's own
    // error would otherwise never be printed at all. On the graceful
    // path the same drain stays quiet, because the poll loop returning
    // `Err` after being told to stop is expected, not an incident.
    let draining = match fault {
        Some(_) => Draining::AfterFault,
        None => Draining::Gracefully,
    };
    let _ = shut_down(&mut supervisor, draining).await;

    match fault {
        // `report` logs the fault and converts it into the error main
        // returns, which is the non-zero exit and the pod restart. Every
        // fault gets that treatment, a clean `Ok(())` retirement
        // included — a subsystem that stopped is a hole in this node's
        // observations whether or not it called it an error, and this
        // DaemonSet has no other way to say so.
        Some(fault) => Err(report(fault)),
        None => {
            info!("Graceful shutdown complete");
            Ok(())
        }
    }
}
