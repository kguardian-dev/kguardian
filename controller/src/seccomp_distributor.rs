//! Writes broker-generated per-workload seccomp profiles onto this node,
//! under the kubelet's seccomp root, so a workload can reference one with
//! `securityContext.seccompProfile.type: Localhost`.
//!
//! Off by default. Enable with `SECCOMP_DISTRIBUTE=true` (Helm:
//! `seccomp.distribute=true`), which also adds the hostPath mount of the
//! kubelet seccomp directory to the controller pod.
//!
//! Deliberately best-effort: a failed pass logs and retries on the next
//! tick, and a missing seccomp root or a broker outage never propagates
//! an error that would restart the controller and interrupt tracing.
//! Files are written atomically (temp + rename) and never deleted — the
//! filename carries the content hash, so an existing file is already
//! correct and stale hashes simply accumulate (see
//! docs/design/per-workload-seccomp-distribution.md).

use crate::client::api_get_bytes;
use crate::pod_watcher::parse_lenient_bool;
use crate::Error;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Default kubelet seccomp root. Overridable because it is not
/// `/var/lib/kubelet` everywhere (k3s, kubeadm custom, OpenShift) — the
/// same portability concern the containerd socket path already has.
const DEFAULT_SECCOMP_ROOT: &str = "/var/lib/kubelet/seccomp";
const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// A row of `GET /seccomp/profiles`. Only the fields the distributor
/// needs; the broker sends more.
#[derive(Debug, Deserialize)]
struct ProfileSummary {
    namespace: String,
    kind: String,
    name: String,
    hash: String,
    #[serde(rename = "localhostProfile")]
    localhost_profile: String,
}

struct Config {
    root: PathBuf,
    interval: Duration,
}

fn enabled_config() -> Option<Config> {
    let enabled = parse_lenient_bool(
        &std::env::var("SECCOMP_DISTRIBUTE").unwrap_or_default(),
        false,
    );
    if !enabled {
        return None;
    }
    let root = std::env::var("SECCOMP_ROOT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SECCOMP_ROOT.to_string());
    let interval = std::env::var("SECCOMP_DISTRIBUTE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_INTERVAL);
    Some(Config {
        root: PathBuf::from(root),
        interval,
    })
}

/// Task entrypoint. Returns `Ok(())` immediately when disabled or
/// misconfigured — the caller joins this alongside the eBPF tasks, and a
/// distribution problem must never take the controller down.
pub async fn run() -> Result<(), Error> {
    let Some(cfg) = enabled_config() else {
        info!("seccomp profile distribution disabled (set SECCOMP_DISTRIBUTE=true to enable)");
        return Ok(());
    };

    if !cfg.root.is_dir() {
        error!(
            root = %cfg.root.display(),
            "SECCOMP_ROOT is not a directory; seccomp profile distribution is inactive. \
             Set seccomp.kubeletRoot to this node's kubelet root if it is not /var/lib/kubelet."
        );
        return Ok(());
    }

    info!(
        root = %cfg.root.display(),
        interval_secs = cfg.interval.as_secs(),
        "seccomp profile distribution active"
    );

    let mut ticker = tokio::time::interval(cfg.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        match reconcile_once(&cfg).await {
            Ok(stats) => {
                if stats.written > 0 || stats.failed > 0 {
                    info!(
                        written = stats.written,
                        present = stats.present,
                        failed = stats.failed,
                        "seccomp profile distribution pass"
                    );
                } else {
                    debug!(
                        present = stats.present,
                        "seccomp profile distribution pass (no change)"
                    );
                }
            }
            Err(e) => warn!("seccomp profile distribution pass failed (will retry): {e}"),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Stats {
    written: usize,
    present: usize,
    failed: usize,
}

async fn reconcile_once(cfg: &Config) -> Result<Stats, Error> {
    let body = api_get_bytes("seccomp/profiles").await?;
    let profiles: Vec<ProfileSummary> = serde_json::from_slice(&body)
        .map_err(|e| Error::Custom(format!("parsing /seccomp/profiles: {e}")))?;

    let mut stats = Stats::default();
    for p in &profiles {
        let rel = match safe_relative_path(&p.localhost_profile) {
            Some(r) => r,
            None => {
                warn!(path = %p.localhost_profile, "skipping profile with an unsafe path");
                stats.failed += 1;
                continue;
            }
        };
        let dest = cfg.root.join(&rel);
        if dest.exists() {
            // The hash is in the filename, so the bytes on disk are
            // already the right ones.
            stats.present += 1;
            continue;
        }

        let file_path = format!(
            "seccomp/profile-file/{}/{}/{}/{}",
            p.namespace, p.kind, p.name, p.hash
        );
        match api_get_bytes(&file_path).await {
            Ok(json) => match write_atomic(&dest, &json) {
                Ok(()) => {
                    debug!(dest = %dest.display(), "wrote seccomp profile");
                    stats.written += 1;
                }
                Err(e) => {
                    warn!(dest = %dest.display(), "failed to write seccomp profile: {e}");
                    stats.failed += 1;
                }
            },
            Err(e) => {
                warn!(workload = %p.name, "failed to fetch seccomp profile: {e}");
                stats.failed += 1;
            }
        }
    }
    Ok(stats)
}

/// Reduce a broker-supplied `localhostProfile` to a relative path that is
/// safe to join onto the seccomp root: no absolute prefix, no `..`, no
/// `.` or empty components. The broker builds this from DNS-1123 values,
/// but the distributor writes to the host filesystem from a network
/// response — so it is validated here rather than trusted.
fn safe_relative_path(raw: &str) -> Option<PathBuf> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let mut out = PathBuf::new();
    let mut components = 0;
    for comp in Path::new(raw).components() {
        match comp {
            std::path::Component::Normal(c) => {
                let s = c.to_str()?;
                if s == ".." || s.is_empty() {
                    return None;
                }
                out.push(s);
                components += 1;
            }
            // RootDir, Prefix, CurDir, ParentDir are all disallowed.
            _ => return None,
        }
    }
    if components == 0 {
        return None;
    }
    Some(out)
}

/// Write `data` to `dest` atomically: create the parent directory, write
/// to a sibling temp file, then rename over `dest`. A concurrent reader
/// (the kubelet loading the profile) never sees a partial file.
fn write_atomic(dest: &Path, data: &[u8]) -> Result<(), Error> {
    let parent = dest
        .parent()
        .ok_or_else(|| Error::Custom(format!("{} has no parent directory", dest.display())))?;
    std::fs::create_dir_all(parent)?;

    let file_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Custom(format!("{} has no file name", dest.display())))?;
    let tmp = parent.join(format!(".{}.{}.tmp", file_name, std::process::id()));

    // Scope the handle so it is flushed and closed before the rename.
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_relative_path_accepts_a_normal_profile_path() {
        let p = safe_relative_path("kguardian/prod/deployment-web-a1b2c3d4.json").unwrap();
        assert_eq!(
            p,
            PathBuf::from("kguardian/prod/deployment-web-a1b2c3d4.json")
        );
    }

    #[test]
    fn safe_relative_path_rejects_traversal_and_absolute() {
        for bad in [
            "",
            "   ",
            "/etc/passwd",
            "../../../etc/passwd",
            "kguardian/../../../etc/cron.d/x",
            "./kguardian/x.json",
            "kguardian/../x.json",
        ] {
            assert!(
                safe_relative_path(bad).is_none(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn safe_relative_path_normalises_a_harmless_dot_component() {
        // `foo/./bar` carries no traversal — Path::components drops the
        // `.` and the result is the plain relative path.
        assert_eq!(
            safe_relative_path("kguardian/./prod/x.json").unwrap(),
            PathBuf::from("kguardian/prod/x.json")
        );
    }

    #[test]
    fn write_atomic_creates_parents_and_file() {
        let dir = std::env::temp_dir().join(format!("kg-seccomp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dest = dir.join("kguardian/prod/deployment-web-abc.json");
        write_atomic(&dest, br#"{"defaultAction":"SCMP_ACT_LOG"}"#).unwrap();
        let got = std::fs::read(&dest).unwrap();
        assert_eq!(got, br#"{"defaultAction":"SCMP_ACT_LOG"}"#);
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dest.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp file not cleaned up");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_atomic_overwrites_existing() {
        let dir = std::env::temp_dir().join(format!("kg-seccomp-test-ow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dest = dir.join("x.json");
        write_atomic(&dest, b"one").unwrap();
        write_atomic(&dest, b"two").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"two");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn profile_summary_deserialises_from_broker_shape() {
        let json = r#"[{"namespace":"prod","kind":"Deployment","name":"web",
            "hash":"a1b2c3d4","localhostProfile":"kguardian/prod/deployment-web-a1b2c3d4.json",
            "syscallCount":73,"architectures":["SCMP_ARCH_X86_64"],
            "updatedAt":"2026-09-02T00:00:00"}]"#;
        let v: Vec<ProfileSummary> = serde_json::from_str(json).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "web");
        assert_eq!(
            v[0].localhost_profile,
            "kguardian/prod/deployment-web-a1b2c3d4.json"
        );
    }
}
