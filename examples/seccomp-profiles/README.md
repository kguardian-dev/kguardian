# Seccomp profile examples

Sample `SeccompProfile` manifests and the workloads that use them, in the
shape kguardian exports and distributes.

> **These are samples. Do not copy the syscall lists.** A seccomp allowlist
> only holds for the binary, libc, configuration and code paths it was
> recorded from. Generate your own profile with kguardian from the workload's
> observed syscalls (a `full` capture tier, under representative load), then
> review it and commit it.

## Files

| File | What it shows |
|------|---------------|
| [`web-service-audit.yaml`](web-service-audit.yaml) | An nginx Deployment's profile as the Broker exports it: `defaultAction: SCMP_ACT_LOG`, one sorted `SCMP_ACT_ALLOW` rule, capture annotations and `workloadRef`. This is the audit-first stage. |
| [`web-service.yaml`](web-service.yaml) | The same profile after promotion to `SCMP_ACT_ERRNO`, with hand-written comments on why each unusual syscall is there. |
| [`batch-job.yaml`](batch-job.yaml) | A stricter profile for a CronJob running a static Go binary: 38 syscalls and `SCMP_ACT_KILL_PROCESS`. |
| [`workloads.yaml`](workloads.yaml) | The Deployment and CronJob referencing those profiles with `seccompProfile.type: Localhost`. |
| [`runtime-default.yaml`](runtime-default.yaml) | The same Deployment on `RuntimeDefault`, the baseline to compare against and to fall back to. |
| [`node-files/kguardian/`](node-files/kguardian/) | The exact JSON a kguardian Controller writes on each node for `web-service.yaml` and `batch-job.yaml`, laid out as under `<kubeletRoot>/seccomp/`. |

`web-service-audit.yaml` and `web-service.yaml` are two stages of the same
object (`prod/deployment-web`). The same goes for `workloads.yaml` and
`runtime-default.yaml` (`prod/web`). Apply one of each pair.

## How kguardian produces and places a profile

1. **Capture.** The Controller's eBPF probe records each pod's syscalls at the
   cluster's capture tier (`syscalls.captureLevel`, default `full`). Only
   `full` yields a profile that is safe to enforce; a lower tier is marked
   partial in the export header and in the CR's `CaptureComplete` condition.
2. **Review.** The Broker keeps a union of every syscall seen per workload
   (ReplicaSet to Deployment, Job to CronJob). You can see it in the UI's
   Workloads view (seccomp columns) or at `GET /seccomp/profiles`.
3. **Export.** `GET /seccomp/profiles/{namespace}/{kind}/{name}/export`
   returns the `SeccompProfile` YAML. The default action is `SCMP_ACT_LOG`;
   `?defaultAction=` and `?name=` override it.
4. **Commit and apply.** kguardian never applies a profile or edits a workload
   on its own. You apply the CR yourself, by hand or through GitOps.
5. **Distribute.** With `seccomp.distribute: true` in the chart, every
   Controller renders the CR to
   `<kubeletRoot>/seccomp/kguardian/<namespace>/<name>.json` (default
   `kubeletRoot` is `/var/lib/kubelet`) and reports per-node readiness in the
   CR's status. A watch picks up changes immediately.
   `seccomp.distributeIntervalSeconds` sets the full resync period (default 30).
6. **Reference.** Add
   `seccompProfile: {type: Localhost, localhostProfile: kguardian/<namespace>/<name>.json}`
   to the pod template once. The CR name is the file name, so the reference
   survives edits to the profile.
7. **Promote.** Change `defaultAction` to `SCMP_ACT_ERRNO` (or a `KILL`
   action) once the CR shows `DenialsObserved: False` with
   `status.denials.observed: 0`.

```yaml
# values.yaml
seccomp:
  distribute: true
  kubeletRoot: /var/lib/kubelet   # k3s: /var/lib/rancher/k3s/agent/kubelet
```

## Audit first, then enforce

Start every profile in `SCMP_ACT_LOG`, which is what the export gives you. In
that mode the kernel allows every syscall and logs the ones outside the list.
kguardian's `audit_seccomp` kprobe reads those records back and shows them as:

- the CR's `DenialsObserved` condition and `status.denials`;
- `GET /seccomp/denials` on the Broker (per event, live);
- the `kguardian_seccomp_denials_total` metric and the
  `KguardianSeccompDenialsObserved` alert.

```bash
kubectl apply -f web-service-audit.yaml
kubectl -n prod get seccompprofile deployment-web     # wait for READY n/n
kubectl apply -f workloads.yaml
# ...run a full usage cycle; for a CronJob, several scheduled runs...
kubectl -n prod get seccompprofile deployment-web -o json \
  | jq '{c: (.status.conditions[] | select(.type=="DenialsObserved")), d: .status.denials}'
```

Promote only on an explicit `False` with `observed: 0`. `Unknown`, or an
absent `status.denials`, means "no data", not "clean". Then apply the
enforcing version and restart the pods, because the kubelet loads the profile
at container start:

```bash
kubectl apply -f web-service.yaml
kubectl -n prod rollout restart deployment/web
```

An enforcing profile rendered by kguardian carries
`"flags": ["SECCOMP_FILTER_FLAG_LOG"]` (see `node-files/`), so `SCMP_ACT_ERRNO`
denials are still audited and the denial signal keeps working after
promotion. A hand-written profile applied outside kguardian without that flag
blocks without leaving an audit record.

## Syscall lists and architectures

Both samples cover `SCMP_ARCH_X86_64` and `SCMP_ARCH_AARCH64`, as an export
does for a workload that ran on amd64 and arm64 nodes. The list is the union
of both. Every name was checked against libseccomp's syscall table (the same
library the Controller uses to resolve syscall numbers):

- Most names exist on both architectures. That includes the startup
  syscalls: `execve` (the runtime execs the entrypoint after installing the
  filter), `mmap`, `futex`, `clone`, `rt_sigaction` and `rt_sigprocmask` in
  both profiles, plus what glibc and its dynamic loader add for nginx: `brk`,
  `mprotect`, `set_tid_address`, `set_robust_list`, `rseq` and `clone3`. The
  static Go binary has no dynamic loader and uses its own runtime instead, so
  its list has `sigaltstack`, `sched_yield` and `tgkill` in their place.
- A few are legacy x86_64-only syscalls: `access`, `arch_prctl`, `chown`,
  `dup2`, `epoll_create`, `epoll_wait`, `mkdir` and `pipe` (only `arch_prctl`
  in the Go batch job). aarch64 never had them, and libc calls the `*at`,
  `dup3`, `pipe2`, `epoll_create1` and `epoll_pwait` forms instead. They
  appear in the list because the x86_64 pods called them. runc and crun skip
  a name that the architecture does not define, which is also how the
  runtimes' own default profiles share one list across architectures.

The CR also accepts `SCMP_ARCH_ARM64` so older manifests keep validating, but
no runtime understands it and the Controller writes it to the node file as
`SCMP_ARCH_AARCH64`. Use `SCMP_ARCH_AARCH64` in new manifests.

## Without the CR

`kubectl kguardian gen seccomp <pod> --default-action SCMP_ACT_LOG` writes the
same allowlist as plain seccomp JSON for a single pod. You can place that file
under `<kubeletRoot>/seccomp/` on each node yourself.

## Further reading

- [Seccomp profiles concept](https://docs.kguardian.dev/concepts/seccomp-profiles)
- [Distributing seccomp profiles](https://docs.kguardian.dev/guides/distributing-seccomp-profiles)
- [`SeccompProfile` CRD reference](https://docs.kguardian.dev/reference/crds/seccompprofile)
- [Seccomp API](https://docs.kguardian.dev/api-reference/endpoints/seccomp)
