# kguardian: Kubernetes Security Profile Generator

- **What it does:** Generates least-privilege Kubernetes NetworkPolicies, CiliumNetworkPolicies, and seccomp profiles from observed runtime behavior.
- **Who it's for:** Platform and security teams running Kubernetes who want policy-as-code without writing rules by hand.
- **What it costs to run:** TBD pending benchmark — see [Performance](#performance) for the reference-workload envelope.

[![Go Report Card](https://goreportcard.com/badge/github.com/kguardian-dev/kguardian)](https://goreportcard.com/report/github.com/kguardian-dev/kguardian)
[![License](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](https://mariadb.com/bsl11/)

kguardian watches pod traffic and syscalls with eBPF, then writes Kubernetes NetworkPolicies, CiliumNetworkPolicies, and seccomp profiles from what it sees — no hand-authored rules.

## What is kguardian?

A Kubernetes runtime-observability tool that turns the network and syscall behavior of your pods into the policy YAML you would otherwise have to write by hand.

## What does it do?

The Controller (eBPF DaemonSet) captures every TCP/UDP connection and syscall on each node. The Broker stores the per-pod baseline in PostgreSQL. The `kubectl kguardian` plugin queries that baseline and synthesizes a least-privilege policy for the pod, namespace, or whole cluster you ask about.

## What does it generate?

For each target you select, kguardian emits:

- a Kubernetes [`NetworkPolicy`](docs/policy-gallery/) YAML,
- a Cilium [`CiliumNetworkPolicy`](docs/policy-gallery/) YAML (for Cilium CNI users),
- a [seccomp](docs/policy-gallery/) JSON profile.

Worked examples for nginx, Postgres, kube-dns, Prometheus, an Istio sidecar, and a Go microservice are in the [Generated Policy Gallery](docs/policy-gallery/).

## Distro Compatibility

kguardian's eBPF Controller requires Linux kernel **6.2 or newer** on every node that runs the DaemonSet. Verify with `uname -r` per node before installing.

| Distro | Default kernel | Compatible? |
|---|---|---|
| Ubuntu 24.04 | 6.8 | ✅ |
| Ubuntu 22.04 | 5.15 | ❌ (need HWE 6.2+) |
| RHEL 9 | 5.14 | ❌ |
| Amazon Linux 2023 | 6.1 | ❌ |
| Debian 12 | 6.1 | ❌ (need backports) |
| Talos / Bottlerocket | usually 6.1+ | check distro version |

Kernel versions reflect the GA/server defaults shipped by each distro as of May 2026. Newer kernels are typically available via opt-in channels (Ubuntu HWE, AL2023 kernel-6.12+ AMI, Debian backports, RHEL 9 kernel modules from third parties).

## Features

- **Network Policy Generation:** Least-privilege Kubernetes `NetworkPolicy` and Cilium `CiliumNetworkPolicy` / `CiliumClusterwideNetworkPolicy` resources from observed pod-to-pod traffic.
- **Seccomp Profile Generation:** Per-container syscall allowlists derived from runtime traces.
- **Targeting:** Generate per-pod, per-namespace, or cluster-wide.
- **Dry-Run Default:** YAML is written to `--output-dir` and not applied unless you pass `--dry-run=false` (NetworkPolicies only).
- **File Output:** YAML/JSON files for review or GitOps pipelines.
- Optional natural-language LLM bridge for querying traffic/syscall data — see [docs/ai-assistant](docs/ai-assistant/).

## Comparison with Other Tools

How kguardian compares to Inspektor Gadget and Security Profiles Operator (NetworkPolicy support, seccomp generation, operational model, …): see the [feature comparison table](https://docs.kguardian.dev/#comparison-with-other-tools) on the docs site.

## Performance

Measured on `<reference workload, e.g., 100 pods doing typical web traffic on a 3-node cluster of m6i.large nodes>`:

- Controller (eBPF DaemonSet): `<X>%` CPU, `<Y>` MiB memory per node.
- Broker: `<X>` MiB memory; `<Y>` req/s sustained.
- Storage growth: `<Z>` GiB / 1000 pods / day.

_Numbers are TODO — pending benchmark on a reference cluster._

## Prerequisites

- Linux Kernel 6.2+ on every node running the Controller DaemonSet
- Kubernetes cluster v1.19+
- `kubectl` v1.19+
- The Controller **MUST** be installed and running in the cluster to collect the necessary data
- (For Seccomp) Linux Kernel supporting seccomp (most modern kernels)

## Installation

Install the Controller, Broker, and UI into your cluster, then install the `kubectl` plugin:

```bash
helm install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --version 1.9.1 --namespace kguardian --create-namespace
sh -c "$(curl -fsSL https://raw.githubusercontent.com/kguardian-dev/kguardian/main/scripts/quick-install.sh)"
```

Krew, manual download, custom Helm values, Kind setup, verification, upgrades, and uninstall are all covered in the [Installation Guide](https://docs.kguardian.dev/installation).

## Quick Start

Once the Controller is running and collecting data, you can generate policies. For curated examples of what the generator produces against representative workloads (nginx, Postgres, kube-dns, Prometheus, Istio sidecar, Go microservice), see the [Generated Policy Gallery](docs/policy-gallery/).

1.  **Generate a Network Policy (Dry Run, Save to File):**

    ```bash
    # Generate for a specific pod in the 'default' namespace
    kubectl kguardian gen networkpolicy my-pod -n default --output-dir ./policies

    # Generate for all pods in the 'staging' namespace
    kubectl kguardian gen networkpolicy --all -n staging --output-dir ./policies
    ```

2.  **Generate a Seccomp Profile (Save to File):**

    ```bash
    # Generate for a specific pod in the 'default' namespace
    kubectl kguardian gen seccomp my-pod -n default --output-dir ./seccomp

    # Generate for all pods in all namespaces
    kubectl kguardian gen seccomp -A --output-dir ./seccomp
    ```

3.  **Review** the generated YAML files in the specified output directories.

4.  **(Optional) Apply the policies:** `--dry-run=true` is the default and only writes YAML to `--output-dir`. To apply network policies, either re-run with `--dry-run=false` or run `kubectl apply -f <directory>` against the saved files. *Note: Seccomp profiles currently only support saving to files.*

## Usage

The plugin follows the standard `kubectl` command structure:

```bash
kubectl kguardian [command] [subcommand] [flags]
```

### Global Flags

These flags are available for most commands:

- `--kubeconfig <path>`: Path to the kubeconfig file to use.
- `--context <name>`: The name of the kubeconfig context to use.
- `--namespace <name>`, `-n <name>`: The namespace scope for this CLI request.
- `--debug`: Enable debug logging.

### Generate Resources (`gen`)

This is the main command group for generating security resources.

#### Network Policies (`networkpolicy`, `netpol`)

Generates Kubernetes or Cilium Network Policies based on observed traffic.

**Usage:**

```bash
kubectl kguardian gen networkpolicy [pod-name] [flags]
```

**Arguments:**

- `[pod-name]` (Optional): The name of the specific pod to generate a policy for. Required unless `-a` or `-A` is used.

**Flags:**

- `-n, --namespace <string>`: Namespace scope (defaults to current context namespace if not `-A`).
- `-a, --all`: Generate policies for all pods in the specified/current namespace.
- `-A, --all-namespaces`: Generate policies for all pods in all namespaces.
- `-t, --type <string>`: Type of policy: `kubernetes` (default) or `cilium`.
- `--output-dir <string>`: Directory to save generated policies (default: `network-policies`). If empty, policies are only printed in dry-run mode.
- `--dry-run`: If true (default), generate policies and save/print them without applying to the cluster. Set to `false` to apply Kubernetes policies directly.

**Examples:**

```bash
# Generate Kubernetes policy for 'my-app-pod' in 'prod' namespace (dry-run, save to ./netpols)
kubectl kguardian gen networkpolicy my-app-pod -n prod --output-dir ./netpols

# Generate Cilium policies for all pods in 'dev' namespace (dry-run, save to ./cilium-pols)
kubectl kguardian gen netpol --all -n dev --type cilium --output-dir ./cilium-pols

# Generate and APPLY Kubernetes policies for all pods in all namespaces (save to default dir)
kubectl kguardian gen netpol -A --dry-run=false

# Generate Kubernetes policy for 'my-pod' (dry-run, print to stdout only)
kubectl kguardian gen netpol my-pod --output-dir=""
```

#### Seccomp Profiles (`seccomp`, `secp`)

Generates Seccomp profiles based on observed syscalls.

**Usage:**

```bash
kubectl kguardian gen seccomp [pod-name] [flags]
```

**Arguments:**

- `[pod-name]` (Optional): The name of the specific pod to generate a profile for. Required unless `-a` or `-A` is used.

**Flags:**

- `-n, --namespace <string>`: Namespace scope (defaults to current context namespace if not `-A`).
- `-a, --all`: Generate profiles for all pods in the specified/current namespace.
- `-A, --all-namespaces`: Generate profiles for all pods in all namespaces.
- `--output-dir <string>`: Directory to save generated profiles (default: `seccomp-profiles`). *Required for seccomp.* `--default-action <string>`: Default action for unlisted syscalls (default: `SCMP_ACT_ERRNO`). Options: `SCMP_ACT_ERRNO`, `SCMP_ACT_LOG`, `SCMP_ACT_KILL`.

**Examples:**

```bash
# Generate seccomp profile for 'db-pod' in 'data' namespace (save to ./secp)
kubectl kguardian gen seccomp db-pod -n data --output-dir ./secp

# Generate seccomp profiles for all pods in 'staging' namespace (save to default dir)
kubectl kguardian gen secp --all -n staging

# Generate seccomp profiles for all pods in all namespaces, logging unlisted calls (save to ./all-secp)
kubectl kguardian gen secp -A --default-action SCMP_ACT_LOG --output-dir ./all-secp
```

## Contributing

Contributions are welcome. Please read the contributing guide (TODO: Create CONTRIBUTING.md) to get started.

For information on the release process and versioning strategy, see [RELEASES.md](RELEASES.md).

## License

This project is licensed under the Business Source License 1.1 — see the [LICENSE](LICENSE) file for details.

**Summary:**
- **Free for:** Development, testing, evaluation, and non-production/non-commercial use
- **Commercial use:** Requires a commercial license (contact the licensors)
- **Converts to:** Apache License 2.0 on January 1, 2029
