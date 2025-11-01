# kguardian: Kubernetes Security Profile Generator

[![Go Report Card](https://goreportcard.com/badge/github.com/kguardian-dev/kguardian)](https://goreportcard.com/report/github.com/kguardian-dev/kguardian)
[![License](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](https://mariadb.com/bsl11/)

kguardian is a powerful Kubernetes security toolkit that analyzes runtime behavior using eBPF and generates tailored security resources like Network Policies and Seccomp Profiles.

## Table of Contents
- [kguardian: Kubernetes Security Profile Generator](#kguardian-kubernetes-security-profile-generator)
  - [Table of Contents](#table-of-contents)
  - [🌟 Features](#-features)
  - [🛠️ Prerequisites](#️-prerequisites)
  - [📦 Installation](#-installation)
    - [Quick Install Script](#quick-install-script)
    - [Krew (Recommended)](#krew-recommended)
    - [Manual Download](#manual-download)
  - [🚀 Quick Start](#-quick-start)
  - [🔨 Usage](#-usage)
    - [Global Flags](#global-flags)
    - [Generate Resources (`gen`)](#generate-resources-gen)
      - [🔒 Network Policies (`networkpolicy`, `netpol`)](#-network-policies-networkpolicy-netpol)
      - [🛡️ Seccomp Profiles (`seccomp`, `secp`)](#️-seccomp-profiles-seccomp-secp)
  - [🤝 Contributing](#-contributing)
  - [📄 License](#-license)

## 🌟 Features

*   **Network Policy Generation:** Automatically create least-privilege network policies based on observed pod communication.
    *   Supports standard Kubernetes `NetworkPolicy` resources.
    *   Supports `CiliumNetworkPolicy` and `CiliumClusterwideNetworkPolicy` for Cilium CNI users.
*   **Seccomp Profile Generation:** Generate least-privilege seccomp profiles by analyzing syscalls used by containers.
*   **Flexible Targeting:** Generate policies/profiles for single pods, all pods in a namespace, or all pods across all namespaces.
*   **Dry-Run Mode:** Preview generated resources without applying them to the cluster.
*   **File Output:** Save generated resources to YAML files for review or integration into GitOps workflows.

## Comparison with Other Tools

This table provides a high-level comparison of kguardian with other popular open-source tools in the Kubernetes security space. The landscape evolves quickly, so features may change.

| Feature                       | kguardian                         | Inspektor Gadget                   | Security Profiles Operator (SPO) |
| :---------------------------- | :-------------------------------- | :--------------------------------- | :------------------------------- |
| **Network Policy (K8s)**      | ✅                                | ✅ (Network Policy Advisor)        | ❌                               |
| **Network Policy (Cilium)**   | ✅                                | ❌                                 | ❌                               |
| **Seccomp Profile Generation**| ✅                                | 📝 (Provides syscall trace data)   | ✅ (Via Log Enricher/Recorder)   |
| **AppArmor Profile Mgmt**     | ❌                                | ❌                                 | ✅                               |
| **SELinux Profile Mgmt**      | ❌                                | ❌                                 | ✅                               |
| **Data Source**               | kguardian Controller (eBPF)      | eBPF                             | Seccomp Logs / BPF Recorder    |
| **Operational Model**         | Client CLI + Server Controller    | Client CLI + Server Gadgets      | Server Operator + CRDs         |
| **Dry Run / Preview**         | ✅ (NetPol)                       | ✅ (YAML output for advisor)       | N/A                              |
| **Save to File**              | ✅ (NetPol, Seccomp)              | ✅ (YAML output for advisor)       | N/A (Uses CRDs)                  |
| **Direct Apply (NetPol)**     | ✅                                | ❌                                 | N/A                              |
| **Direct Apply (Seccomp)**    | ❌                                | ❌                                 | ✅                               |

*Legend: ✅ = Supported, ❌ = Not Supported, 📝 = Partial/Requires Manual Steps, N/A = Not Applicable*

**Note on Operational Models:** kguardian and Inspektor Gadget use client CLIs that interact with dedicated server-side components (Controller/Gadgets) primarily for data retrieval. SPO operates as a full Kubernetes operator managing security profiles via Custom Resource Definitions (CRDs).

**Key Differentiators for kguardian:**
*   Generates both Network Policies (K8s Native & Cilium) and Seccomp profiles from a single data source.
*   Provides options for direct application (Network Policy) or saving to files for GitOps workflows.

## 🛠️ Prerequisites

*   Linux Kernel 6.2+
*   Kubernetes cluster v1.19+
*   `kubectl` v1.19+
*   kguardian Controller **MUST** be installed and running in the cluster to collect the necessary data.
*   (For Seccomp) Linux Kernel supporting seccomp (most modern kernels).

## 📦 Installation

Choose one of the following methods:

### Quick Install Script

This script downloads the latest release binary and attempts to install it.

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/kguardian-dev/kguardian/main/scripts/quick-install.sh)"
```

### Krew (Recommended)

Use [Krew](https://krew.sigs.k8s.io/), the plugin manager for `kubectl`:

```bash
# Ensure Krew is installed: https://krew.sigs.k8s.io/docs/user-guide/setup/install/
kubectl krew install kguardian
```

### Manual Download

Download the appropriate binary for your system from the [Releases page](https://github.com/kguardian-dev/kguardian/releases) and place it in your `PATH` named `kubectl-kguardian`.

Example (Linux AMD64, replace version/binary name as needed):

```bash
# Replace with the correct release URL
wget -O kguardian https://github.com/kguardian-dev/kguardian/releases/download/vX.Y.Z/kguardian-linux-amd64
chmod +x kguardian
sudo mv kguardian /usr/local/bin/kubectl-kguardian

# Verify installation
kubectl kguardian --help
```

## 🚀 Quick Start

Once the kguardian controller is running and collecting data, you can generate policies.

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

4.  **(Optional) Apply the policies:** If satisfied after reviewing the files or the dry-run output, remove `--dry-run` (for network policies) or manually apply the saved YAML files using `kubectl apply -f <directory>`. *Note: Seccomp profiles currently only support saving to files.* ## 🔨 Usage

The plugin follows the standard `kubectl` command structure:

```bash
kubectl kguardian [command] [subcommand] [flags]
```

### Global Flags

These flags are available for most commands:

*   `--kubeconfig <path>`: Path to the kubeconfig file to use.
*   `--context <name>`: The name of the kubeconfig context to use.
*   `--namespace <name>`, `-n <name>`: The namespace scope for this CLI request.
*   `--debug`: Enable debug logging.

### Generate Resources (`gen`)

This is the main command group for generating security resources.

#### 🔒 Network Policies (`networkpolicy`, `netpol`)

Generates Kubernetes or Cilium Network Policies based on observed traffic.

**Usage:**

```bash
kubectl kguardian gen networkpolicy [pod-name] [flags]
```

**Arguments:**

*   `[pod-name]` (Optional): The name of the specific pod to generate a policy for. Required unless `-a` or `-A` is used.

**Flags:**

*   `-n, --namespace <string>`: Namespace scope (defaults to current context namespace if not `-A`).
*   `-a, --all`: Generate policies for all pods in the specified/current namespace.
*   `-A, --all-namespaces`: Generate policies for all pods in all namespaces.
*   `-t, --type <string>`: Type of policy: `kubernetes` (default) or `cilium`.
*   `--output-dir <string>`: Directory to save generated policies (default: `network-policies`). If empty, policies are only printed in dry-run mode.
*   `--dry-run`: If true (default), generate policies and save/print them without applying to the cluster. Set to `false` to apply Kubernetes policies directly.

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

#### 🛡️ Seccomp Profiles (`seccomp`, `secp`)

Generates Seccomp profiles based on observed syscalls.

**Usage:**

```bash
kubectl kguardian gen seccomp [pod-name] [flags]
```

**Arguments:**

*   `[pod-name]` (Optional): The name of the specific pod to generate a profile for. Required unless `-a` or `-A` is used.

**Flags:**

*   `-n, --namespace <string>`: Namespace scope (defaults to current context namespace if not `-A`).
*   `-a, --all`: Generate profiles for all pods in the specified/current namespace.
*   `-A, --all-namespaces`: Generate profiles for all pods in all namespaces.
*   `--output-dir <string>`: Directory to save generated profiles (default: `seccomp-profiles`). *Required for seccomp.* `--default-action <string>`: Default action for unlisted syscalls (default: `SCMP_ACT_ERRNO`). Options: `SCMP_ACT_ERRNO`, `SCMP_ACT_LOG`, `SCMP_ACT_KILL`.

**Examples:**

```bash
# Generate seccomp profile for 'db-pod' in 'data' namespace (save to ./secp)
kubectl kguardian gen seccomp db-pod -n data --output-dir ./secp

# Generate seccomp profiles for all pods in 'staging' namespace (save to default dir)
kubectl kguardian gen secp --all -n staging

# Generate seccomp profiles for all pods in all namespaces, logging unlisted calls (save to ./all-secp)
kubectl kguardian gen secp -A --default-action SCMP_ACT_LOG --output-dir ./all-secp
```

## 🤝 Contributing

Contributions are welcome! Please read the contributing guide (TODO: Create CONTRIBUTING.md) to get started.

For information on the release process and versioning strategy, see [RELEASES.md](RELEASES.md).

## 📄 License

This project is licensed under the Business Source License 1.1 - see the [LICENSE](LICENSE) file for details.

**Summary:**
- **Free for:** Development, testing, evaluation, and non-production/non-commercial use
- **Commercial use:** Requires a commercial license (contact the licensors)
- **Converts to:** Apache License 2.0 on January 1, 2029
