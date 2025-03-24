# Xentra: Advisor for Kubernetes

Xentra is a powerful kubectl plugin designed to enhance the security of your Kubernetes clusters. The Advisor component allows users to automatically generate crucial security resources like Network Policies, Seccomp Profiles, and more for Kubernetes pods or services.

## Table of Contents
- [Xentra: Advisor for Kubernetes](#xentra-advisor-for-kubernetes)
  - [Table of Contents](#table-of-contents)
  - [🌟 Features](#-features)
  - [🛠️ Prequisites](#️-prequisites)
  - [📦 Installation](#-installation)
  - [🔨 Usage](#-usage)
    - [🔒 Generate Network Policies](#-generate-network-policies)
      - [Kubernetes Network Policies](#kubernetes-network-policies)
      - [Cilium Network Policies](#cilium-network-policies)
  - [🤝 Contributing](#-contributing)
  - [📄 License](#-license)
  - [🙏 Acknowledgments](#-acknowledgments)

## 🌟 Features

WIP

## 🛠️ Prequisites

- Linux Kernel 6.2+
- Kubernetes 1.19+
- kubectl v1.18+
- [Kube Guardian](https://github.com/xentra-ai/kube-guardian/tree/main/charts/kube-guardian) **MUST** be running in-cluster

## 📦 Installation

There are several options to install the advisor client.

To use the quick install use the following command:

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/xentra-ai/kube-guardian/main/scripts/quick-install.sh)"
```

You can also install Xentra via Krew, the plugin manager for kubectl:

```bash
kubectl krew install xentra
```

Or manually download the release and place it in your PATH:

Example:

```bash
# Download the release and set it as executable
wget -O advisor https://github.com/xentra-ai/kube-guardian/releases/download/v0.0.4/advisor-linux-amd64
chmod +x advisor
sudo mv advisor /usr/local/bin/kubectl-advisor
```

## 🔨 Usage

### 🔒 Generate Network Policies

Xentra can generate both Kubernetes native NetworkPolicies and Cilium CiliumNetworkPolicies.

#### Kubernetes Network Policies

Create a Kubernetes network policy for a single pod in a namespace:

```bash
kubectl advisor gen networkpolicy [pod-name] --namespace [namespace-name]
```

Create a Kubernetes network policy for all pod(s) in a namespace:

```bash
kubectl advisor gen networkpolicy --namespace [namespace-name] --all
```

Create a Kubernetes network policy for all pod(s) in all namespace(s):

```bash
kubectl advisor gen networkpolicy -A
```

#### Cilium Network Policies

Create a Cilium network policy for a single pod in a namespace:

```bash
kubectl advisor gen networkpolicy [pod-name] --namespace [namespace-name] --type cilium
```

Create a Cilium network policy for all pod(s) in a namespace:

```bash
kubectl advisor gen networkpolicy --namespace [namespace-name] --all --type cilium
```

Create a Cilium network policy for all pod(s) in all namespace(s):

```bash
kubectl advisor gen networkpolicy -A --type cilium
```

For more details on the commands:

```bash
kubectl advisor --help
```

## 🤝 Contributing

Contributions are welcome! Please read the contributing guide to get started.

## 📄 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Thanks to the Kubernetes community for the excellent tools and libraries.
