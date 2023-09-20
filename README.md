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
    - [🛡️ Generate Seccomp Profiles](#️-generate-seccomp-profiles)
  - [🤝 Contributing](#-contributing)
  - [📄 License](#-license)
  - [🙏 Acknowledgments](#-acknowledgments)

## 🌟 Features

WIP

## 🛠️ Prequisites

- Kubernetes cluster v1.18+
- kubectl v1.18+

## 📦 Installation

You can install Xentra via Krew, the plugin manager for kubectl:

```bash
kubectl krew install xentra
```

Or manually download the release and place it in your PATH:

```bash
# Download the release and set it as executable
wget https://github.com/xentra-ai/advisor/releases/download/v0.0.1/xentra
chmod +x xentra
mv xentra /usr/local/bin/
```

## 🔨 Usage

### 🔒 Generate Network Policies

```bash
kubectl xentra gen networkpolicy [pod-name] --namespace [namespace-name]
```

### 🛡️ Generate Seccomp Profiles

```bash
kubectl xentra gen seccomp [pod-name] --namespace [namespace-name]
```

For more details on the commands:

```bash
kubectl xentra --help
```

## 🤝 Contributing

Contributions are welcome! Please read the contributing guide to get started.

## 📄 License

This project is licensed under the [PLACEHOLDER] License - see the [LICENSE.md](LICENSE.md) file for details.

## 🙏 Acknowledgments

Thanks to the Kubernetes community for the excellent tools and libraries.
