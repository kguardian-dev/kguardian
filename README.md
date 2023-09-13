# ARX: Advisor for Kubernetes

ARX is a powerful kubectl plugin designed to enhance the security of your Kubernetes clusters. The Advisor component allows users to automatically generate crucial security resources like Network Policies, Seccomp Profiles, and more for Kubernetes pods or services.

## Table of Contents
- [ARX: Advisor for Kubernetes](#arx-advisor-for-kubernetes)
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

You can install ARX via Krew, the plugin manager for kubectl:

```bash
kubectl krew install arx
```

Or manually download the release and place it in your PATH:

```bash
# Download the release and set it as executable
wget https://github.com/arx-inc/advisor/releases/download/v1.0.0/arx
chmod +x arx
mv arx /usr/local/bin/
```

## 🔨 Usage

### 🔒 Generate Network Policies

```bash
kubectl arx gen networkpolicy [pod-name] --namespace my-namespace
```

### 🛡️ Generate Seccomp Profiles

```bash
kubectl arx gen seccomp [pod-name] --namespace my-namespace
```

For more details on the commands:

```bash
kubectl arx --help
```

## 🤝 Contributing

Contributions are welcome! Please read the contributing guide to get started.

## 📄 License

This project is licensed under the [PLACEHOLDER] License - see the [LICENSE.md](LICENSE.md) file for details.

## 🙏 Acknowledgments

Thanks to the Kubernetes community for the excellent tools and libraries.
