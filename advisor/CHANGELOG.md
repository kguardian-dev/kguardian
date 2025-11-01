# Changelog

All notable changes to the kguardian Advisor (kubectl plugin) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-11-01

### Features

- Initial release of kguardian Advisor kubectl plugin
- Network policy generation from observed traffic
  - Support for standard Kubernetes NetworkPolicy
  - Support for Cilium NetworkPolicy and ClusterwideNetworkPolicy
- Seccomp profile generation from observed syscalls
- Flexible targeting: single pod, all pods in namespace, or all namespaces
- Dry-run mode for preview without applying
- File output for GitOps integration
- SLSA3-attested binaries for supply chain security
- Multi-platform support (linux/darwin, amd64/arm64)

[Unreleased]: https://github.com/kguardian-dev/kguardian/compare/advisor/v1.0.0...HEAD
[1.0.0]: https://github.com/kguardian-dev/kguardian/releases/tag/advisor/v1.0.0
