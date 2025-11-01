# Changelog

All notable changes to the kguardian Helm Chart will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-11-01

### Features

- Initial v1.0.0 release of kguardian Helm chart
- Complete deployment of all kguardian components:
  - Controller DaemonSet with eBPF capabilities
  - Broker API server deployment
  - PostgreSQL database deployment
  - UI web interface deployment
- Comprehensive configuration via values.yaml
- Support for component-specific version pinning
- Security contexts and RBAC for all components
- Service accounts with configurable automount
- Configurable resource limits and requests
- Node selectors, tolerations, and affinity rules
- Autoscaling support for broker and UI
- Persistent volume support for database
- Health probes for all components
- Namespace filtering configuration
- Image pull secrets support

[Unreleased]: https://github.com/kguardian-dev/kguardian/compare/chart/v1.0.0...HEAD
[1.0.0]: https://github.com/kguardian-dev/kguardian/releases/tag/chart/v1.0.0
