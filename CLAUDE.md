# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Architecture

Kube Guardian is a Kubernetes security profile enhancer with three main components:

1. **Advisor** (`advisor/`) - Go-based kubectl plugin that generates Network Policies and Seccomp profiles
   - CLI tool using Cobra framework
   - Generates Kubernetes and Cilium Network Policies from observed traffic
   - Creates Seccomp profiles from syscall analysis
   - Main entry point: `advisor/main.go`

2. **Controller** (`controller/`) - Rust-based eBPF data collector
   - Runs as DaemonSet to collect runtime behavior data
   - Uses eBPF to monitor network traffic and syscalls
   - Sends data to the Broker component

3. **Broker** (`broker/`) - Rust-based data processing service
   - Receives and processes data from Controllers
   - Provides API endpoints for the Advisor to query
   - Stores collected security data

## Commands

### Build and Development
```bash
# Build all components
task all

# Run preflight checks for all components
task preflight

# Create fresh KinD cluster for development
task kind

# Install in KinD cluster after building
task install
```

### Component-specific builds
```bash
# Advisor (Go)
task advisor:all

# Controller (Rust with cross-compilation)
task controller:all

# Broker (Rust)
task broker:all
```

### Testing
```bash
# Run Go tests for advisor
cd advisor && go test ./...

# Run individual test files
cd advisor && go test ./pkg/network/
```

### Prerequisites Check
```bash
# Check all required tools
task preflight

# Check individual component requirements
task advisor:preflight   # Requires: go, golangci-lint
task controller:preflight # Requires: cargo, cross, docker, kind, helm
task broker:preflight    # Requires: docker, kind
```

## Key Directories

- `advisor/` - Go CLI tool with packages for K8s integration, network policy generation, and seccomp profiles
- `controller/` - Rust eBPF controller
- `broker/` - Rust data broker service
- `charts/kube-guardian/` - Helm chart for deployment
- `.taskfiles/` - Task definitions for each component

## Usage Patterns

The Advisor generates security policies by:
1. Querying the Broker for collected runtime data via port-forward
2. Processing traffic patterns and syscall data
3. Generating least-privilege Network Policies or Seccomp profiles
4. Supporting both dry-run preview and direct application

Network Policy types supported:
- Standard Kubernetes NetworkPolicy
- CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy

Example usage:
```bash
kubectl xentra gen networkpolicy my-pod -n default --output-dir ./policies
kubectl xentra gen seccomp my-pod -n default --output-dir ./seccomp
```