# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

kguardian is a Kubernetes security tool consisting of four main components that work together to enhance security profiles for Kubernetes applications:

1. **Controller** (Rust + eBPF): Runs as a DaemonSet, uses eBPF programs to monitor network traffic and syscalls at the kernel level
2. **Broker** (Rust + Actix-web): REST API server that stores collected telemetry data in PostgreSQL
3. **CLI** (Go): kubectl plugin that generates Network Policies and Seccomp profiles from observed runtime behavior
4. **UI** (React + TypeScript): Modern web interface for visualizing network traffic and pod connections in real-time

The system works by: Controller monitors pods via eBPF → sends data to Broker → CLI generates policies / UI visualizes data.

## Build and Development Commands

This project uses [Task](https://taskfile.dev/) for build orchestration. All commands use `task` (not `make`).

### Prerequisites Check
```bash
task preflight           # Check all dependencies
task advisor:preflight   # Check Go and golangci-lint
task broker:preflight    # Check Docker and Kind
task controller:preflight # Check Cargo, cross, Docker, Kind, Helm
task ui:preflight        # Check Node.js and npm
```

Required tools:
- **Controller**: Rust, Cargo, `cross` (for cross-compilation), Docker, Kind, Helm, Linux Kernel 6.2+
- **Broker**: Docker, Kind, PostgreSQL (via Docker)
- **Advisor**: Go 1.x, golangci-lint
- **UI**: Node.js 20+, npm

### Build Commands
```bash
# Build individual components
task controller:build    # Cross-compiles Rust with eBPF, builds Docker image, loads into Kind
task broker:build        # Builds Docker image, loads into Kind
task advisor:install     # Installs Go binary
task ui:build           # Builds React app for production
task ui:docker          # Builds UI Docker image and loads into Kind

# Build all (controller + broker)
task all                 # Builds broker and controller, creates fresh Kind cluster
```

### Testing and Development
```bash
# For Controller (Rust)
cd controller
cargo test               # Run tests
cargo build --release --target x86_64-unknown-linux-gnu  # Build release
cross build --release --target x86_64-unknown-linux-gnu  # Cross-compile

# For Broker (Rust)
cd broker
cargo test
cargo run               # Run locally (needs DATABASE_URL env var)

# For Advisor (Go)
cd advisor
go test ./...           # Run tests
go build -o advisor     # Build binary

# For UI (React + TypeScript)
cd frontend
npm install             # Install dependencies
npm run dev             # Start dev server (http://localhost:5173)
npm run build           # Build for production
npm run lint            # Lint code
```

### Deployment
```bash
task kind               # Create fresh Kind cluster
task install            # Build all + install Helm chart in Kind cluster
```

The Helm chart can be installed from OCI registry (recommended):
```bash
# Production installation (from OCI registry)
helm install kguardian oci://ghcr.io/kguardian-dev/charts/kguardian \
  --namespace kguardian \
  --create-namespace

# Local development installation (using task install)
# This uses the local Helm repo with locally-built images
helm install kguardian kguardian/kguardian \
  --namespace kguardian --create-namespace \
  --set controller.image.tag=local \
  --set broker.image.tag=local
```

### Using the CLI
```bash
# Generate Network Policies
kubectl kguardian gen networkpolicy <pod-name> -n <namespace> --output-dir ./policies
kubectl kguardian gen netpol --all -n staging --type cilium  # Cilium policies for all pods

# Generate Seccomp Profiles
kubectl kguardian gen seccomp <pod-name> -n <namespace> --output-dir ./seccomp
kubectl kguardian gen secp -A --output-dir ./seccomp  # All pods, all namespaces

# Flags
# --dry-run: Preview without applying (default: true for netpol)
# -A, --all-namespaces: Target all namespaces
# -a, --all: All pods in namespace
# --type: kubernetes or cilium (for network policies)
```

## Architecture Details

### Controller (Rust + eBPF)
- **Location**: `controller/src/`
- **eBPF Programs**: `controller/src/bpf/` contains:
  - `network_probe.bpf.c`: Monitors TCP/network traffic
  - `syscall.bpf.c`: Tracks syscall usage
  - Build process uses `libbpf-cargo` to generate Rust skeletons (`.skel.rs` files)
- **Key Modules**:
  - `bpf.rs`: Loads eBPF programs, sets up perf buffers for kernel→userspace events
  - `pod_watcher.rs`: Watches K8s pods via kube-rs, filters by node and excluded namespaces
  - `network.rs`: Processes network events from eBPF, enriches with pod metadata
  - `syscall.rs`: Aggregates syscall events, caches and sends to Broker periodically
  - `container.rs`: Queries containerd for container network namespace inodes
- **Build**: Uses `cross` for cross-compilation, `build.rs` compiles eBPF C → skeletons
- **Environment Variables**:
  - `CURRENT_NODE`: Node name for filtering pods
  - `EXCLUDED_NAMESPACES`: Comma-separated (default: "kube-system,kguardian")
  - `IGNORE_DAEMONSET_TRAFFIC`: Boolean (default: "true")

### Broker (Rust + Actix-web)
- **Location**: `broker/src/`
- **Database**: PostgreSQL with Diesel ORM, migrations in `broker/db/migrations/`
- **API Endpoints** (port 9090):
  - POST `/pods` - Add pod info
  - POST `/pod/spec` - Add pod details with full spec
  - POST `/pods/syscalls` - Add syscall data
  - POST `/svc/spec` - Add service details
  - GET `/pod/traffic/:pod_ip` - Get network traffic for pod
  - GET `/pod/traffic/name/:namespace/:pod_name` - Get traffic by name
  - GET `/pod/syscalls/name/:namespace/:pod_name` - Get syscalls by name
  - GET `/health` - Health check
- **Schema**: `broker/src/schema.rs` defines tables for pods, services, network traffic, syscalls

### CLI (Go kubectl plugin)
- **Location**: `advisor/`
- **Command Structure**: Uses Cobra CLI framework
  - `cmd/root.go`: Root command setup, K8s config initialization
  - `cmd/networkpolicy.go`: Network policy generation logic
  - `cmd/seccomp.go`: Seccomp profile generation logic
- **Key Packages**:
  - `pkg/k8s/`: Kubernetes client utilities, CRD handling (Cilium policies)
  - `pkg/api/`: HTTP client for Broker API communication
  - `pkg/network/`: Network policy generation logic
  - `pkg/common/`: Shared utilities
- **Flow**: Queries Broker API → aggregates data → generates YAML manifests → optionally applies to cluster

### UI (React + TypeScript)
- **Location**: `frontend/`
- **Tech Stack**: React 19, TypeScript, Vite, TailwindCSS 4, React Flow
- **Key Components**:
  - `App.tsx`: Main application container with header, graph, and table
  - `components/NetworkGraph.tsx`: Network visualization using React Flow
  - `components/PodNode.tsx`: Collapsible pod node component
  - `components/NamespaceSelector.tsx`: Namespace dropdown
  - `components/DataTable.tsx`: Pod details and traffic table
- **Services**:
  - `services/api.ts`: Centralized Broker API client (Axios)
  - `hooks/usePodData.ts`: Custom hook for data fetching and state management
- **Styling**: Dark theme inspired by Cilium Hubble (see `index.css` for color scheme)
- **Build**: Vite for dev server and production builds, outputs to `dist/`
- **Deployment**: Multi-stage Docker build with nginx for serving static files
- **Configuration**:
  - `vite.config.ts`: Uses `VITE_API_URL` environment variable for broker URL (defaults to `http://broker.kguardian.svc.cluster.local:9090`)
  - `.env.example`: Example environment variables for local development

## Important Implementation Notes

### eBPF Development
- eBPF programs in `controller/src/bpf/*.bpf.c` require kernel 6.2+
- Changes to `.bpf.c` files require rebuild via `task controller:build`
- Network namespace inodes are used to correlate kernel events with pods
- Perf buffers used for high-throughput event streaming from kernel to userspace

### Data Flow
1. Controller's eBPF hooks capture network/syscall events with container inode
2. Controller matches inode → pod via containerd API and K8s pod watcher
3. Controller sends enriched events to Broker API (HTTP POST)
4. Broker stores in PostgreSQL with timestamps
5. CLI queries Broker, aggregates historical data, generates policies

### Namespace Filtering
- Controller excludes namespaces via `EXCLUDED_NAMESPACES` (default: kube-system, kguardian)
- Controller optionally ignores DaemonSet traffic via `IGNORE_DAEMONSET_TRAFFIC`
- CLI targets specific namespaces via `-n` or all via `-A`

### Testing in Kind
- `task kind` creates a fresh cluster and tears down the old one
- `task all` builds images with tag `local` and loads into Kind
- Controller runs privileged with `CAP_BPF` capability
- Broker needs DATABASE_URL pointing to PostgreSQL (configured in Helm values)

## Release Management

kguardian uses **automated component-based versioning** powered by [release-please](https://github.com/googleapis/release-please). See [RELEASES.md](RELEASES.md) for comprehensive documentation and [.github/RELEASE_GUIDE.md](.github/RELEASE_GUIDE.md) for quick reference.

### Quick Reference - Automated Releases

**Use Conventional Commits:**
```bash
# Feature (minor bump: 1.0.0 → 1.1.0)
git commit -m "feat(controller): add IPv6 monitoring support"

# Bug fix (patch bump: 1.0.0 → 1.0.1)
git commit -m "fix(broker): resolve connection pool leak"

# Breaking change (major bump: 1.0.0 → 2.0.0)
git commit -m "feat(ui)!: redesign API integration

BREAKING CHANGE: Requires broker v2.0.0 or higher"

# Push to main
git push origin main
```

**Release-please workflow:**
1. Analyzes conventional commits
2. Creates/updates Release PR with version bumps and changelogs
3. When merged, creates tags and triggers builds
4. Publishes artifacts automatically

**Git Tag Format (Auto-created):** `<component>/v<semver>`
- Tags are created automatically by release-please
- Examples: `controller/v1.0.0`, `broker/v1.2.3`, `ui/v2.0.0`

**Version Tracking:**
- `.release-please-manifest.json` - Current versions
- `<component>/VERSION` - Component version files
- `<component>/CHANGELOG.md` - Auto-generated changelogs

**CI Workflows:**
- `.github/workflows/release-please.yaml` - Main automation (runs on push to main)
- `.github/workflows/controller-release.yaml` - Controller builds
- `.github/workflows/broker-release.yaml` - Broker builds
- `.github/workflows/ui-release.yaml` - UI builds
- `.github/workflows/advisor-release.yml` - Advisor builds
- `.github/workflows/charts-release.yaml` - Chart publishing

**Published Artifacts:**
- Docker images: `ghcr.io/kguardian-dev/kguardian/guardian-{controller,broker,ui}:vX.Y.Z`
- Helm chart: `oci://ghcr.io/kguardian-dev/charts/kguardian:X.Y.Z`
- Advisor binaries: GitHub Releases with SLSA3 attestation

## Documentation (Mintlify)

The project documentation is located in the `docs/` directory and uses [Mintlify](https://mintlify.com).

### Documentation Development
```bash
# Install Mintlify CLI
npm i -g mint

# Preview documentation locally (from docs/ directory)
cd docs
mint dev  # Opens at http://localhost:3000
```

### Documentation Structure
The documentation follows a Talos Linux-inspired organization pattern:
- **docs.json**: Navigation configuration with tabs and page groups
- **Structure**: Getting Started → Core Concepts → User Guides → CLI Reference → Advanced → Roadmap
- **File format**: MDX files with YAML frontmatter (title, description, icon)

### Key Documentation Files
- `docs.json`: Main navigation configuration
- `roadmap/roadmap.mdx`: High-level roadmap and release timeline
- `roadmap/feature-deep-dives.mdx`: Detailed technical specifications for planned features
- Navigation groups follow logical progression from overview to advanced topics

### Documentation Guidelines
- ALWAYS prefer editing existing files over creating new ones
- Only create new pages when explicitly required
- Update `docs.json` navigation when adding/removing pages
- Use descriptive titles and clear descriptions in frontmatter
- Follow existing MDX patterns (Cards, Steps, Accordions, etc.)
- Cross-reference related pages to maintain documentation cohesion

## Common Issues

### Controller Build Failures
- Missing `cross`: Install via `cargo install cross`
- eBPF compilation errors: Ensure vmlinux.h matches target kernel architecture
- Kernel version: Requires 6.2+, check with `uname -r`

### Broker Database Connectivity
- Ensure PostgreSQL is running and reachable
- Check DATABASE_URL format: `postgres://user:password@host:port/dbname`
- Migrations run automatically on startup via `diesel_migrations`

### Advisor CLI Issues
- Must have Kube Guardian Controller deployed and collecting data first
- Broker must be accessible from Advisor (usually via kubectl port-forward)
- Network policies require observed traffic to generate meaningful rules
- Seccomp profiles require pods to have executed syscalls
