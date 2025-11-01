# Release Management

This document describes the versioning and release strategy for the kguardian project.

## Overview

kguardian uses **component-based versioning** where each component can be released independently with its own semantic version. This allows components to evolve at different rates while maintaining clear version tracking.

**Release automation is powered by [release-please](https://github.com/googleapis/release-please)**, which automatically:
- Creates release PRs based on conventional commits
- Generates changelogs
- Bumps versions according to semantic versioning
- Creates GitHub releases
- Triggers component-specific build workflows

## Components

The project consists of five independently versioned components:

1. **Controller** - eBPF-based monitoring DaemonSet (Rust)
2. **Broker** - API server for telemetry storage (Rust)
3. **UI** - Web interface for visualization (React/TypeScript)
4. **Advisor** - kubectl plugin for policy generation (Go)
5. **Chart** - Helm chart for Kubernetes deployment

## Version Tracking

Each component maintains its version in two places:

1. **VERSION file** - Located at `<component>/VERSION` (e.g., `controller/VERSION`)
2. **Package manifest** - Component-specific file:
   - Controller: `controller/Cargo.toml`
   - Broker: `broker/Cargo.toml`
   - UI: `ui/package.json`
   - Advisor: Set via ldflags during build
   - Chart: `charts/kguardian/Chart.yaml`

## Git Tagging Strategy

Each component uses a **prefixed tag** format: `<component>/v<semver>`

**Tags are created automatically by release-please.** You should not manually create tags unless you're bypassing automation (emergency only).

### Tag Format

- `controller/v1.0.0` - Controller releases
- `broker/v1.2.3` - Broker releases
- `ui/v2.0.0` - UI releases
- `advisor/v1.1.0` - Advisor releases
- `chart/v1.0.0` - Helm chart releases

When you merge a Release PR created by release-please, these tags are automatically created and pushed.

## Release Workflow

### Automated Release Process (Recommended)

kguardian uses **release-please** to automate the entire release process. Here's how it works:

#### 1. Commit Changes Using Conventional Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) format for all commits to the `main` branch:

```bash
# Feature commits (minor version bump)
git commit -m "feat(controller): add support for custom namespace labels"
git commit -m "feat(ui): add real-time syscall heatmap visualization"

# Bug fix commits (patch version bump)
git commit -m "fix(broker): resolve connection pool exhaustion under load"
git commit -m "fix(advisor): correct NetworkPolicy port generation"

# Breaking changes (major version bump)
git commit -m "feat(controller)!: migrate to CO-RE eBPF requiring kernel 5.15+"
# OR with body
git commit -m "feat(broker): change API response format

BREAKING CHANGE: The /pods endpoint now returns an array instead of an object"

# Other commit types
git commit -m "docs(readme): update installation instructions"
git commit -m "refactor(ui): extract custom hooks for policy editing"
git commit -m "perf(controller): optimize eBPF map lookups"
git commit -m "chore(deps): update dependencies"
```

**Important commit prefixes:**
- `feat(component):` - New feature (minor bump)
- `fix(component):` - Bug fix (patch bump)
- `feat(component)!:` - Breaking change (major bump)
- Include `BREAKING CHANGE:` in commit body for major bumps
- `perf(component):` - Performance improvement
- `docs(component):` - Documentation changes
- `refactor(component):` - Code refactoring
- `test(component):` - Test changes
- `chore(component):` - Maintenance tasks
- `ci(component):` - CI/CD changes

#### 2. Release-Please Creates Release PR

When you push commits to `main`, the **release-please** GitHub Action automatically:

1. Analyzes commits since the last release for each component
2. Determines version bumps based on commit types (feat/fix/BREAKING CHANGE)
3. Creates or updates a **Release PR** for affected components
4. The PR includes:
   - Version bumps in package manifests (Cargo.toml, package.json, Chart.yaml)
   - Updated VERSION files
   - Generated CHANGELOG.md entries
   - Component-specific git tags

Example PR title: `chore(main): release controller 1.1.0, broker 1.0.1`

#### 3. Review and Merge Release PR

1. Review the automatically generated changelog and version bumps
2. Make any necessary edits to CHANGELOG.md if needed
3. Merge the Release PR to `main`

#### 4. Automated Build and Publish

Once the Release PR is merged, release-please automatically:

1. Creates git tags for each released component (e.g., `controller/v1.1.0`)
2. Creates GitHub Releases with changelog content
3. Triggers component-specific build workflows via workflow_dispatch
4. Publishes artifacts:
   - **Controller**: Docker image to `ghcr.io/kguardian-dev/kguardian/guardian-controller:vX.Y.Z`
   - **Broker**: Docker image to `ghcr.io/kguardian-dev/kguardian/guardian-broker:vX.Y.Z`
   - **UI**: Docker image to `ghcr.io/kguardian-dev/kguardian/guardian-ui:vX.Y.Z`
   - **Advisor**: SLSA3-attested binaries to GitHub Releases (linux/darwin, amd64/arm64)
   - **Chart**: Helm package to `oci://ghcr.io/kguardian-dev/charts/kguardian:X.Y.Z`
5. Tags Docker images with `latest`

### Coordinated Multi-Component Releases

Release-please automatically handles multi-component releases. When you make changes across multiple components, a single Release PR will be created with updates for all affected components.

**Example:**
```bash
git commit -m "feat(controller): add IPv6 support"
git commit -m "feat(broker): add IPv6 fields to API"
git commit -m "feat(ui): display IPv6 addresses"
git push origin main

# Release-please creates ONE PR that releases all three:
# - controller: 1.0.0 → 1.1.0
# - broker: 1.0.0 → 1.1.0
# - ui: 1.0.0 → 1.1.0
```

When merged, all three components are released simultaneously with their respective tags.

### Helm Chart Releases

The Helm chart can be released independently via conventional commits:

```bash
git commit -m "feat(chart): add support for custom annotations"
# → Creates PR: chart 1.0.0 → 1.1.0
```

The chart can reference specific component versions via `values.yaml`:
```yaml
controller:
  image:
    tag: "v1.2.0"  # Pin to specific controller version
broker:
  image:
    tag: "v1.3.1"  # Pin to specific broker version
ui:
  image:
    tag: "v2.0.0"  # Pin to specific UI version
```

### Manual Override (Emergency Use Only)

If release-please is unavailable or you need to bypass automation:

```bash
# Manual version bump
echo "1.2.3" > component/VERSION
vim component/Cargo.toml  # Update version
vim component/CHANGELOG.md  # Add entry manually

git commit -am "chore(component): manual release v1.2.3"
git tag component/v1.2.3
git push origin main component/v1.2.3
```

This triggers the component-specific build workflow directly, but **you lose automatic changelog generation and version tracking**. Only use this in emergencies.

## Semantic Versioning

All components follow [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes, incompatible API changes
- **MINOR** (x.Y.0): New features, backward-compatible
- **PATCH** (x.y.Z): Bug fixes, backward-compatible

### Component-Specific Guidelines

**Controller:**
- MAJOR: eBPF program changes requiring kernel version bump, API breaking changes
- MINOR: New monitoring features, additional telemetry
- PATCH: Bug fixes, performance improvements

**Broker:**
- MAJOR: Database schema breaking changes, API endpoint removals
- MINOR: New API endpoints, additional features
- PATCH: Bug fixes, security patches

**UI:**
- MAJOR: Complete redesign, framework upgrades
- MINOR: New features, new visualizations
- PATCH: Bug fixes, UX improvements

**Advisor:**
- MAJOR: Command structure changes, breaking CLI changes
- MINOR: New commands, new policy types
- PATCH: Bug fixes, policy generation improvements

**Chart:**
- MAJOR: Breaking configuration changes, API version changes
- MINOR: New features, new configuration options
- PATCH: Bug fixes, template improvements

## Version Compatibility

### Controller ↔ Broker

- Same MAJOR version required
- MINOR versions are forward-compatible
- Controller v1.2.x works with Broker v1.0.x-v1.2.x

### Broker ↔ UI

- Same MAJOR version required
- UI can be newer MINOR version than Broker
- UI v1.3.x works with Broker v1.0.x-v1.3.x

### Broker ↔ Advisor

- Same MAJOR version recommended
- Advisor should match or exceed Broker MINOR version for full feature support
- Advisor v1.2.x works best with Broker v1.2.x

### Chart ↔ Components

- Chart MAJOR version should match components' MAJOR version
- Chart can specify any compatible component versions via values

## Configuration Files

### Release-Please Configuration

- **`.release-please-manifest.json`** - Tracks current version for each component
  ```json
  {
    "controller": "1.0.0",
    "broker": "1.0.0",
    "ui": "1.0.0",
    "advisor": "1.0.0",
    "charts/kguardian": "1.0.0"
  }
  ```

- **`release-please-config.json`** - Configures release-please behavior per component
  - Specifies release types (rust, node, go, helm)
  - Defines changelog paths
  - Configures tag format (component/vX.Y.Z)
  - Lists extra files to update (VERSION files)
  - Defines changelog sections

- **`.versionrc.json`** - Conventional Changelog configuration
  - Commit type mappings
  - URL formats for commits, comparisons, issues
  - Release commit message format

### Component Changelogs

Each component maintains its own CHANGELOG.md:
- `controller/CHANGELOG.md`
- `broker/CHANGELOG.md`
- `ui/CHANGELOG.md`
- `advisor/CHANGELOG.md`
- `charts/kguardian/CHANGELOG.md`

These are automatically updated by release-please based on conventional commits.

## Workflow Files

### Release Automation

- **`.github/workflows/release-please.yaml`** - Main release automation workflow
  - Runs on every push to `main`
  - Creates/updates release PRs
  - Triggers component-specific builds when releases are merged

### Component Build Workflows

- `.github/workflows/controller-release.yaml` - Triggered by `controller/v*` tags or workflow_dispatch
- `.github/workflows/broker-release.yaml` - Triggered by `broker/v*` tags or workflow_dispatch
- `.github/workflows/ui-release.yaml` - Triggered by `ui/v*` tags or workflow_dispatch
- `.github/workflows/advisor-release.yml` - Triggered by `advisor/v*` tags or workflow_dispatch
- `.github/workflows/charts-release.yaml` - Triggered by `chart/v*` tags or chart file changes

## Querying Versions

### Current Installed Versions

```bash
# Controller version (from pod)
kubectl get pods -n kguardian -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].spec.containers[0].image}'

# Broker version (from pod)
kubectl get pods -n kguardian -l app.kubernetes.io/component=broker -o jsonpath='{.items[0].spec.containers[0].image}'

# UI version (from pod)
kubectl get pods -n kguardian -l app.kubernetes.io/component=ui -o jsonpath='{.items[0].spec.containers[0].image}'

# Advisor version (from binary)
kubectl xentra version

# Chart version (from Helm)
helm list -n kguardian
```

### Available Versions

```bash
# Docker images
docker pull ghcr.io/kguardian-dev/kguardian/guardian-controller
docker pull ghcr.io/kguardian-dev/kguardian/guardian-broker
docker pull ghcr.io/kguardian-dev/kguardian/guardian-ui

# Helm chart versions
helm search repo kguardian --versions

# Advisor releases
gh release list --repo kguardian-dev/kguardian
```

## Best Practices

### For Development

1. **Use conventional commits** for ALL commits to main
   - Follow the format: `type(component): description`
   - Use `feat` for features, `fix` for bugs, `feat!` or `BREAKING CHANGE:` for breaking changes

2. **Write descriptive commit messages**
   - The commit message becomes your changelog entry
   - Include context and impact in the commit body
   - Reference issues: `fixes #123`

3. **Test before pushing to main**
   - Ensure your changes work as expected
   - Run local tests and builds
   - Commits to main trigger release-please analysis

4. **Review Release PRs carefully**
   - Check version bumps are appropriate
   - Review auto-generated changelogs
   - Edit CHANGELOG.md in the PR if needed

### For Releases

5. **Use release-please as the primary method**
   - Let automation handle version bumps and changelogs
   - Only use manual releases in emergencies

6. **Pin component versions** in Helm values for production
   - Don't use `latest` in production
   - Use specific version tags: `v1.2.3`

7. **Coordinate breaking changes**
   - Document breaking changes clearly in commit body
   - Update dependent components in the same PR if possible
   - Test compatibility across components

8. **Monitor release workflows**
   - Check that builds complete successfully
   - Verify artifacts are published correctly
   - Test deployed releases

## Migration from Previous Versioning

Previously, the project used a single `v*` tag for all components. With release-please:

1. ✅ All workflows updated to use component-specific tags (component/v*)
2. ✅ VERSION files created for each component at v1.0.0
3. ✅ Helm chart updated to support component-specific versions
4. ✅ Release-please configured for automated releases
5. ✅ CHANGELOG.md files created for each component
6. 🔄 Next step: Push to main and let release-please create the first Release PR
7. 📋 Legacy `v*` tags remain for backward compatibility but are deprecated

**Important:** With release-please, you no longer manually create tags. The automation handles all versioning, tagging, and changelog generation.

## Validation and Testing

Before using release-please in production, validate your configuration:

```bash
# Run the validation script
./.github/scripts/validate-release-config.sh
```

This validates:
- JSON syntax and structure
- Component consistency
- Version file existence and consistency
- Workflow configuration
- Conventional commit parsing

For comprehensive testing including dry-runs, mock commits, and using the release-please CLI, see [.github/TESTING_RELEASES.md](.github/TESTING_RELEASES.md).

## Examples

### Example 1: Hotfix Release (Patch) - Automated with Release-Please

```bash
# Fix a critical bug in the broker
cd broker
# Make your code changes...

# Commit using conventional commits (fix = patch bump)
git add .
git commit -m "fix(broker): resolve connection pool exhaustion under high load

This fixes a critical issue where connection pools would be exhausted
after prolonged periods of high traffic, causing API timeouts."

git push origin main

# Release-please will:
# 1. Detect the fix(broker) commit
# 2. Create/update a Release PR bumping broker from 1.0.0 -> 1.0.1
# 3. Generate CHANGELOG entry
# 4. When you merge the PR, it creates the release and triggers the build
```

### Example 2: Feature Release (Minor) - Automated with Release-Please

```bash
# Add a new feature to the UI
cd ui
# Implement the feature...

# Commit using conventional commits (feat = minor bump)
git add .
git commit -m "feat(ui): add real-time syscall heatmap visualization

Adds an interactive heatmap showing syscall frequency across pods.
Users can filter by time range and syscall type."

git push origin main

# Release-please will:
# 1. Detect the feat(ui) commit
# 2. Create/update a Release PR bumping ui from 1.0.0 -> 1.1.0
# 3. Generate CHANGELOG entry under "Features" section
# 4. When merged, creates ui/v1.1.0 release and builds the image
```

### Example 3: Breaking Change (Major) - Automated with Release-Please

```bash
# Make a breaking change in the controller
cd controller
# Implement breaking changes...

# Commit with ! suffix or BREAKING CHANGE in body (major bump)
git add .
git commit -m "feat(controller)!: migrate to CO-RE eBPF

BREAKING CHANGE: This version requires Linux kernel 5.15+ with BTF support.
Previous versions supported kernel 5.4+. Update your cluster nodes before deploying."

git push origin main

# Release-please will:
# 1. Detect the BREAKING CHANGE
# 2. Create Release PR bumping controller from 1.0.0 -> 2.0.0
# 3. Highlight the breaking change prominently in CHANGELOG
# 4. When merged, creates controller/v2.0.0 release
```

### Example 4: Multi-Component Release

```bash
# Make changes across multiple components
git commit -m "feat(controller): add IPv6 support for network monitoring"
git commit -m "feat(broker): add IPv6 address fields to database schema"
git commit -m "feat(ui): display IPv6 addresses in network graph"
git commit -m "docs(readme): update IPv6 feature documentation"

git push origin main

# Release-please will:
# 1. Create a single Release PR with updates for all 3 components:
#    - controller: 1.0.0 -> 1.1.0
#    - broker: 1.0.0 -> 1.1.0
#    - ui: 1.0.0 -> 1.1.0
# 2. Each component gets its own CHANGELOG update
# 3. When merged, creates 3 releases: controller/v1.1.0, broker/v1.1.0, ui/v1.1.0
# 4. Triggers all 3 build workflows
```

### Example 5: Chart-Only Release

```bash
# Update Helm chart configuration
cd charts/kguardian
# Edit templates or values...

git add .
git commit -m "feat(chart): add support for custom pod annotations

Allows users to specify custom annotations for controller and broker pods
via values.yaml."

git push origin main

# Release-please will:
# 1. Create Release PR bumping chart from 1.0.0 -> 1.1.0
# 2. Update charts/kguardian/Chart.yaml version and appVersion
# 3. When merged, creates chart/v1.1.0 and publishes to OCI registry
```

### Example 6: Manual Release (Without Release-Please)

If you need to bypass release-please for any reason:

```bash
# Manual version bump for broker
echo "1.0.1" > broker/VERSION
vim broker/Cargo.toml  # version = "1.0.1"
vim broker/CHANGELOG.md  # Add entry manually

git commit -am "chore(broker): manual release v1.0.1"
git push origin main

# Manually create tag
git tag broker/v1.0.1
git push origin broker/v1.0.1

# This triggers the broker-release.yaml workflow directly
```
