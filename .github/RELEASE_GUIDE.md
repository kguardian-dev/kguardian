# Quick Release Guide

This is a quick reference for releasing kguardian components. For comprehensive documentation, see [RELEASES.md](../../RELEASES.md).

## TL;DR - How to Release

1. **Make your changes** to the component
2. **Commit with conventional commits**:
   ```bash
   git commit -m "feat(component): description"  # Minor version bump
   git commit -m "fix(component): description"   # Patch version bump
   git commit -m "feat(component)!: description" # Major version bump (breaking)
   ```
3. **Push to main**: `git push origin main`
4. **Wait for Release PR**: release-please creates/updates a PR automatically
5. **Review and merge** the Release PR
6. **Done!** Releases are created and artifacts are built automatically

## Conventional Commit Format

```
<type>(<component>): <short description>

[optional body]

[optional footer]
```

### Types

- `feat`: New feature (→ minor version bump)
- `fix`: Bug fix (→ patch version bump)
- `feat!` or `BREAKING CHANGE:`: Breaking change (→ major version bump)
- `docs`: Documentation only
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Tests
- `chore`: Maintenance
- `ci`: CI/CD changes

### Components

- `controller` - eBPF monitoring DaemonSet
- `broker` - API server
- `ui` - Web interface
- `advisor` - kubectl plugin
- `chart` - Helm chart

### Examples

```bash
# Feature (minor bump)
git commit -m "feat(controller): add IPv6 network monitoring support"

# Bug fix (patch bump)
git commit -m "fix(broker): resolve database connection leak"

# Breaking change (major bump)
git commit -m "feat(ui)!: redesign API integration

BREAKING CHANGE: UI now requires broker v2.0.0 or higher"

# Multiple components
git commit -m "feat(controller): add new telemetry endpoint"
git commit -m "feat(broker): consume new telemetry data"
git commit -m "feat(ui): visualize new telemetry metrics"
```

## What Happens After Push?

1. **Automatic PR Creation**: release-please analyzes your commits and creates a Release PR
2. **Version Bumps**: Automatically updates `VERSION`, `Cargo.toml`, `package.json`, `Chart.yaml`
3. **Changelog Generation**: Adds entries to component `CHANGELOG.md` files
4. **Review Time**: You can review and edit the PR if needed
5. **Merge to Release**: Merging creates GitHub releases and triggers builds
6. **Artifact Publishing**: Docker images, Helm chart, and binaries are published automatically

## Release PR Example

When you push commits, release-please creates a PR like:

```
Title: chore(main): release controller 1.1.0, broker 1.0.1

Changes:
- controller/VERSION: 1.0.0 → 1.1.0
- controller/Cargo.toml: version = "1.1.0"
- controller/CHANGELOG.md: Added new entries
- broker/VERSION: 1.0.0 → 1.0.1
- broker/Cargo.toml: version = "1.0.1"
- broker/CHANGELOG.md: Added new entries
```

## Common Scenarios

### Hotfix for Production Issue

```bash
# Fix the bug
vim broker/src/main.rs

# Commit with fix type
git commit -am "fix(broker): prevent panic on malformed requests"
git push origin main

# Release-please creates patch release (1.0.0 → 1.0.1)
# Merge PR → broker/v1.0.1 is released
```

### Add New Feature

```bash
# Implement feature
vim ui/src/components/NewFeature.tsx

# Commit with feat type
git commit -am "feat(ui): add syscall timeline visualization"
git push origin main

# Release-please creates minor release (1.0.0 → 1.1.0)
# Merge PR → ui/v1.1.0 is released
```

### Breaking API Change

```bash
# Make breaking changes
vim controller/src/api.rs

# Commit with ! or BREAKING CHANGE
git commit -am "feat(controller)!: change telemetry API format

BREAKING CHANGE: Telemetry payload structure has changed.
Requires broker v2.0.0 or higher."
git push origin main

# Release-please creates major release (1.x.x → 2.0.0)
# Merge PR → controller/v2.0.0 is released
```

## Manual Override

If you need to bypass automation:

```bash
# Manual version bump
echo "1.2.3" > component/VERSION
vim component/package.json  # Update version
vim component/CHANGELOG.md  # Add entry

# Commit and tag
git commit -am "chore(component): release v1.2.3"
git tag component/v1.2.3
git push origin main component/v1.2.3
```

## Troubleshooting

### Release PR Not Created?

- Check that commits follow conventional commit format
- Ensure commits are on `main` branch
- Check `.github/workflows/release-please.yaml` ran successfully
- Verify component names match `release-please-config.json`

### Wrong Version Bump?

- Edit the Release PR directly before merging
- Update VERSION files and CHANGELOG.md in the PR
- Use `feat!` or `BREAKING CHANGE:` for major bumps

### Need to Update a Release?

- Close the existing Release PR
- Make additional commits
- release-please will create a new PR with all changes

## Validation and Testing

Before pushing to production, validate your configuration:

```bash
# Run validation script
.github/scripts/validate-release-config.sh

# Should output: ✓ All validations passed!
```

For advanced testing (dry-runs, mock commits, etc.), see [TESTING_RELEASES.md](TESTING_RELEASES.md).

## Learn More

- [Full Release Documentation](../../RELEASES.md)
- [Testing Release Configuration](TESTING_RELEASES.md)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Release Please Docs](https://github.com/googleapis/release-please)
- [Semantic Versioning](https://semver.org/)
