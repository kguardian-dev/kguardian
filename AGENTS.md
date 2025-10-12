# Repository Guidelines
## Project Structure & Module Organization
`advisor/` contains the Go-based kubectl plugin, with commands in `cmd/`, shared logic in `pkg/`, and an entry point at `main.go`. `broker/` is a Rust service that persists runtime findings; Diesel migrations live under `broker/db/migrations`, and JSON fixtures for integration tests sit in `broker/test/`. `controller/` holds the eBPF-powered Rust controller, built with Cross; its entry point is `src/main.rs` and BPF programs live in `src/bpf/`. Deployment assets are grouped in `charts/` (Helm) and automation helpers in `scripts/`. Shared orchestration lives in `Taskfile.yaml` and `.taskfiles/*`, which wrap component-specific build and image pipelines.

## Build, Test, and Development Commands
Install Task (https://taskfile.dev) and drive routine workflows from the repo root. `task preflight` checks local prerequisites such as Go, Cargo, Cross, Docker, Kind, and Helm. `task advisor:all`, `task broker:all`, and `task controller:all` build each component and load the resulting images into your Kind cluster; `task install` deploys the full stack via Helm using the locally-built images. When iterating inside a component, you can run `go build ./...` within `advisor/`, `cargo build --release` inside `broker/`, and `cross build --release --target x86_64-unknown-linux-gnu` within `controller/`.

## Coding Style & Naming Conventions
Follow each language’s canonical formatter before committing: `gofmt` (or `go fmt ./...`) for Go code, and `cargo fmt` for Rust crates. Prefer idiomatic package layouts already in place (`pkg/network`, `src/network.rs`). Exported Go identifiers should use PascalCase, while private helpers remain camelCase; Rust modules use snake_case filenames and CamelCase types. Keep logging consistent with zerolog in the advisor and tracing in Rust services. Run `golangci-lint` and `cargo clippy --all-targets --all-features` when touching the respective stacks.

## Testing Guidelines
Unit tests live alongside their sources. Run `go test ./...` from `advisor/` for CLI coverage. For Rust services, execute `cargo test` inside `broker/` and `controller/`; broker tests expect a PostgreSQL `DATABASE_URL`, so point to a disposable database or use Docker based on the Diesel docs. Before opening a PR, execute the relevant `task <component>:all` target to ensure binaries still build and images load.

## Commit & Pull Request Guidelines
Commit history follows Conventional Commits (e.g., `fix(deps): update module github.com/spf13/cobra to v1.10.1`). Use clear scopes like `advisor`, `broker`, or `charts` when possible. Each PR should summarise the change, link any tracking issues, note required Helm value adjustments, and attach CLI output or screenshots for user-facing changes. Confirm tests and builds in the PR description and mention any follow-up tasks.
