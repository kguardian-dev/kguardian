# Contributing to kguardian

Thanks for your interest in contributing. This guide explains how to file issues, propose changes, and get a development environment running.

## Code of Conduct

Be respectful and constructive — critique code and ideas, not people, and keep discussions focused on making the project better. Report unacceptable behaviour privately to the maintainers listed below.

## Where to file what

| You want to …                                                | Use                                                                                                |
|--------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| Report a security vulnerability                              | **Private channel** — see [`SECURITY.md`](./SECURITY.md). Do not open a public issue.              |
| Report a reproducible bug                                    | [GitHub Issues](https://github.com/kguardian-dev/kguardian/issues) with the `bug` template.        |
| Request a feature or behaviour change                        | [GitHub Issues](https://github.com/kguardian-dev/kguardian/issues) with the `feature` template.    |
| Ask a question, share a use case, or discuss design          | [GitHub Discussions](https://github.com/kguardian-dev/kguardian/discussions).                      |
| Submit a fix or new feature                                  | A pull request — see below.                                                                        |

If you are not sure whether something is a bug, a feature, or a discussion topic, default to a Discussion. We will move it to an issue if there is a clear repro or scope.

## Pull request conventions

### Conventional Commits

We use [Conventional Commits](https://www.conventionalcommits.org/) on every commit that lands on `main`. Release-please reads the commit history to compute version bumps and changelogs (see [`RELEASES.md`](./RELEASES.md)).

```
<type>(<component>): <short summary>

<optional body>

<optional footer, e.g. BREAKING CHANGE: …>
```

Common type/component pairs:

- `feat(controller): …` — new Controller feature (minor bump)
- `fix(broker): …` — Broker bug fix (patch bump)
- `feat(advisor)!: …` — breaking change in the CLI (major bump)
- `docs: …` — documentation-only changes
- `chore(deps): …` — dependency updates (Renovate uses this)
- `ci: …` — CI/CD changes

A breaking change is signalled either by `!` after the type/scope or by a `BREAKING CHANGE:` footer.

### Branch naming

Use a short, prefixed branch name that mirrors the commit type:

- `feat/<component>-<topic>`
- `fix/<component>-<short-bug-name>`
- `docs/<topic>`
- `chore/<topic>`

Avoid the `docs/<scope>` namespace when contributing under directories that already have `docs/` paths in the repo — pick a non-colliding name (for example `tier3-pages` rather than `docs/tier3-pages`) so reviewers do not have to disambiguate file paths from branch names.

### Sign-off

All commits must be signed off:

```bash
git commit -s -m "fix(broker): close DB pool on shutdown"
```

The `-s` flag adds a `Signed-off-by:` trailer that certifies you have the right to submit the work under the project licence (see the [Developer Certificate of Origin](https://developercertificate.org/)). Sign-off is expected on all commits; maintainers may ask you to add it during review.

### PR checklist

Before requesting review:

1. The change is covered by tests (unit, integration, or both).
2. `task preflight` and the relevant component build (`task <component>:build`) pass locally.
3. Docs are updated if behaviour, flags, or API contracts changed.
4. Style rules from [`STYLE.md`](./STYLE.md) are honoured (lowercase product name, no banned marketing words, no emoji in headings, no unqualified "real-time").
5. Commit messages follow Conventional Commits and are signed off.

## Local development setup

The monorepo builds via [`Taskfile.yaml`](./Taskfile.yaml) (run `task --list` for all targets) and each component lives in its own source directory: `controller/`, `broker/`, `frontend/`, `advisor/`, `evaluator/`, `mcp-server/`, `llm-bridge/`, `charts/`.

Quick start:

```bash
# clone + enter
git clone https://github.com/kguardian-dev/kguardian
cd kguardian

# preflight: check required tooling is installed
task preflight

# build everything for a local kind cluster
task all
```

If `task preflight` reports missing tooling, install the listed tools and re-run before opening a PR.

## Style guide

User-facing copy (READMEs, docs, CLI help text, error messages) follows the kguardian [Style Guide](./STYLE.md). Highlights:

- The product name is `kguardian` — lowercase, always.
- Component nouns are capitalised proper nouns: **Controller**, **Broker**, **UI**.
- The CLI is invoked as `kubectl kguardian <subcommand>`. Never `kguardian-cli`.
- Banned marketing words: "made simple", "tailored", "zero-trust" (write "default-deny"), "powerful", "next-generation", "cutting-edge", "world-class", "say goodbye to …".
- No emoji in headings; emoji is fine in tables or inline status markers.
- The UI polls the Broker (~5 s cadence). Write "live view (polled, ~5s)" or "polled" — never an unqualified "real-time".

If you are touching docs, read `STYLE.md` end-to-end before writing — it is short and the rules are enforced.

## Releases

kguardian uses component-based versioning automated by [release-please](https://github.com/googleapis/release-please). See [`RELEASES.md`](./RELEASES.md) for the full release flow. As a contributor, the only thing you usually need to do is write a Conventional Commit message — release-please does the rest.

## Maintainers

- [@xUnholy](https://github.com/xUnholy) — Michael Fornaro

## Licence

By contributing, you agree that your contributions will be licensed under the project's [BSL-1.1 licence](./LICENSE).
