# kguardian Style Guide

This document defines naming, terminology, and tone conventions used in kguardian's documentation, READMEs, and any user-facing copy. Apply it when adding or revising content. Tier-2 docs cleanup (PR `tier2-structure`) introduced this file; future tiers reference it instead of relitigating these rules.

## Naming

### Product name

The product name is `kguardian` — lowercase, always. That includes the start of a sentence ("kguardian watches pod traffic …"), titles, frontmatter, and headings. Never `KGuardian`, `Kguardian`, `KGUARDIAN`, or `K-Guardian`.

Use `kguardian` (the package/system) when speaking about the project as a whole. Use a component noun (below) when you mean a specific binary or service.

### Component nouns

The system has three named components. When referring to the specific kguardian component, capitalize as proper nouns:

- **Controller** — the eBPF DaemonSet that captures pod traffic and syscalls.
- **Broker** — the Rust + Actix-web service that stores observed behavior in PostgreSQL and serves it back over an HTTP API.
- **UI** — the React + TypeScript frontend that visualises pod-to-pod traffic.

When the same words appear generically (a controller in another tool, the broker pattern, a ui), keep them lowercase.

Avoid the awkward "kguardian Controller" form — within kguardian's own README and docs, "the Controller" is unambiguous. Reach for the qualified form ("kguardian's Controller") only when the surrounding text is comparing kguardian to other projects, where the bare proper noun could be mistaken for someone else's component.

### Binary and CLI

- The binary on disk is `kubectl-kguardian`. Use this exact spelling **only** when literally referring to the file (install instructions, `mv` targets, `which` output).
- The CLI is invoked as `kubectl kguardian <subcommand>` — no hyphen, space-separated, written in `code` font.
- Do not write `kguardian-cli`. It is not a binary, command, or package name and never has been.

### Generated artefact names

- Capitalise Kubernetes API kinds when referring to the resource: `NetworkPolicy`, `CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy`, `SeccompProfile`.
- Use lowercase plain-English when speaking about the concept: "a network policy", "the seccomp profile JSON", "a Cilium policy".

## Tone

- **Specific over fluff.** Prefer concrete numbers, kernel versions, and command examples. A docs sentence with a kernel version, a Helm version, and a kubectl flag in it is almost always stronger than one without.
- **No emoji in headings.** Emoji is fine in feature-comparison tables, badges, and inline status markers (`✅`, `❌`, `🔜`). Headings stay text-only.
- **Banned marketing words.** The following do not appear in user-facing copy:
  - "made simple"
  - "tailored"
  - "zero-trust" (we mean default-deny — say that)
  - "powerful"
  - "next-generation", "cutting-edge", "world-class"
  - "say goodbye to …"
  - "hello to …"
- **No unqualified "real-time".** kguardian's UI polls the Broker (~5 second cadence). When describing this, write "live view (polled, ~5s)" or simply "polled". Reserve "real-time" for sub-second push paths kguardian does not currently have.

## Versioning and links

- Pin Helm chart versions in copy-paste install snippets so they do not drift behind newer releases. The Tier-1 baseline is `1.9.1`; bump in lockstep with chart releases.
- Internal docs links are repo-relative (`/installation`, `/quickstart`, `/architecture`). External links use full URLs.
- Cross-link rather than duplicate. If the same install snippet, comparison table, or "what is kguardian?" pitch already lives somewhere canonical, link to it instead of copy-pasting.

## Canonical sources for repeated content

When the same content would otherwise appear in multiple places, this is the canonical home and everything else links to it:

| Topic | Canonical source |
|---|---|
| "What is kguardian?" pitch | `README.md` lede (line 10) — used verbatim in `docs/index.mdx` and `docs/concepts/overview.mdx` |
| Feature comparison table | `docs/index.mdx` `## Comparison with Other Tools` |
| Install snippets (Helm, Krew, manual, Kind, custom values) | `docs/installation.mdx` |
| Quickstart-flow install (one Helm command + link) | `docs/quickstart.mdx` Step 1 |
| Generated policy examples | `docs/policy-gallery/` |

If a future change makes one of those locations no longer canonical, update this table in the same PR.
