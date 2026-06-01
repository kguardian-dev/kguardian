# Security Policy

kguardian is a security tool. We take vulnerability reports seriously and want to make it easy for security researchers to report issues responsibly.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** Public issues are visible to everyone before a fix is available, and that puts kguardian users at risk.

Instead, send a private report to:

- **Email:** `security@kguardian.dev`
- **GitHub Security Advisory:** Use the [private vulnerability reporting](https://github.com/kguardian-dev/kguardian/security/advisories/new) form on this repository.

Please include, where possible:

- The kguardian component affected (Controller, Broker, UI, Advisor CLI, Helm chart, LLM Bridge, MCP Server).
- The version (output of `kubectl kguardian version` or the chart `appVersion`).
- A description of the vulnerability and the impact you believe it has.
- Steps to reproduce, including manifests or configuration if relevant.
- Whether the issue requires cluster access, network access, or unauthenticated remote access.

## Response SLA

We aim to:

- **Acknowledge** receipt of a report within **72 hours**.
- Provide a **first technical assessment** within **7 days**.
- Agree on a **fix timeline and disclosure date** with the reporter as soon as the impact is understood.

If you do not receive an acknowledgement within 72 hours, please re-send the report and CC the maintainers listed in [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Disclosure Policy

We follow **coordinated disclosure** with a **90-day default window**:

- We will work with the reporter to fix the issue and prepare an advisory.
- Once a fix is released, we publish a GitHub Security Advisory crediting the reporter (unless they request otherwise).
- If 90 days pass without resolution, the reporter is free to disclose publicly. We will ask for an extension only if a fix is genuinely in flight and we can show progress.

We will not pursue legal action against researchers who follow this policy in good faith.

## Supported Versions

Security fixes are backported to currently supported releases only. Older releases receive fixes on a best-effort basis.

| Component  | Version     | Supported          |
|------------|-------------|--------------------|
| Controller | latest minor | ✅ security fixes  |
| Controller | older        | ❌ best-effort     |
| Broker     | latest minor | ✅ security fixes  |
| Broker     | older        | ❌ best-effort     |
| Advisor    | latest minor | ✅ security fixes  |
| Advisor    | older        | ❌ best-effort     |
| UI         | latest minor | ✅ security fixes  |
| Helm chart | latest minor | ✅ security fixes  |

"latest minor" means the most recent `MAJOR.MINOR.x` release line for each component. See [`RELEASES.md`](./RELEASES.md) for the per-component versioning model.

## Threat Model and Architecture Notes

For security-relevant architecture details (Controller capabilities, Broker auth posture, data sensitivity, trust boundaries) see [`docs/security-model.mdx`](./docs/security-model.mdx). That page is the canonical source for "what does kguardian assume about its environment?" — please read it before reporting issues that depend on those assumptions.

## Style

This file follows the kguardian [Style Guide](./STYLE.md) — lowercase product name, no banned marketing words, no emoji in headings.
