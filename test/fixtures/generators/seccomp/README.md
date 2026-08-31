# G2 generator golden fixtures — seccomp

Language-neutral fixtures for the seccomp profile generator
(gate G2). Each `*.json` is:

```
{ "name": "...", "input": { "syscalls": [...sorted...], "arch": "x86_64|aarch64" },
  "expected": { <the canonical SeccompProfile object> } }
```

Both implementations must produce `expected` (compared as a parsed object,
so cross-language key ordering/whitespace never matters):

- advisor Go — `advisor/pkg/k8s` `BuildSeccompProfile` (the reference;
  `advisor/pkg/k8s/seccomp_fixture_test.go`)
- frontend TS — `buildSeccompProfile` (`frontend/src/utils/seccompProfileGenerator.ts`,
  `*.fixture.test.ts`)

The reference is advisor behavior. Capturing these fixtures surfaced two
real frontend divergences, both fixed to match the reference in the PR that
introduced this suite:
1. **arch** — the frontend hardcoded `[SCMP_ARCH_X86_64, SCMP_ARCH_X86,
   SCMP_ARCH_X32]` for every pod, so an aarch64 pod got an x86 profile
   (unusable). Now arch-mapped like advisor.
2. **empty syscalls** — advisor always emits the allow rule; the frontend
   emitted none. Now consistent.

`syscalls` inputs are pre-sorted so ordering is unambiguous across the two
generators (advisor preserves input order; the frontend sorts).

Network-policy fixtures live under `../networkpolicy/` with advisor Go
reference goldens; frontend consumption of those lands with the shared
generator package, where the two input shapes converge.
