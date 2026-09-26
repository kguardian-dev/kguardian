# Signing fixtures (#1533)

`{request, status, body}` captures of `GET /images/{digest}/attestation` and
`GET /image-trust` from a local broker built from #1698
(`TELEMETRY_ENABLED=false`, scratch Postgres), used by the llm-bridge and
advisor tests.

What is real and what was seeded:

- **Signature results (real).** The supplychain component's verifier
  (sigstore-go) checked the recorded supplychain test fixtures and posted
  the results through the broker's ingest route: chainguard-static
  (keyless, with SLSA and SPDX attestations), key-legacy with its key
  configured, key-bundle without it (`key_signed`), the unsigned kguardian
  controller, a pause signature with one byte flipped (`invalid`), and a
  registry answering 401 (`unknown` / `registry_auth`). Repositories name
  the fixture registry's local host (`127.0.0.1:<port>`).
- **Inventory (seeded).** The `shop` workloads and their containers
  (`workload_containers`, `images`) were inserted with SQL. The
  `payments` and `recs` digests are synthetic (`sha256:aaaa…`,
  `sha256:dddd…`); `recs` has no signature result on purpose (never
  checked).
- **ImageTrustPolicy results (real evaluator, demo policies).** The
  evaluator binary ran against an envtest kube-apiserver (1.34.1) holding
  two demo policies (`shop/release-signers`, a namespaced
  ImageTrustPolicy, and `require-provenance`, a ClusterImageTrustPolicy)
  and read the seeded workloads and real signature results from the
  broker.
- `image-trust-evaluator-down.json` is the broker's answer with the
  evaluator stopped.
