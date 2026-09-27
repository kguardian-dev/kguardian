"""Seed a local Broker with image signature results and capture what the UI reads.

Run a Broker built from the commit you want captures of, against an empty
database, with scoped auth on (the attestation ingest refuses writes
without the supplychain scope) and the anonymous version check-in off:

    BROKER_TOKEN_READ=<r> BROKER_TOKEN_INGEST=<i> BROKER_TOKEN_SUPPLYCHAIN=<s> \\
    TELEMETRY_ENABLED=false DATABASE_URL=... LISTEN_ADDR=127.0.0.1:<port> broker

then:

    python3 capture.py http://127.0.0.1:<port> <r> <i> <s> <broker git sha>

It posts the pods of ../vuln-captures/capture.py's world (the same names
and digests, so the two sets join), then one signature result per image
as the supplychain component would post it, and writes one `{provenance,
request, status, body}` JSON per read into this directory. Nothing here
edits a response. Every verdict the UI draws is covered:

  payments/checkout          verified, keyless (a GitHub Actions release
                             workflow), signed on the multi-arch index,
                             with a verified SLSA provenance attestation
  payments/ledger            verified with a configured key
  payments/reports           unsigned
  observability/grafana      key_signed (a key kguardian was not given)
  observability/prometheus   invalid (bad_signature)
  observability/node-exporter unknown (rate_limited)
  flux-system/source-controller unknown with a reason code this Broker
                             does not know (stored as unrecognised_reason)
  ingress-nginx/controller   no result: not checked

Workload profiles (contract v1.8, images.supplyChain) are captured as
signature-profile-<name>. For the not_configured state, start a Broker with
SIGNATURE_DISCOVERY_ENABLED=false on the same database and run again with
--not-configured: it only captures signature-profile-not-configured-<name>.

Image trust (contract v1.9, images.supplyChain.imageTrust) needs an
evaluator, and the real one needs a Kubernetes API for its policy CRDs. The
seeded Broker is evaluated by ./evaluator-standin instead: the evaluator's own
imagetrust Runner and Handler, with its three policies in the in-memory fake
dynamic client its tests use (no envtest, no cluster):

    evaluator-standin/build.sh /tmp/evaluator-standin   # offline, from the module cache
    /tmp/evaluator-standin -listen 127.0.0.1:<eport> -broker http://127.0.0.1:<port> -token <r>

Start the Broker with EVALUATOR_URL=http://127.0.0.1:<eport> and pass
--evaluator-standin. It reads /attestations/running, so seed first: run this
script with --seed-only, start the stand-in, then run it again with
--evaluator-standin (seeding again is harmless: newer results replace older).
For the unavailable state, restart the Broker with EVALUATOR_URL at a
closed port and run with --evaluator-down (captures signature-profile-evaluator-down-<name>).
"""
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.request

BASE, READ, INGEST, SC, SHA = sys.argv[1:6]
# --not-configured: capture only the workload profiles, from the same database
# served by a Broker started with SIGNATURE_DISCOVERY_ENABLED=false.
NOT_CONFIGURED = '--not-configured' in sys.argv[6:]
# --evaluator-down: capture only the workload profiles, from the same database
# served by a Broker whose EVALUATOR_URL points at a closed port.
EVALUATOR_DOWN = '--evaluator-down' in sys.argv[6:]
# --evaluator-standin: the Broker's EVALUATOR_URL is ./evaluator-standin (the
# evaluator's own imagetrust code with a fake Kubernetes API); the provenance says so.
STANDIN = '--evaluator-standin' in sys.argv[6:]
PROFILES_ONLY = NOT_CONFIGURED or EVALUATOR_DOWN
# --seed-only: post the world and exit (the evaluator stand-in reads it next).
SEED_ONLY = '--seed-only' in sys.argv[6:]
SUFFIX = '-not-configured' if NOT_CONFIGURED else '-evaluator-down' if EVALUATOR_DOWN else ''
HERE = os.path.dirname(os.path.abspath(__file__))
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def ts(hours_ago=0.0, z=False):
    t = NOW - dt.timedelta(hours=hours_ago)
    return t.strftime('%Y-%m-%dT%H:%M:%S') + ('Z' if z else '')


def call(method, path, token, body=None, accept='application/json'):
    req = urllib.request.Request(BASE + path, method=method, headers={'Authorization': f'Bearer {token}', 'Accept': accept})
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def ok(status, text, what):
    if status >= 300:
        raise SystemExit(f'{what}: {status} {text[:300]}')


# ── The world of ../vuln-captures/capture.py (same digests and pods) ───
D = {
    'checkout': 'sha256:f48949f11f15c0e2b8fa2132d1ab201cf50e80dea612783e5c3ac78c6b378235',  # platform manifest
    'checkout-index': 'sha256:17ebfb68fefc63fba2251c8d2ff2d194fa031f8d2b59e63e710a23768136d4ca',
    'ledger': 'sha256:f57d4908af0027fb38feb4e8d5a8d5e2c1511ccf52c596837d2314611f1640fe',
    'reports': 'sha256:7533b1c0c510e06c0385bf2c3d0424c3e7942093c40d9051bf853e610d656dfa',
    'grafana': 'sha256:1eb73105a1fe5826de974a647f3d2e72905e16803a8ca2b9c891bf3545bc242c',
    'prometheus': 'sha256:2f802f6162499e19393cf17fb615e5037cfafd5bd421ed7d36208d0c24ac56e7',
    'node-exporter': 'sha256:f50806e18227349c4b827b7d70cbf67a9ca3087226a89bc3aa6826b13fd1d7fa',
    'source-controller': 'sha256:4832e654a05c1e66ce1982c0300effaca0c7b1a90be575e0f52bd465a12dc18a',
    'ingress-nginx': 'sha256:d6dcbecd496c2f5aa1b3e8d8f2c0b0a4e1c9f7d6b5a4c3e2f1d0c9b8a7f6e5d4',
}
REPO = {
    'checkout': ('ghcr.io/example/checkout', '4.2.0'),
    'ledger': ('ghcr.io/example/ledger', '2.3.1'),
    'reports': ('ghcr.io/example/reports', '1.0.3'),
    'grafana': ('docker.io/grafana/grafana', '11.2.0'),
    'prometheus': ('quay.io/prometheus/prometheus', 'v2.54.1'),
    'node-exporter': ('quay.io/prometheus/node-exporter', 'v1.8.2'),
    'source-controller': ('ghcr.io/fluxcd/source-controller', 'v1.6.2'),
    'ingress-nginx': ('registry.k8s.io/ingress-nginx/controller', 'v1.11.2'),
}
PODS = [
    ('checkout-7d9f8-abcde', 'payments', '10.244.1.10', 'Deployment', 'checkout', 'app', 'checkout', 'running', None, False),
    ('checkout-7d9f8-fghij', 'payments', '10.244.1.11', 'Deployment', 'checkout', 'app', 'checkout', 'running', None, False),
    ('ledger-5c6d7-klmno', 'payments', '10.244.1.20', 'Deployment', 'ledger', 'ledger', 'ledger', 'running', None, False),
    ('reports-29012345-pqrst', 'payments', '10.244.1.30', 'CronJob', 'reports', 'reports', 'reports', 'running', None, False),
    ('grafana-6f7a8-uvwxy', 'observability', '10.244.2.10', 'Deployment', 'grafana', 'grafana', 'grafana', 'running', None, False),
    ('prometheus-0', 'observability', '10.244.2.20', 'StatefulSet', 'prometheus', 'prometheus', 'prometheus', 'running', None, False),
    ('node-exporter-z9y8x', 'observability', '10.0.0.11', 'DaemonSet', 'node-exporter', 'node-exporter', 'node-exporter', 'running', None, True),
    ('source-controller-8b9c0-abcde', 'flux-system', '10.244.3.10', 'Deployment', 'source-controller', 'manager', 'source-controller', 'running', None, False),
    ('ingress-nginx-controller-1a2b3-cdefg', 'ingress-nginx', '10.244.4.10', 'Deployment', 'ingress-nginx-controller', 'controller', 'ingress-nginx', 'running', None, False),
]

def seed():
    for name, ns, ip, kind, wl, container, key, state, reason, host in PODS:
        repo, tag = REPO[key]
        c = {
            'name': container, 'kind': 'regular', 'image': f'{repo}:{tag}', 'image_id': f'{repo}@{D[key]}',
            'digest': D[key], 'digest_kind': 'repo', 'repository': repo, 'tag': tag, 'state': state,
        }
        if reason:
            c['state_reason'] = reason
        body = {
            'pod_name': name, 'pod_namespace': ns, 'pod_ip': ip, 'node_name': 'worker-1', 'is_dead': False,
            'pod_identity': wl, 'workload_selector_labels': {'app.kubernetes.io/name': wl},
            'workload_kind': kind, 'workload_name': wl, 'host_network': host,
            'pod_obj': {'metadata': {'name': name, 'namespace': ns, 'labels': {'app.kubernetes.io/name': wl}}, 'spec': {'hostNetwork': host}},
            'time_stamp': ts(), 'started_at': ts(hours_ago=48), 'containers': [c],
        }
        ok(*call('POST', '/pod/spec', INGEST, body), f'pod {name}')

    # ── Signature results, as the supplychain component posts them ─────────
    GHA = 'https://token.actions.githubusercontent.com'
    CHECKOUT_SAN = 'https://github.com/example-org/checkout/.github/workflows/release.yaml@refs/tags/v4.2.0'
    # A throwaway P-256 public key (generated for these captures; no private key kept)
    # and the sha256 of its DER encoding, as the component reports a configured key.
    LEDGER_PEM = (
        '-----BEGIN PUBLIC KEY-----\n'
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIiPD8en3MRzsqzYYBfQXGi+WsFs0\n'
        '31/MnG5IODS0jF8L/SRsW+uanwUL+beVkFYHHSWIoLEp9DBmVsw/R64M3w==\n'
        '-----END PUBLIC KEY-----\n'
    )
    LEDGER_FP = 'd4d97426189ec7a3bc8a16cc81bfc8ec314b179c4dad1123ff4e167026fc2c41'


    def result(key, verdict, signatures=(), attestations=(), reason=None, hours_ago=3, **extra):
        repo, _ = REPO[key]
        body = {
            'schema_version': 1, 'digest': D[key], 'repository': repo, 'checked_at': ts(hours_ago, z=True),
            'verdict': verdict, 'reason': reason, 'trust_root': 'public-good',
            'signatures': list(signatures), 'attestations': list(attestations),
        }
        body.update(extra)
        ok(*call('POST', f"/images/{D[key]}/attestation", SC, body), f'attestation {key}')


    result('checkout', 'verified', signed_via='index', signed_digest=D['checkout-index'], signatures=[{
        'format': 'sigstore-bundle', 'source': 'referrers', 'verified': True, 'signer_kind': 'keyless',
        'issuer': GHA, 'san': CHECKOUT_SAN, 'integrated_time': ts(72, z=True), 'tlog_index': 123456789,
    }], attestations=[{
        'predicate_type': 'https://slsa.dev/provenance/v1', 'format': 'sigstore-bundle', 'source': 'referrers', 'verified': True,
        'signer_kind': 'keyless', 'issuer': GHA, 'san': CHECKOUT_SAN,
        'payload_sha256': '9b2c4f6e8a0d1c3e5f7a9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a',
        'provenance': {
            'builder_id': 'https://github.com/actions/runner/github-hosted', 'build_type': 'https://actions.github.io/buildtypes/workflow/v1',
            'source_repo': 'https://github.com/example-org/checkout', 'source_commit': '4f1c2a9e7b3d5f60819a2b3c4d5e6f7081920a1b',
            'source_ref': 'refs/tags/v4.2.0',
        },
    }])
    result('ledger', 'verified', signed_via='self', signed_digest=D['ledger'], signatures=[{
        'format': 'cosign-legacy', 'source': 'sig-tag', 'verified': True, 'signer_kind': 'key',
        'key_name': 'payments-release', 'key_fingerprint': LEDGER_FP, 'key_pem': LEDGER_PEM,
    }])
    result('reports', 'unsigned')
    result('grafana', 'key_signed', signatures=[{
        'format': 'cosign-legacy', 'source': 'sig-tag', 'verified': False, 'error': 'untrusted_key',
        'detail': 'signed with a public key that is not configured', 'key_hint': 'grafana-release',
    }])
    result('prometheus', 'invalid', reason='bad_signature', signatures=[{
        'format': 'cosign-legacy', 'source': 'sig-tag', 'verified': False, 'error': 'bad_signature',
        'detail': 'signature does not verify against the certificate',
    }])
    result('node-exporter', 'unknown', reason='rate_limited')
    result('source-controller', 'unknown', reason='oci_referrers_v2_required')  # a code this Broker does not know



if not PROFILES_ONLY:
    seed()
if SEED_ONLY:
    print('seeded; start ./evaluator-standin, then run again with --evaluator-standin')
    sys.exit(0)

# ── Capture ────────────────────────────────────────────────────────────
PROVENANCE = f'captured from broker {SHA} (frontend/src/fixtures/attestation-captures/capture.py), no edits'
if STANDIN:
    PROVENANCE += "; image trust results from ./evaluator-standin (the evaluator's own imagetrust Runner and Handler over the real Broker, Kubernetes API replaced by the in-memory fake client; no cluster)"
if EVALUATOR_DOWN:
    PROVENANCE += '; EVALUATOR_URL pointed at a closed port'


def capture(name, path, accept='application/json'):
    st, text = call('GET', path, READ, accept=accept)
    try:
        body = json.loads(text)
    except ValueError:
        body = text
    with open(os.path.join(HERE, name + '.json'), 'w') as f:
        json.dump({'provenance': PROVENANCE, 'request': 'GET ' + path, 'status': st, 'body': body}, f, indent=2, sort_keys=True)
        f.write('\n')
    return body


def capture_attestation_reads():
    REQUESTS = {
        'attestations': '/attestations',
        'attestations-verified': '/attestations?verdict=verified',
        'attestations-page1-limit3': '/attestations?limit=3',
        'attestations-running': '/attestations/running',
        'attestations-running-namespace-payments': '/attestations/running?namespace=payments',
        'attestations-running-namespace-observability': '/attestations/running?namespace=observability',
        'attestations-running-namespace-flux-system': '/attestations/running?namespace=flux-system',
        'attestations-running-namespace-ingress-nginx': '/attestations/running?namespace=ingress-nginx',
        'attestations-running-namespace-empty': '/attestations/running?namespace=no-such-namespace',
        'attestation-bad-digest': '/images/latest/attestation',
    }
    for key in ('checkout', 'ledger', 'reports', 'grafana', 'prometheus', 'node-exporter', 'source-controller', 'ingress-nginx'):
        REQUESTS[f'attestation-{key}'] = f'/images/{D[key]}/attestation'
    for name, path in REQUESTS.items():
        capture(name, path)

    p = json.load(open(os.path.join(HERE, 'attestations-page1-limit3.json')))['body']
    if p.get('nextAfter'):
        capture('attestations-page2-limit3', f"/attestations?limit=3&after={p['nextAfter']}")

    # Admission policies, audit mode only (what the UI offers).
    for fmt in ('kguardian', 'kyverno', 'policy-controller'):
        capture(f'policy-{fmt}-audit', f'/attestations/policy?format={fmt}&mode=audit', 'application/yaml')
    capture('policy-kguardian-audit-namespace-payments', '/attestations/policy?format=kguardian&mode=audit&namespace=payments', 'application/yaml')
    for ns, kind, wl in (('payments', 'Deployment', 'checkout'), ('payments', 'CronJob', 'reports'), ('observability', 'Deployment', 'grafana')):
        capture(f'export-admission-{wl}', f'/workloads/{ns}/{kind}/{wl}/export?artifacts=admission&mode=audit&format=zip-manifest')


if not PROFILES_ONLY:
    capture_attestation_reads()

# Workload profiles (contract v1.8 carries dimensions.images.supplyChain).
# Named signature-profile-* so they do not collide with the vulnerability
# world's profile-* captures.
WORKLOADS = [('payments', 'Deployment', 'checkout'), ('payments', 'Deployment', 'ledger'), ('payments', 'CronJob', 'reports'),
             ('observability', 'Deployment', 'grafana'), ('observability', 'StatefulSet', 'prometheus'),
             ('observability', 'DaemonSet', 'node-exporter'), ('flux-system', 'Deployment', 'source-controller'),
             ('ingress-nginx', 'Deployment', 'ingress-nginx-controller')]
for ns, kind, wl in WORKLOADS:
    capture(f'signature-profile{SUFFIX}-{wl}', f'/workloads/{ns}/{kind}/{wl}/profile')

print('captured', len([f for f in os.listdir(HERE) if f.endswith('.json')]), 'responses from', SHA, '(profiles only, signature discovery off)' if NOT_CONFIGURED else '(profiles only, evaluator down)' if EVALUATOR_DOWN else '')
