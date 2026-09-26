"""Seed a local Broker through its real ingest routes and capture what the UI reads.

Run a Broker built from the commit you want captures of, against an empty
database, with scoped auth on (the supply-chain routes refuse writes
without it) and the shortest supply-chain retention interval. That loop
rebuilds the CVE summary and the report-to-inventory links; its first pass
runs 45 s after the Broker starts, then every interval, and the Broker
enforces a 60 s floor on the interval. TELEMETRY_ENABLED=false keeps a
scratch Broker from sending the anonymous version check-in:

    BROKER_TOKEN_READ=<r> BROKER_TOKEN_INGEST=<i> BROKER_TOKEN_SUPPLYCHAIN=<s> \\
    TELEMETRY_ENABLED=false SUPPLYCHAIN_RETENTION_INTERVAL_SECS=60 DATABASE_URL=... LISTEN_ADDR=127.0.0.1:<port> broker

then:

    python3 capture.py http://127.0.0.1:<port> <r> <i> <s> <broker git sha>

Set CAPTURE_INTERVAL_SECS if the Broker runs a longer interval (default
60). It posts pods (with `containers[]`), traffic, vulnerability reports
and SBOMs, waits for a rebuild and then one more (so every link and the
exposure view are current; a few minutes in all), then writes one `{provenance,
request, status, body}` JSON per read into this directory. Nothing here
edits a response.

The world is neutral: payments (checkout, ledger, reports CronJob),
observability (grafana, prometheus, node-exporter on the host network),
flux-system (source-controller) and ingress-nginx, with fictional
CVE-2099-* ids. Findings, text and SBOMs match the earlier #1671 captures
(../vuln-captures-1671), so the same scenarios are covered.
"""
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE, READ, INGEST, SC, SHA = sys.argv[1:6]
HERE = os.path.dirname(os.path.abspath(__file__))
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def ts(hours_ago=0.0, z=False):
    t = NOW - dt.timedelta(hours=hours_ago)
    return t.strftime('%Y-%m-%dT%H:%M:%S') + ('Z' if z else '')


def call(method, path, token, body=None):
    req = urllib.request.Request(BASE + path, method=method, headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'})
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


# ── Images (digests are fictional but well formed) ─────────────────────
D = {
    'checkout': 'sha256:f48949f11f15c0e2b8fa2132d1ab201cf50e80dea612783e5c3ac78c6b378235',  # platform manifest
    'checkout-index': 'sha256:17ebfb68fefc63fba2251c8d2ff2d194fa031f8d2b59e63e710a23768136d4ca',
    'ledger': 'sha256:f57d4908af0027fb38feb4e8d5a8d5e2c1511ccf52c596837d2314611f1640fe',
    'reports': 'sha256:7533b1c0c510e06c0385bf2c3d0424c3e7942093c40d9051bf853e610d656dfa',
    'grafana': 'sha256:1eb73105a1fe5826de974a647f3d2e72905e16803a8ca2b9c891bf3545bc242c',
    'prometheus': 'sha256:2f802f6162499e19393cf17fb615e5037cfafd5bd421ed7d36208d0c24ac56e7',
    'prometheus-report': 'sha256:e01dcbccb64f2d4d69fc6ad2bf19dd3a0e9e32bd1d84f8a2b1b7c6c4f3d0e1a2',  # not in the inventory: tag-only join
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

# ── Pods: (name, namespace, ip, kind, workload, container, image key, state, reason, host_network)
PODS = [
    ('checkout-7d9f8-abcde', 'payments', '10.244.1.10', 'Deployment', 'checkout', 'app', 'checkout', 'running', None, False),
    ('checkout-7d9f8-fghij', 'payments', '10.244.1.11', 'Deployment', 'checkout', 'app', 'checkout', 'running', None, False),
    ('ledger-5c6d7-klmno', 'payments', '10.244.1.20', 'Deployment', 'ledger', 'ledger', 'ledger', 'running', None, False),
    ('reports-29012345-pqrst', 'payments', '10.244.1.30', 'CronJob', 'reports', 'reports', 'reports', 'terminated', 'Completed', False),
    ('grafana-6f7a8-uvwxy', 'observability', '10.244.2.10', 'Deployment', 'grafana', 'grafana', 'grafana', 'running', None, False),
    ('prometheus-0', 'observability', '10.244.2.20', 'StatefulSet', 'prometheus', 'prometheus', 'prometheus', 'running', None, False),
    ('node-exporter-z9y8x', 'observability', '10.0.0.11', 'DaemonSet', 'node-exporter', 'node-exporter', 'node-exporter', 'running', None, True),
    ('source-controller-8b9c0-abcde', 'flux-system', '10.244.3.10', 'Deployment', 'source-controller', 'manager', 'source-controller', 'running', None, False),
    ('ingress-nginx-controller-1a2b3-cdefg', 'ingress-nginx', '10.244.4.10', 'Deployment', 'ingress-nginx-controller', 'controller', 'ingress-nginx', 'running', None, False),
]

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


# ── Traffic (the reporting pod's view; peers are stamped by the broker) ─
def flow(pod, direction, peer_ip, peer_port, pod_port, hours_ago):
    name, ns, ip = next((p[0], p[1], p[2]) for p in PODS if p[0] == pod)
    return {
        'uuid': str(uuid.uuid4()), 'pod_name': name, 'pod_namespace': ns, 'pod_ip': ip, 'pod_port': pod_port,
        'ip_protocol': 'TCP', 'traffic_type': direction, 'traffic_in_out_ip': peer_ip, 'traffic_in_out_port': peer_port,
        'decision': 'ALLOW', 'time_stamp': ts(hours_ago=hours_ago),
    }


FLOWS = [
    flow('checkout-7d9f8-abcde', 'INGRESS', '10.244.4.10', '41234', '8080', 2),  # ingress-nginx: other namespace
    flow('checkout-7d9f8-abcde', 'INGRESS', '81.2.69.160', '51000', '8080', 3),  # a public client, unattributed
    flow('checkout-7d9f8-fghij', 'INGRESS', '10.244.1.20', '42000', '8080', 4),  # ledger: same namespace
    flow('checkout-7d9f8-abcde', 'EGRESS', '10.244.1.20', '5432', '38000', 2),
    flow('ledger-5c6d7-klmno', 'INGRESS', '10.244.1.10', '38000', '5432', 2),  # checkout: same namespace only
    flow('grafana-6f7a8-uvwxy', 'INGRESS', '10.244.4.10', '41300', '3000', 5),  # ingress-nginx: other namespace
    flow('prometheus-0', 'INGRESS', '10.0.0.11', '43000', '9090', 1),  # a node (host-network peer)
    flow('source-controller-8b9c0-abcde', 'EGRESS', '140.82.112.3', '443', '39000', 1),  # egress only
]
ok(*call('POST', '/pod/traffic/batch', INGEST, FLOWS), 'traffic')

# ── Findings and SBOMs: text from the #1671 captures, so nothing is invented here ─
OLD = os.path.join(HERE, '..', 'vuln-captures-1671')


def old(name):
    with open(os.path.join(OLD, name + '.json')) as f:
        return json.load(f)['body']


def vuln(f, source):
    v = {
        'id': f['id'],
        'package': {'name': f['package']['name'], 'version': f['installedVersion'], 'type': f['package']['type'], 'purl': f['package']['purl']},
        'severity': f['severity'], 'score': f['score'], 'title': f['title'], 'primary_url': f['primaryUrl'],
        'file_paths': f['filePaths'],
    }
    if f['fixedVersions']:
        # The #1671 capture merged sources: Grype gave the first fixed version, Trivy the last.
        v['fixed_version'] = f['fixedVersions'][0] if source == 'grype' else f['fixedVersions'][-1]
    if source == 'grype':
        for src, dst in (('kev', 'kev'), ('kevDateAdded', 'kev_date_added'), ('epss', 'epss'), ('epssPercentile', 'epss_percentile')):
            if f[src] is not None:
                v[dst] = f[src] + 'Z' if dst == 'kev_date_added' else f[src]
    return v


def image(key, digest=None, kind='manifest', platform=None):
    repo, tag = REPO[key]
    registry, _, rest = repo.partition('/')
    img = {'digest': digest or D[key], 'ref': f'{repo}:{tag}', 'registry': registry, 'repository': rest, 'tag': tag, 'digest_kind': kind}
    if platform:
        img['platform_manifests'] = platform
    return img


TRIVY = {'name': 'Trivy', 'vendor': 'Aqua Security', 'version': '0.58.1'}
GRYPE = {'name': 'grype', 'vendor': 'Anchore', 'version': '0.86.1'}


def post_vulns(key, source, findings, hours_ago, img=None, observed=None, extra=None):
    body = {
        'schema_version': 1, 'image': img or image(key), 'source': source,
        'scanner': TRIVY if source == 'trivy-operator' else GRYPE, 'scanned_at': ts(hours_ago, z=True),
        'os': {'family': 'alpine', 'name': '3.20.3'}, 'observed_in': observed or [],
        'sbom_trust': 'scanned', 'vulnerabilities': [vuln(f, source) for f in findings],
    }
    body.update(extra or {})
    digest = body['image']['digest']
    ok(*call('POST', f'/images/{digest}/vulnerabilities', SC, body), f'vulns {key} {source}')


def items(name, source):
    return [f for f in old(f'image-{name}-vulnerabilities')['items'] if source in f['sources']]


checkout_img = image('checkout', D['checkout-index'], 'index', {'linux/amd64': D['checkout']})
post_vulns('checkout', 'trivy-operator', items('checkout', 'trivy-operator'), 6, checkout_img,
           [{'namespace': 'payments', 'kind': 'ReplicaSet', 'name': 'checkout-7d9f8', 'container': 'app'}])
post_vulns('checkout', 'grype', items('checkout', 'grype'), 2, checkout_img, [],
           {'sbom_sources': ['trivy-operator'], 'db_updated_at': ts(20, z=True)})
for key in ('ledger', 'reports', 'grafana', 'source-controller'):
    post_vulns(key, 'trivy-operator', items(key, 'trivy-operator'), 6)
post_vulns('prometheus', 'trivy-operator', items('prometheus', 'trivy-operator'), 30,
           image('prometheus', D['prometheus-report'], 'unknown'),
           [{'namespace': 'observability', 'kind': 'StatefulSet', 'name': 'prometheus', 'container': 'prometheus'}])


def component(c):
    out = {k: c[k] for k in ('name', 'version', 'purl', 'type') if c.get(k) is not None}
    if c.get('licenses'):
        out['licenses'] = c['licenses']
    return out


def post_sbom(key, source, img, comps, hours_ago, trust, attestation=None):
    body = {
        'schema_version': 1, 'image': img, 'source': source, 'scanned_at': ts(hours_ago, z=True),
        'scanner': TRIVY if source == 'trivy-operator' else {'name': 'registry', 'vendor': attestation['mechanism']},
        'format': 'CycloneDX', 'spec_version': '1.5', 'observed_in': [], 'sbom_trust': trust,
        'components': [component(c) for c in comps],
    }
    if attestation:
        body['attestation'] = attestation
    ok(*call('POST', f"/images/{img['digest']}/sbom", SC, body), f'sbom {key} {source}')


post_sbom('checkout', 'trivy-operator', checkout_img, old('image-checkout-sbom')['items'], 6, 'scanned')
for key, trust in (('grafana', 'attached-unbound'), ('source-controller', 'verified')):
    s = old(f'image-{key}-sbom')
    att = dict(s['reports'][0]['attestation'])
    post_sbom(key, 'registry', image(key), s['items'], 8, trust, att)

# ── Wait for the summary rebuild and the link refresh ─────────────────
INTERVAL = max(60, int(os.environ.get('CAPTURE_INTERVAL_SECS', '60')))


def computed_at():
    st, text = call('GET', '/vulnerabilities', READ)
    if st != 200:
        return None
    body = json.loads(text)
    return body.get('computedAt') if body.get('items') else None


def wait_for(pred, secs, what):
    deadline = time.monotonic() + secs
    while time.monotonic() < deadline:
        v = pred()
        if v:
            return v
        time.sleep(2)
    raise SystemExit(f'{what} within {secs} s; is SUPPLYCHAIN_RETENTION_INTERVAL_SECS {INTERVAL}?')


# The first pass may have run before the seed finished, so wait for a
# rebuild with findings, then for the pass after it.
first = wait_for(computed_at, 45 + INTERVAL + 60, 'the CVE summary never rebuilt')
wait_for(lambda: (c := computed_at()) and c != first, INTERVAL + 60, 'no second supply-chain pass')

# ── Capture ────────────────────────────────────────────────────────────
PROVENANCE = f'captured from broker {SHA} (frontend/src/fixtures/vuln-captures/capture.py), no edits'
NAMES = {'checkout': D['checkout'], 'ledger': D['ledger'], 'reports': D['reports'], 'grafana': D['grafana'],
         'prometheus': D['prometheus'], 'node-exporter': D['node-exporter'], 'source-controller': D['source-controller']}
REQUESTS = {
    'vulnerabilities': '/vulnerabilities',
    'vulnerabilities-critical': '/vulnerabilities?severity=CRITICAL',
    'vulnerabilities-fixable': '/vulnerabilities?fixable=true',
    'vulnerabilities-running': '/vulnerabilities?running=true',
    'vulnerabilities-tier-p0': '/vulnerabilities?tier=P0',
    'vulnerabilities-page1-limit2': '/vulnerabilities?limit=2',
    'vulnerabilities-namespace-payments': '/vulnerabilities?namespace=payments',
    'vulnerabilities-namespace-observability': '/vulnerabilities?namespace=observability',
    'vulnerabilities-namespace-flux-system': '/vulnerabilities?namespace=flux-system',
    'images': '/images',
    'images-page1-limit3': '/images?limit=3',
    'images-namespace-payments': '/images?namespace=payments',
    'images-namespace-observability': '/images?namespace=observability',
    'image-bad-digest': '/images/latest/vulnerabilities',
    'exposure-not-found': '/vulnerabilities/CVE-2099-9999/exposure',
}
for n, d in NAMES.items():
    REQUESTS[f'image-{n}'] = f'/images/{d}'
    REQUESTS[f'image-{n}-vulnerabilities'] = f'/images/{d}/vulnerabilities'
    REQUESTS[f'image-{n}-vulnerabilities-p0p1'] = f'/images/{d}/vulnerabilities?tier=P0,P1'
    REQUESTS[f'image-{n}-sbom'] = f'/images/{d}/sbom'
for i in range(1, 8):
    REQUESTS[f'exposure-CVE-2099-000{i}'] = f'/vulnerabilities/CVE-2099-000{i}/exposure'


def capture(name, path):
    st, text = call('GET', path, READ)
    try:
        body = json.loads(text)
    except ValueError:
        body = text
    with open(os.path.join(HERE, name + '.json'), 'w') as f:
        json.dump({'provenance': PROVENANCE, 'request': 'GET ' + path, 'status': st, 'body': body}, f, indent=2, sort_keys=True)
        f.write('\n')
    return body


for name, path in REQUESTS.items():
    capture(name, path)

# Second pages follow the cursor the first page returned.
p = json.load(open(os.path.join(HERE, 'vulnerabilities-page1-limit2.json')))['body']
if p.get('nextAfter'):
    capture('vulnerabilities-page2-limit2', f"/vulnerabilities?limit=2&after={p['nextAfter']}")
p = json.load(open(os.path.join(HERE, 'images-page1-limit3.json')))['body']
if p.get('nextAfter'):
    capture('images-page2-limit3', f"/images?limit=3&after={p['nextAfter']}")
print('captured', len(os.listdir(HERE)) - 1, 'responses from', SHA)
