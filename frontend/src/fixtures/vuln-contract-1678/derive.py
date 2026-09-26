"""Derive #1678-shaped fixtures from the #1671 captures.

Adds tier, tierFactors, inUseDetail and the CVE tier counts that the in-use
tiers release (#1678) puts on the vulnerability reads. The values are set
by hand in F below, following #1678's tier rule; nothing here was captured
from a Broker. Re-run after changing F:  python3 derive.py
Replace the output with real captures once #1678 merges.
"""
import json, os, copy
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, '..', 'vuln-captures')
DST = HERE
PROV = ("contract-derived, not captured: the #1671 capture of the same request with the fields #1678 "
        "(feat/1533-in-use-tiers @ 0c25f288) adds. In-use states and exposure are set by hand in derive.py; KEV/EPSS "
        "are resolved per CVE across every source row, and tier/tierFactors are computed with broker/src/in_use.rs "
        "tier() at default settings (EPSS 0.1, unknown exposure counts as exposed). "
        "Replace with real captures once #1678 merges.")
def load(n): return json.load(open(os.path.join(SRC, n + '.json')))
def save(n, cap):
    cap = {'provenance': PROV, **cap}
    json.dump(cap, open(os.path.join(DST, n + '.json'), 'w'), indent=2, sort_keys=True); open(os.path.join(DST, n + '.json'), 'a').write('\n')
OBS = '2026-09-25T03:00:00'
def detail(state, reason, coverage, covered=True):
    return {'state': state, 'reason': reason, 'observedSince': OBS if covered else None, 'windowHours': 24, 'containers': 1, 'coverage': coverage}
# (image, cve) -> (in-use state, unknown reason, coverage, exposure factor). The
# tier is computed below with the broker's rule, never set here.
F = {
 ('checkout','CVE-2099-0001'): ('loaded',None,'file','exposed'),
 ('checkout','CVE-2099-0002'): ('unknown','language_package','interpreted','exposed'),
 ('checkout','CVE-2099-0007'): ('unknown','language_package','interpreted','exposed'),
 ('checkout','CVE-2099-0003'): ('loaded',None,'file','exposed'),
 ('checkout','CVE-2099-0004'): ('installed_not_observed',None,'file','exposed'),
 ('ledger','CVE-2099-0001'): ('loaded',None,'file','internal'),
 ('ledger','CVE-2099-0005'): ('unknown','capture_gap','file','internal'),
 ('reports','CVE-2099-0001'): ('unknown','no_runtime_data','file','exposure:unknown'),
 ('grafana','CVE-2099-0006'): ('executed',None,'static_binary','exposed'),
 ('grafana','CVE-2099-0003'): ('unknown','no_package_files','file','exposed'),
 ('prometheus','CVE-2099-0006'): ('executed',None,'static_binary','exposed'),
}
EPSS_T = 0.1
SEV_RANK = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'NONE': 1, 'UNKNOWN': 0}

def broker_tier(state, severity, kev, epss, exp, fixable):
    """broker/src/in_use.rs tier(), default settings."""
    if state == 'installed_not_observed':
        return 'Background'
    exposed = {'exposed': True, 'internal': False, 'exposure:unknown': True}[exp]
    hot = bool(kev) or (epss is not None and epss >= EPSS_T)
    if hot and exposed: return 'P0'
    if hot: return 'P1'
    r = SEV_RANK[severity]
    if r == 4 and not fixable and not exposed: return 'P2'
    if r in (4, 5): return 'P1'
    return 'P2'

IN_USE_BOOL = {'executed': True, 'loaded': True, 'installed_not_observed': False, 'unknown': None}
def factors(f, state, exp):
    out = [f'in_use:{state}']
    if f['kev']: out.append('kev')
    if f['epss'] is not None and f['epss'] >= 0.1: out.append('epss>=0.1')
    out.append('severity:' + f['severity'].lower())
    out.append(exp)
    if not f['fixable']: out.append('no_fix')
    return out
IMAGES = ['checkout','ledger','reports','grafana','prometheus','source-controller','node-exporter']
# #1678 @ 0c25f288: KEV and EPSS are per CVE over every source row of every
# image (kev true if any says true, false if some says false and none true,
# null if none reports it; EPSS and its percentile the highest).
rows = [f for n in IMAGES for f in load(f'image-{n}-vulnerabilities')['body']['items']]
CVL = {}
for f in rows:
    c = CVL.setdefault(f['id'], {'kev': None, 'kevDateAdded': None, 'epss': None, 'epssPercentile': None})
    if f['kev'] is True or (f['kev'] is False and c['kev'] is None): c['kev'] = f['kev']
    if f['kevDateAdded'] and (c['kevDateAdded'] is None or f['kevDateAdded'] < c['kevDateAdded']): c['kevDateAdded'] = f['kevDateAdded']
    for k in ('epss', 'epssPercentile'):
        if f[k] is not None and (c[k] is None or f[k] > c[k]): c[k] = f[k]
TIERS = {}
for n in IMAGES:
    cap = load(f'image-{n}-vulnerabilities')
    for f in cap['body']['items']:
        f.update(CVL[f['id']])
        state, reason, cov, exp = F[(n, f['id'])]
        tier = broker_tier(state, f['severity'], f['kev'], f['epss'], exp, f['fixable'])
        TIERS[(n, f['id'])] = tier
        f['inUse'] = IN_USE_BOOL[state]; f['inUseState'] = state
        f['inUseDetail'] = detail(state, reason, cov, covered=(n != 'reports'))
        f['tier'] = tier; f['tierFactors'] = factors(f, state, exp)
    save(f'image-{n}-vulnerabilities', cap)
    hot = copy.deepcopy(cap)
    hot['request'] = cap['request'] + '?tier=P0,P1'
    hot['body']['items'] = [f for f in cap['body']['items'] if f['tier'] in ('P0', 'P1')]
    save(f'image-{n}-vulnerabilities-p0p1', hot)
RANK = {'P0':3,'P1':2,'P2':1,'Background':0}
STRONG = ['executed','loaded','unknown','installed_not_observed']
cves = load('vulnerabilities')
# which image names each CVE's workloads run, from the exposures
for c in cves['body']['items']:
    e = load(f"exposure-{c['id']}")['body']
    digest_name = {load(f'image-{n}')['body']['digest']: n for n in IMAGES}
    rows = []
    for w in e['workloads']:
        name = w['name']
        state, reason, cov, exp = F[(name, c['id'])]
        tier = TIERS[(name, c['id'])]
        rows.append((tier, state, exp))
        w['inUse'] = IN_USE_BOOL[state]; w['inUseState'] = state
    top = min((r[1] for r in rows), key=STRONG.index)
    e['inUse'] = IN_USE_BOOL[top]; e['inUseState'] = top
    save(f"exposure-{c['id']}", {'request': f"GET /vulnerabilities/{c['id']}/exposure", 'status': 200, 'body': e})
    c['tier'] = max((r[0] for r in rows), key=RANK.get)
    c['executedWorkloads'] = sum(r[1] == 'executed' for r in rows)
    c['loadedWorkloads'] = sum(r[1] == 'loaded' for r in rows)
    c['unknownWorkloads'] = sum(r[1] == 'unknown' for r in rows)
    c['notObservedWorkloads'] = sum(r[1] == 'installed_not_observed' for r in rows)
    c['exposedWorkloads'] = sum(r[2] == 'exposed' for r in rows)
    c['inUse'] = IN_USE_BOOL[top]; c['inUseState'] = top
save('vulnerabilities', cves)
print([(c['id'], c['tier'], c['inUseState'], c['exposedWorkloads']) for c in cves['body']['items']])
