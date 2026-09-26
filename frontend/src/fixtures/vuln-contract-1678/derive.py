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
        "(feat/1533-in-use-tiers @ 1cc299a3) adds, set by hand per its docs/api-reference/endpoints/vulnerabilities.mdx "
        "and broker/src/in_use.rs tier() with default settings (EPSS 0.1, unknown exposure counts as exposed). "
        "Replace with real captures once #1678 merges.")
def load(n): return json.load(open(os.path.join(SRC, n + '.json')))
def save(n, cap):
    cap = {'provenance': PROV, **cap}
    json.dump(cap, open(os.path.join(DST, n + '.json'), 'w'), indent=2, sort_keys=True); open(os.path.join(DST, n + '.json'), 'a').write('\n')
OBS = '2026-09-25T03:00:00'
def detail(state, reason, coverage, covered=True):
    return {'state': state, 'reason': reason, 'observedSince': OBS if covered else None, 'windowHours': 24, 'containers': 1, 'coverage': coverage}
# (image, cve) -> (tier, state, reason, coverage, exposure factor)
F = {
 ('checkout','CVE-2099-0001'): ('P0','loaded',None,'file','exposed'),
 ('checkout','CVE-2099-0002'): ('P1','unknown','language_package','interpreted','exposed'),
 ('checkout','CVE-2099-0007'): ('P1','unknown','language_package','interpreted','exposed'),
 ('checkout','CVE-2099-0003'): ('P2','loaded',None,'file','exposed'),
 ('checkout','CVE-2099-0004'): ('Background','installed_not_observed',None,'file','exposed'),
 ('ledger','CVE-2099-0001'): ('P1','loaded',None,'file','internal'),
 ('ledger','CVE-2099-0005'): ('P2','unknown','capture_gap','file','internal'),
 ('reports','CVE-2099-0001'): ('P1','unknown','no_runtime_data','file','exposure:unknown'),
 ('grafana','CVE-2099-0006'): ('P1','executed',None,'static_binary','exposed'),
 ('grafana','CVE-2099-0003'): ('P2','unknown','no_package_files','file','exposed'),
 ('prometheus','CVE-2099-0006'): ('P1','executed',None,'static_binary','exposed'),
}
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
for n in IMAGES:
    cap = load(f'image-{n}-vulnerabilities')
    for f in cap['body']['items']:
        tier, state, reason, cov, exp = F[(n, f['id'])]
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
        tier, state, reason, cov, exp = F[(name, c['id'])]
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
