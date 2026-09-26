import { expect, test } from 'vitest';
import { ALL_CAPTURES, PROFILE_CAPTURES } from './profile';

// The fixtures are raw Broker captures cast to the UI's types. A cast checks
// nothing, so this pins the parts of the contract the UI relies on: if a
// re-capture drifts, it fails here instead of rendering something wrong.

const walk = (o: unknown, path: string, visit: (key: string, path: string) => void) => {
  if (Array.isArray(o)) o.forEach((x, i) => walk(x, `${path}[${i}]`, visit));
  else if (o && typeof o === 'object') {
    for (const [k, v] of Object.entries(o)) {
      visit(k, `${path}.${k}`);
      walk(v, `${path}.${k}`, visit);
    }
  }
};

test('v1.2: no numeric score survives anywhere in any capture', () => {
  const found: string[] = [];
  for (const c of ALL_CAPTURES) {
    walk(c.body, c.request, (k, p) => {
      if (['score', 'scored', 'grade', 'weights', 'deductions'].includes(k)) found.push(p);
    });
  }
  expect(found).toEqual([]);
});

test('every profile capture carries the fields the page reads', () => {
  for (const { request, status, body: p } of PROFILE_CAPTURES) {
    expect(status, request).toBe(200);
    expect(Object.keys(p).sort(), request).toEqual(
      ['attention', 'contentHash', 'controls', 'dimensions', 'exposure', 'findings', 'generatedAt', 'posture', 'readiness', 'snapshotPending', 'version', 'workload'].sort(),
    );
    expect(Object.keys(p.posture).sort(), request).toEqual(['coverage', 'reasons', 'status', 'unknownDimensions']);
    expect(Object.keys(p.dimensions).sort(), request).toEqual(['compute', 'images', 'network', 'podSecurity', 'syscalls']);
    for (const [name, d] of Object.entries(p.dimensions)) {
      expect(['ok', 'warn', 'risk', 'unknown'], `${request} ${name}`).toContain(d.status);
      expect(d.coverage, `${request} ${name}`).toHaveProperty('level');
      expect(Array.isArray(d.reasons), `${request} ${name}`).toBe(true);
    }
    expect(p.dimensions.podSecurity).toHaveProperty('staleContainers');
    expect(p.dimensions.podSecurity.pod).toHaveProperty('known');
    for (const c of p.dimensions.images.containers) expect(typeof c.stale, request).toBe('boolean');
    // unknownDimensions = core dimensions whose status is unknown (v1.2).
    const core = ['network', 'syscalls', 'podSecurity', 'images'] as const;
    expect([...p.posture.unknownDimensions].sort(), request).toEqual(core.filter((d) => p.dimensions[d].status === 'unknown').sort());
    // readiness podSecurityRestricted is never true (restricted is only an upper bound).
    expect(p.readiness.find((r) => r.id === 'podSecurityRestricted')?.ok, request).not.toBe(true);
  }
});

test('captures use neutral namespaces only', () => {
  const allowed = new Set(['payments', 'observability', 'flux-system', 'ingress-nginx', 'kube-system']);
  for (const c of ALL_CAPTURES) {
    const nss = [...JSON.stringify(c.body).matchAll(/"namespace":"([^"]+)"/g)].map((m) => m[1]);
    for (const ns of nss) expect(allowed, `${c.request}: ${ns}`).toContain(ns);
  }
});
