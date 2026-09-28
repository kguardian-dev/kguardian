import { expect, test } from 'vitest';
import { DEFAULT_VIEW, LEGACY_VIEWS, legacyRedirect, isAllNamespaces, resolveRoute, routeHref, workloadParams, workloadsBackParams } from './routes';

// Old links live in tickets, runbooks and browser history. A rename that
// silently sends them to the map is a broken link; these pin the redirects.

test('#/findings redirects to #/risks and keeps its params', () => {
  const r = resolveRoute({ view: 'findings', params: { ns: 'payments' } });
  expect(r.view).toBe('risks');
  expect(r.redirect).toEqual({ view: 'risks', params: { ns: 'payments' } });
});

test('#/seccomp redirects to the Workloads seccomp columns, keeping its namespace scope', () => {
  const r = resolveRoute({ view: 'seccomp', params: { ns: 'observability' } });
  expect(r.view).toBe('workloads');
  expect(r.redirect).toEqual({ view: 'workloads', params: { ns: 'observability', control: 'seccomp', scope: 'ns' } });
  // No namespace in the old link: nothing to narrow to.
  expect(resolveRoute({ view: 'seccomp', params: {} }).redirect).toEqual({ view: 'workloads', params: { control: 'seccomp' } });
});

test('workload links carry the list context and Back restores it', () => {
  const p = workloadParams('payments', 'Deployment', 'api', { scope: 'ns', control: 'seccomp' });
  expect(p).toEqual({ ns: 'payments', kind: 'Deployment', name: 'api', scope: 'ns', control: 'seccomp' });
  expect(workloadsBackParams(p)).toEqual({ ns: 'payments', scope: 'ns', control: 'seccomp' });
  // The profile page's own params (tab, diff selection) never leak into the list.
  expect(workloadsBackParams({ ...p, tab: 'versions', from: '1', to: '2' })).toEqual({ ns: 'payments', scope: 'ns', control: 'seccomp' });
  expect(workloadParams('payments', 'Deployment', 'api')).toEqual({ ns: 'payments', kind: 'Deployment', name: 'api' });
  // Opened off a cluster-wide list (no scope): Back returns to the cluster-wide list, so the workload's namespace does not ride along.
  expect(workloadsBackParams({ ns: 'payments', kind: 'Deployment', name: 'api' })).toEqual({});
  expect(workloadsBackParams({ ns: 'payments', kind: 'Deployment', name: 'api', control: 'seccomp' })).toEqual({ control: 'seccomp' });
  expect(routeHref('workload', { ns: 'a b', kind: 'Deployment', name: 'x' })).toBe('#/workload?ns=a+b&kind=Deployment&name=x');
});

test('current routes resolve to themselves with no redirect', () => {
  for (const view of ['map', 'risks', 'workloads', 'workload']) {
    expect(resolveRoute({ view, params: {} })).toEqual({ view });
  }
});

test('Object.prototype names in the hash are unknown routes, never redirects', () => {
  // CodeQL js/unvalidated-dynamic-method-call: an object-literal lookup
  // resolved these to inherited methods and invoked them as redirects.
  for (const view of ['constructor', 'toString', '__proto__', 'hasOwnProperty', 'valueOf']) {
    expect(resolveRoute({ view, params: { ns: 'payments' } })).toEqual({ view: DEFAULT_VIEW });
  }
});

test('unknown and empty routes land on the map without a redirect', () => {
  expect(resolveRoute({ view: '', params: {} })).toEqual({ view: 'map' });
  expect(resolveRoute({ view: 'nope', params: { ns: 'x' } })).toEqual({ view: 'map' });
});

test('Workloads and Images default to all namespaces; a named namespace or scope=ns narrows them; other views are always scoped', () => {
  expect(isAllNamespaces('workloads', {})).toBe(true);
  expect(isAllNamespaces('images', {})).toBe(true);
  expect(isAllNamespaces('workloads', { scope: 'ns' })).toBe(false);
  // IMG-08: a shared link that names a namespace shows that namespace.
  expect(isAllNamespaces('images', { ns: 'argocd' })).toBe(false);
  expect(isAllNamespaces('workloads', { ns: 'payments' })).toBe(false);
  expect(isAllNamespaces('images', { ns: 'argocd', scope: 'ns' })).toBe(false);
  expect(isAllNamespaces('risks', {})).toBe(false);
  expect(isAllNamespaces('map', {})).toBe(false);
});

test('every LEGACY_VIEWS name has a redirect, and nothing else does', () => {
  for (const v of LEGACY_VIEWS) expect(legacyRedirect(v, {})).toBeDefined();
  for (const v of ['map', 'risks', 'workloads', 'constructor', '__proto__', '']) expect(legacyRedirect(v, {})).toBeUndefined();
});
