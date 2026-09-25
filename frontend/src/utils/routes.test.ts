import { expect, test } from 'vitest';
import { isAllNamespaces, resolveRoute } from './routes';

// Old links live in tickets, runbooks and browser history. A rename that
// silently sends them to the map is a broken link; these pin the redirects.

test('#/findings redirects to #/risks and keeps its params', () => {
  const r = resolveRoute({ view: 'findings', params: { ns: 'payments' } });
  expect(r.view).toBe('risks');
  expect(r.redirect).toEqual({ view: 'risks', params: { ns: 'payments' } });
});

test('#/seccomp redirects to the Workloads seccomp columns', () => {
  const r = resolveRoute({ view: 'seccomp', params: { ns: 'observability' } });
  expect(r.view).toBe('workloads');
  expect(r.redirect).toEqual({ view: 'workloads', params: { ns: 'observability', control: 'seccomp' } });
});

test('current routes resolve to themselves with no redirect', () => {
  for (const view of ['map', 'risks', 'workloads', 'workload']) {
    expect(resolveRoute({ view, params: {} })).toEqual({ view });
  }
});

test('unknown and empty routes land on the map without a redirect', () => {
  expect(resolveRoute({ view: '', params: {} })).toEqual({ view: 'map' });
  expect(resolveRoute({ view: 'nope', params: { ns: 'x' } })).toEqual({ view: 'map' });
});

test('Workloads defaults to all namespaces; scope=ns narrows it; other views are always scoped', () => {
  expect(isAllNamespaces('workloads', {})).toBe(true);
  expect(isAllNamespaces('workloads', { scope: 'ns' })).toBe(false);
  expect(isAllNamespaces('risks', {})).toBe(false);
  expect(isAllNamespaces('map', {})).toBe(false);
});
