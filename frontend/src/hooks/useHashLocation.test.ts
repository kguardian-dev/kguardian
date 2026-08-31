// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { useHashLocation } from './useHashLocation';

// The hash IS the application's navigation state — which view, which namespace,
// which selected workload — so a parsing slip silently sends people to the
// wrong screen or drops a selection on refresh. These pin the round trip and
// the two history behaviours the callers depend on.

afterEach(() => {
  // Leave no hash behind; renderHook reads window.location at mount.
  window.history.replaceState(null, '', window.location.pathname);
});

const setHash = (h: string) => window.history.replaceState(null, '', h);

test('parses an empty hash as an empty view with no params', () => {
  const { result } = renderHook(() => useHashLocation());
  expect(result.current.loc).toEqual({ view: '', params: {} });
});

test('parses the view token with and without the leading slash', () => {
  setHash('#/findings');
  expect(renderHook(() => useHashLocation()).result.current.loc.view).toBe('findings');

  // `#map` (no slash) must not lose its first character to the prefix strip.
  setHash('#map');
  expect(renderHook(() => useHashLocation()).result.current.loc.view).toBe('map');
});

test('parses query params after the view', () => {
  setHash('#/map?ns=prod&pod=web-1');
  const { loc } = renderHook(() => useHashLocation()).result.current;
  expect(loc.view).toBe('map');
  expect(loc.params).toEqual({ ns: 'prod', pod: 'web-1' });
});

test('decodes percent-encoded param values', () => {
  // Namespaces and pod names reach the hash through encodeURIComponent; a
  // value that survives the round trip as literal %2F would not match any pod.
  setHash(`#/map?pod=${encodeURIComponent('a b/c')}`);
  expect(renderHook(() => useHashLocation()).result.current.loc.params.pod).toBe('a b/c');
});

test('navigate round-trips view and params through the URL', async () => {
  const { result } = renderHook(() => useHashLocation());
  act(() => result.current.navigate('map', { ns: 'prod', pod: 'web-1' }));

  // The URL moves synchronously.
  expect(window.location.hash).toBe('#/map?ns=prod&pod=web-1');
  // State follows on the hashchange event, which the platform dispatches on a
  // later task — the push path is deliberately event-driven so an external
  // change (back button, pasted link) and an internal one take the same route.
  // Callers therefore see state one tick behind the URL here; the replace path
  // below is the synchronous one.
  await waitFor(() =>
    expect(result.current.loc).toEqual({ view: 'map', params: { ns: 'prod', pod: 'web-1' } }),
  );
});

test('navigate omits empty, null and undefined params rather than serialising them', async () => {
  // Otherwise a cleared selection becomes `?pod=` or `?pod=undefined`, which
  // parses back as a real value and re-selects a workload that does not exist.
  const { result } = renderHook(() => useHashLocation());
  act(() => result.current.navigate('map', { ns: 'prod', pod: '', node: undefined, svc: null }));

  expect(window.location.hash).toBe('#/map?ns=prod');
  await waitFor(() => expect(result.current.loc.params).toEqual({ ns: 'prod' }));
});

test('replace navigation still updates state, since replaceState fires no hashchange', () => {
  // This is the subtle one: the push path relies on the hashchange listener to
  // refresh state, but replaceState is silent. If the hook did not parse
  // explicitly on this path, frequent selection changes would move the URL
  // while the UI kept rendering the previous selection.
  const { result } = renderHook(() => useHashLocation());
  act(() => result.current.navigate('map', { pod: 'web-1' }, { replace: true }));

  expect(window.location.hash).toBe('#/map?pod=web-1');
  expect(result.current.loc.params.pod).toBe('web-1');
});

test('replace navigation does not grow history, push navigation does', () => {
  const { result } = renderHook(() => useHashLocation());
  const start = window.history.length;

  act(() => result.current.navigate('map', { pod: 'a' }, { replace: true }));
  act(() => result.current.navigate('map', { pod: 'b' }, { replace: true }));
  expect(window.history.length).toBe(start);

  act(() => result.current.navigate('findings', {}));
  expect(window.history.length).toBeGreaterThan(start);
});

test('navigating to the current location is a no-op', () => {
  // Guards against a render loop: a component that navigates from an effect
  // would otherwise push an identical entry on every pass.
  setHash('#/map?ns=prod');
  const { result } = renderHook(() => useHashLocation());
  const before = window.history.length;

  act(() => result.current.navigate('map', { ns: 'prod' }));
  expect(window.history.length).toBe(before);
});

test('reacts to external hash changes such as browser back', () => {
  const { result } = renderHook(() => useHashLocation());
  act(() => result.current.navigate('findings', {}));

  act(() => {
    window.history.replaceState(null, '', '#/map?ns=kube-system');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  });

  expect(result.current.loc).toEqual({ view: 'map', params: { ns: 'kube-system' } });
});
