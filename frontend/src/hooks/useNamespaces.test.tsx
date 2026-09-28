// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { cleanup, renderHook, waitFor } from '@testing-library/react';
import { AxiosError } from 'axios';
import { apiClient } from '../services/api';
import { namespaceFromUrl, useNamespaces } from './useNamespaces';

// The seed decides which namespace the first pod-data run fetches for. It was
// `['default']`, so every load fetched `default` first and raced it against the
// namespace the user asked for, and the losing run's `finally` cleared the
// loading flag under the winner (the false "No workloads" empty state).
//
// These go through the real client with its axios instance spied, so the
// failure cases are the ones the broker actually produces.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const axiosOf = (c: unknown) => (c as any).client as { get: (url: string) => Promise<unknown> };

beforeEach(() => {
  window.location.hash = '';
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.location.hash = '';
});

test('namespaceFromUrl reads the ns param and nothing else', () => {
  expect(namespaceFromUrl('#/map?ns=argocd&lens=vulns')).toBe('argocd');
  expect(namespaceFromUrl('#/map?lens=vulns')).toBeNull();
  expect(namespaceFromUrl('#/map?ns=')).toBeNull();
  expect(namespaceFromUrl('')).toBeNull();
});

test('seeds from the URL namespace, so the first run is for the requested one', async () => {
  window.location.hash = '#/map?ns=argocd';
  let resolve: (v: unknown) => void = () => {};
  vi.spyOn(axiosOf(apiClient), 'get').mockReturnValue(new Promise((r) => { resolve = r; }));
  const { result } = renderHook(() => useNamespaces());
  expect(result.current.namespaces).toEqual(['argocd']);
  expect(result.current.loading).toBe(true);
  resolve({ data: ['kube-system', 'argocd'] });
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.namespaces).toEqual(['argocd', 'kube-system']);
  expect(result.current.error).toBeNull();
});

test('seeds empty without a URL namespace: never a hardcoded default', async () => {
  vi.spyOn(axiosOf(apiClient), 'get').mockResolvedValue({ data: ['payments'] } as never);
  const { result } = renderHook(() => useNamespaces());
  expect(result.current.namespaces).toEqual([]);
  await waitFor(() => expect(result.current.namespaces).toEqual(['payments']));
});

// A 503 shed or the broker's 30 s statement timeout is routine; it used to
// come back as `['default']`, replace the deep link's namespace and get its
// URL rewritten to default.
test('a shed or timed-out list read keeps the URL seed and reports the error', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  window.location.hash = '#/map?ns=argocd';
  vi.spyOn(axiosOf(apiClient), 'get').mockRejectedValue(
    new AxiosError('Service Unavailable', 'ERR_BAD_RESPONSE', undefined, undefined, { status: 503 } as never) as never,
  );
  const { result } = renderHook(() => useNamespaces());
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.namespaces).toEqual(['argocd']);
  expect(result.current.error).toMatch(/Service Unavailable/);
});

test('a network failure keeps the seed too', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  window.location.hash = '#/map?ns=argocd';
  vi.spyOn(axiosOf(apiClient), 'get').mockRejectedValue(new Error('Network Error') as never);
  const { result } = renderHook(() => useNamespaces());
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.namespaces).toEqual(['argocd']);
  expect(result.current.error).toBe('Network Error');
});

test('an older broker (404) derives the list from live pods and is not an error', async () => {
  window.location.hash = '#/map?ns=argocd';
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation((async (url: string) => {
    if (url === '/pod/namespaces') {
      throw new AxiosError('Not Found', 'ERR_BAD_REQUEST', undefined, undefined, { status: 404 } as never);
    }
    return { data: [{ pod_name: 'a', pod_namespace: 'argocd', is_dead: false }, { pod_name: 'b', pod_namespace: 'batch', is_dead: false }] };
  }) as never);
  const { result } = renderHook(() => useNamespaces());
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.namespaces).toEqual(['argocd', 'batch']);
  expect(result.current.error).toBeNull();
});
