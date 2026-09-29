import { afterEach, expect, test, vi } from 'vitest';
import { apiClient } from './api';

// The per-pod traffic and syscall reads used to turn every failure into `[]`.
// A timed-out pod then looked flow-less: the Traffic filter hid its card and
// the Policy Builder read it as "0 conns". An empty array must mean the
// broker holds nothing for the pod, so a failed read is rethrown and the
// caller decides how to mark it.

afterEach(() => vi.restoreAllMocks());

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const axiosOf = (c: unknown) => (c as any).client as { get: (url: string) => Promise<unknown> };

test('a failed traffic read is rethrown, not returned as no flows', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(axiosOf(apiClient), 'get').mockRejectedValue(new Error('timeout of 10000ms exceeded') as never);
  await expect(apiClient.getPodTrafficByName('api-1')).rejects.toThrow(/timeout/);
});

test('a failed syscall read is rethrown, not returned as no syscalls', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(axiosOf(apiClient), 'get').mockRejectedValue(new Error('timeout of 10000ms exceeded') as never);
  await expect(apiClient.getPodSyscalls('api-1')).rejects.toThrow(/timeout/);
});

test('an empty answer is still an empty array: that is the honest no-flows case', async () => {
  vi.spyOn(axiosOf(apiClient), 'get').mockResolvedValue({ data: [] } as never);
  await expect(apiClient.getPodTrafficByName('api-1')).resolves.toEqual([]);
  await expect(apiClient.getPodSyscalls('api-1')).resolves.toEqual([]);
});

test('concurrent /svc/info callers share one request, like /pod/info', async () => {
  let calls = 0;
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation((() => {
    calls += 1;
    return new Promise((resolve) => setTimeout(() => resolve({ data: [{ svc_ip: '10.100.0.1' }] }), 5));
  }) as never);

  const [a, b] = await Promise.all([apiClient.getAllServices(), apiClient.getAllServices()]);
  expect(calls).toBe(1);
  expect(a).toHaveLength(1);
  expect(b).toHaveLength(1);

  // Coalescing, not caching: a later call fetches again.
  await apiClient.getAllServices();
  expect(calls).toBe(2);
});

test('a failed /svc/info does not poison the next one', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  let calls = 0;
  vi.spyOn(axiosOf(apiClient), 'get').mockImplementation((() => {
    calls += 1;
    return calls === 1 ? Promise.reject(new Error('broker unavailable')) : Promise.resolve({ data: [{ svc_ip: '10.100.0.1' }] });
  }) as never);
  await expect(apiClient.getAllServices()).rejects.toThrow('broker unavailable');
  expect(await apiClient.getAllServices()).toHaveLength(1);
});
