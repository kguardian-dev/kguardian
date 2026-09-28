import { afterEach, expect, test, vi } from 'vitest';
import { BROKER_STATEMENT_TIMEOUT_MS, PROFILE_READ_TIMEOUT_MS, READ_TIMEOUT_MS } from './readTimeout';
import { ProfileApi } from './profileApi';

afterEach(() => vi.restoreAllMocks());

test('profile reads outlast the Broker\'s statement timeout, so its own answer or error arrives before the client gives up', () => {
  expect(BROKER_STATEMENT_TIMEOUT_MS).toBe(30_000);
  expect(PROFILE_READ_TIMEOUT_MS).toBeGreaterThan(BROKER_STATEMENT_TIMEOUT_MS);
  // Other reads keep the short budget.
  expect(READ_TIMEOUT_MS).toBeLessThan(PROFILE_READ_TIMEOUT_MS);
});

test('ProfileApi arms the profile read timeout by default', async () => {
  const spy = vi.spyOn(AbortSignal, 'timeout');
  const api = new ProfileApi({ fetchImpl: (async () => new Response('{"items":[],"nextAfter":null}', { status: 200 })) as unknown as typeof fetch });
  await api.listWorkloads();
  expect(spy).toHaveBeenCalledWith(PROFILE_READ_TIMEOUT_MS);
});
