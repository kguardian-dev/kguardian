// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider, useAuth } from './AuthContext';

function Probe() {
  const { mode, user, loading } = useAuth();
  return <div data-testid="auth">{loading ? 'loading' : `${mode}:${user?.id ?? ''}:${user?.name ?? ''}`}</div>;
}

function answer(res: Response) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(res));
  render(<AuthProvider><Probe /></AuthProvider>);
  return waitFor(() => expect(screen.getByTestId('auth').textContent).not.toBe('loading'));
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('AuthProvider', () => {
  it('runs in local mode on a 204 from the UI server (no proxy in front)', async () => {
    await answer(new Response(null, { status: 204, headers: { 'X-Kguardian-Sso': 'none' } }));
    expect(screen.getByTestId('auth').textContent).toBe('none::');
  });

  it('runs in local mode on a 200 without a JSON user or email', async () => {
    await answer(new Response('<!doctype html>', { status: 200, headers: { 'Content-Type': 'text/html' } }));
    expect(screen.getByTestId('auth').textContent).toBe('none::');
  });

  it('runs in local mode on JSON with no identity', async () => {
    await answer(Response.json({ groups: ['x'] }));
    expect(screen.getByTestId('auth').textContent).toBe('none::');
  });

  it('shows the SSO user from a 200 with an identity', async () => {
    await answer(Response.json({ email: 'a@example.com', preferredUsername: 'alice' }));
    expect(screen.getByTestId('auth').textContent).toBe('oidc:a@example.com:alice');
  });
});
