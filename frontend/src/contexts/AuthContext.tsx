import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';

export type AuthMode = 'none' | 'oidc';

export interface AuthUser {
  id: string;
  name: string;
  email?: string;
  groups?: string[];
}

interface AuthContextValue {
  mode: AuthMode;
  user: AuthUser | null;
  /** True while an OIDC session is being resolved. */
  loading: boolean;
  signOut: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

// Auth auto-detects at runtime — no build-time flag, so the same image works
// with or without SSO. On load it asks the identity-aware proxy (oauth2-proxy)
// who the user is via `/oauth2/userinfo` (same-origin; the SSO cookie is sent):
//   - 200 with an identity  -> SSO is active, show the real user (mode 'oidc')
//   - 401 / 404 / error      -> no proxy in front, run in local/no-auth mode
//     (shown honestly in the account menu — no fake login).
// To turn SSO on, front the route with oauth2-proxy + a `/oauth2/*` route (the
// chart's frontend.sso.* templates, or the cluster's Envoy SecurityPolicy). The
// rest of the app consumes `useAuth()` and needs no change.
export function AuthProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<AuthMode>('none');
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/oauth2/userinfo', {
          credentials: 'include',
          headers: { Accept: 'application/json' },
        });
        if (!res.ok) throw new Error(String(res.status));
        const info = await res.json();
        const id = info.user ?? info.email;
        if (!id) throw new Error('no identity');
        if (!cancelled) {
          setUser({
            id,
            name: info.preferredUsername ?? info.name ?? info.user ?? info.email ?? 'User',
            email: info.email,
            groups: info.groups,
          });
          setMode('oidc');
        }
      } catch {
        // No session / proxy not present — local/no-auth mode.
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const signOut = () => {
    if (mode === 'oidc') window.location.href = '/oauth2/sign_out';
  };

  return (
    <AuthContext.Provider value={{ mode, user, loading, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}
