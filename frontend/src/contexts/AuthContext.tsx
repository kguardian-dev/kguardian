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

// Auth is OFF by default — the app runs in local/no-auth mode and shows that
// honestly (no fake login screen). To enable SSO, front the frontend + broker
// with an identity-aware proxy (e.g. oauth2-proxy) and build with
// VITE_AUTH_MODE=oidc; this provider then reads the signed-in identity from the
// proxy's /oauth2/userinfo and the account menu reflects the real user. The rest
// of the app consumes `useAuth()` and needs no change when SSO is turned on.
const MODE: AuthMode = (import.meta.env.VITE_AUTH_MODE as AuthMode) || 'none';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState<boolean>(MODE === 'oidc');

  useEffect(() => {
    if (MODE !== 'oidc') return;
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/oauth2/userinfo', { credentials: 'include' });
        if (!res.ok) throw new Error(String(res.status));
        const info = await res.json();
        if (!cancelled) {
          setUser({
            id: info.user ?? info.email ?? 'unknown',
            name: info.preferredUsername ?? info.name ?? info.user ?? info.email ?? 'User',
            email: info.email,
            groups: info.groups,
          });
        }
      } catch {
        // No session / proxy not present — treated as signed out.
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const signOut = () => {
    // oauth2-proxy sign-out; a no-op in local mode.
    if (MODE === 'oidc') window.location.href = '/oauth2/sign_out';
  };

  return (
    <AuthContext.Provider value={{ mode: MODE, user, loading, signOut }}>
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
