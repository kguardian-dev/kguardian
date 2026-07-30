import { useCallback, useEffect, useState } from 'react';

/**
 * Minimal dependency-free hash router. The app has a handful of top-level views
 * and no server-side routing, so a full router is overkill — this syncs a single
 * view token to `location.hash` (`#/map`, `#/findings`, …) so views become
 * shareable URLs and the browser back/forward buttons work, which the
 * modal-toggle model never gave us.
 */
export function useHashRoute<T extends string>(fallback: T, valid: readonly T[]) {
  const parse = useCallback((): T => {
    const raw = window.location.hash.replace(/^#\/?/, '') as T;
    return valid.includes(raw) ? raw : fallback;
  }, [fallback, valid]);

  const [route, setRouteState] = useState<T>(parse);

  useEffect(() => {
    const onChange = () => setRouteState(parse());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, [parse]);

  const setRoute = useCallback((next: T) => {
    if (window.location.hash.replace(/^#\/?/, '') !== next) {
      window.location.hash = `/${next}`;
    }
    setRouteState(next);
  }, []);

  return [route, setRoute] as const;
}
