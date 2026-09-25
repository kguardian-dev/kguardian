import { useCallback, useEffect, useState } from 'react';

export interface HashLocation {
  /** Path token after `#/` (e.g. "map", "findings"). */
  view: string;
  /** Query params after `?` (e.g. ns, pod). */
  params: Record<string, string>;
}

type ParamInput = Record<string, string | undefined | null>;

function parse(): HashLocation {
  const raw = window.location.hash.replace(/^#\/?/, '');
  const qi = raw.indexOf('?');
  const view = qi >= 0 ? raw.slice(0, qi) : raw;
  // fromEntries defines OWN properties, so a `__proto__=` key in a pasted
  // link becomes a plain param instead of assigning the object's prototype.
  // Later duplicates win, as with repeated assignment.
  const params: Record<string, string> = qi >= 0 ? Object.fromEntries(new URLSearchParams(raw.slice(qi + 1))) : {};
  return { view, params };
}

function build(view: string, params: ParamInput): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v != null && v !== '') sp.set(k, String(v));
  }
  const q = sp.toString();
  return `#/${view}${q ? `?${q}` : ''}`;
}

/**
 * Dependency-free hash router that carries a view token *and* query params, so
 * the whole location — which view, which namespace, which selected workload —
 * lives in a shareable, refreshable URL. `navigate(..., {replace})` mirrors
 * frequent selection changes without spamming history; the default pushes a
 * history entry so back/forward walks view/namespace changes.
 */
export function useHashLocation() {
  const [loc, setLoc] = useState<HashLocation>(parse);

  useEffect(() => {
    const onChange = () => setLoc(parse());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);

  const navigate = useCallback((view: string, params: ParamInput, opts?: { replace?: boolean }) => {
    const target = build(view, params);
    if (window.location.hash === target) return;
    if (opts?.replace) {
      window.history.replaceState(null, '', target);
      setLoc(parse()); // replaceState doesn't fire hashchange
    } else {
      window.location.hash = target; // fires hashchange → setLoc
    }
  }, []);

  return { loc, navigate };
}
