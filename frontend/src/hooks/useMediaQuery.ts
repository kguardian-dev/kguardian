import { useSyncExternalStore } from 'react';

/**
 * Whether a CSS media query matches, kept live (resize, rotation, a docked
 * devtools pane). False where matchMedia does not exist (tests, SSR).
 */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      if (typeof window === 'undefined' || !window.matchMedia) return () => {};
      const mql = window.matchMedia(query);
      mql.addEventListener('change', onChange);
      return () => mql.removeEventListener('change', onChange);
    },
    () => (typeof window !== 'undefined' && !!window.matchMedia ? window.matchMedia(query).matches : false),
    () => false,
  );
}

/** Below Tailwind's `md`: the rail is an overlay, not a column. */
export const NARROW_QUERY = '(max-width: 767px)';
