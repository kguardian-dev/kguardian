import { useEffect } from 'react';
import type { RefObject } from 'react';

/**
 * Close-on-dismiss for popovers/menus: outside pointer-down *and* Escape.
 * Both rail dropdowns (cluster switcher, account menu) hand-rolled only the
 * outside-click half and neither closed on Esc — this unifies them and makes
 * the menus keyboard-dismissable.
 */
export function useDismissable(
  open: boolean,
  onClose: () => void,
  ref: RefObject<HTMLElement | null>,
) {
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open, onClose, ref]);
}
