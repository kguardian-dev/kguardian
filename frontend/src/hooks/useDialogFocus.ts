import { useEffect, useRef, type RefObject } from 'react';

const FOCUSABLE = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

/**
 * Keyboard behaviour of a modal overlay: on open, focus the first match of
 * `initialFocus` (or the first focusable) inside `dialogRef`; Tab and
 * Shift+Tab stay inside; Esc inside the dialog calls `onClose`. Whenever it
 * closes, however it closes (Esc, backdrop, navigation, a layout change),
 * focus returns to `returnFocusRef`, read after the close renders so an
 * element that remounted in the meantime is found.
 */
export function useDialogFocus(opts: {
  open: boolean;
  dialogRef: RefObject<HTMLElement | null>;
  returnFocusRef: RefObject<HTMLElement | null>;
  onClose: () => void;
  initialFocus?: string;
}) {
  const { open, dialogRef, returnFocusRef, onClose, initialFocus } = opts;
  const wasOpen = useRef(false);

  useEffect(() => {
    if (open) {
      wasOpen.current = true;
      const d = dialogRef.current;
      (d?.querySelector<HTMLElement>(initialFocus ?? FOCUSABLE) ?? d?.querySelector<HTMLElement>(FOCUSABLE))?.focus();
      return;
    }
    if (wasOpen.current) {
      wasOpen.current = false;
      returnFocusRef.current?.focus();
    }
  }, [open, dialogRef, returnFocusRef, initialFocus]);

  // Esc belongs to the dialog. It is handled when it comes from inside the
  // dialog or from the body: a click on a non-focusable part of the dialog
  // (or its backdrop) leaves focus on the body, and the Esc must still close
  // it. Esc from anywhere else on the page is left to its own handlers.
  useEffect(() => {
    if (!open) return;
    const onEsc = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      const d = dialogRef.current;
      const t = e.target as Node | null;
      const fromDialog = !!(d && t && d.contains(t));
      const fromBody = t === document.body || t === document.documentElement;
      if (!fromDialog && !fromBody) return;
      e.stopPropagation();
      onClose();
    };
    window.addEventListener('keydown', onEsc, true);
    return () => window.removeEventListener('keydown', onEsc, true);
  }, [open, dialogRef, onClose]);

  // Tab is caught on the window so focus that did get out is pulled back in.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      const d = dialogRef.current;
      if (e.key !== 'Tab' || !d) return;
      const focusables = [...d.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => !el.hasAttribute('disabled'));
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const inside = d.contains(document.activeElement);
      if (e.shiftKey && (document.activeElement === first || !inside)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (document.activeElement === last || !inside)) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, dialogRef, onClose]);
}
