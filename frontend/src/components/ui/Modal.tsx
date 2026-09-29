import { useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { X } from 'lucide-react';
import { Button } from './Button';
import { openModalDialogs } from '../../hooks/useDialogFocus';
import { useDrawerDock } from '../../hooks/useAssistantDock';

type ModalSize = 'sm' | 'md' | 'lg' | 'xl' | 'full';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  /** Header title. Omit with `hideHeader` if the caller renders its own chrome. */
  title?: ReactNode;
  subtitle?: ReactNode;
  size?: ModalSize;
  /** Sticky footer region (actions). */
  footer?: ReactNode;
  children: ReactNode;
  /** Extra classes merged onto the panel element. */
  className?: string;
  /** Suppress the default header row (caller draws its own inside children). */
  hideHeader?: boolean;
  /** Accessible name when no visible title labels the dialog (e.g. with `hideHeader`). */
  ariaLabel?: string;
  /** Override the content wrapper classes. Large modals that manage their own
   *  sticky header/toolbar + scroll region pass a flex-column here instead of
   *  the default single scroll body. */
  contentClassName?: string;
  /** Disable close-on-backdrop-click (e.g. destructive-in-progress). */
  disableBackdropClose?: boolean;
  /** Placement. 'top' anchors near the top (command-palette style);
   *  'right' is a full-height side drawer over the current view. */
  align?: 'center' | 'top' | 'right';
  /** Selector of the element to focus on open (a search box that sits behind
   *  the header's Close button). Defaults to the first focusable. */
  initialFocus?: string;
}

const SIZE_CLASS: Record<ModalSize, string> = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
  full: 'max-w-[92vw]',
};

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Return-focus chain per open dialog; one opened from inside another inherits its
// chain, so the Policy Builder's editor returns focus to the rail after its picker unmounts.
const returnChainOf = new WeakMap<HTMLElement, HTMLElement[]>();

function returnChain(): HTMLElement[] {
  if (typeof document === 'undefined') return [];
  const el = document.activeElement as HTMLElement | null;
  if (!el) return [];
  const host = el.closest<HTMLElement>('[role="dialog"][aria-modal="true"]');
  return [el, ...(host ? returnChainOf.get(host) ?? [] : [])];
}

/**
 * One dialog shell for every overlay in the app. Replaces the four hand-rolled
 * `fixed inset-0 … pointer-events-none` wrappers that each re-implemented the
 * overlay differently and none of which trapped focus, closed on Esc, animated,
 * or locked body scroll. Handles: enter/exit fade+scale (honoring
 * prefers-reduced-motion via the global CSS reset), Esc-to-close, focus trap +
 * restore, body-scroll-lock, and `role="dialog"` / `aria-modal` wiring.
 */
export function Modal({
  isOpen,
  onClose,
  title,
  subtitle,
  size = 'md',
  footer,
  children,
  className = '',
  hideHeader = false,
  ariaLabel,
  contentClassName = 'flex-1 min-h-0 overflow-y-auto',
  disableBackdropClose = false,
  align = 'center',
  initialFocus,
}: ModalProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  // Record the opener while rendering the open, before commit: a child with
  // autoFocus (the command palette's input) takes focus during commit, ahead
  // of any effect here, and would be recorded as the "opener" instead.
  const [returnTo, setReturnTo] = useState<HTMLElement[]>(() => (isOpen ? returnChain() : []));
  const [openSeen, setOpenSeen] = useState(isOpen);
  if (isOpen !== openSeen) {
    setOpenSeen(isOpen);
    if (isOpen) setReturnTo(returnChain());
  }
  const labelId = useId();
  // Keep the node mounted through the exit transition.
  const [mounted, setMounted] = useState(isOpen);
  const [entered, setEntered] = useState(false);

  // The latest onClose, so the key listener is not torn down and re-added on
  // every render (callers pass fresh arrow functions).
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (isOpen) {
      // Mount, then flip to the entered state on the next frame so the
      // fade+scale transition actually runs (mounting already-entered skips it).
      let inner = 0;
      const raf = requestAnimationFrame(() => {
        setMounted(true);
        inner = requestAnimationFrame(() => setEntered(true));
      });
      return () => {
        cancelAnimationFrame(raf);
        cancelAnimationFrame(inner);
      };
    }
    // Closing: transition out, then unmount after the animation window.
    const raf = requestAnimationFrame(() => setEntered(false));
    const t = setTimeout(() => setMounted(false), 200);
    return () => {
      cancelAnimationFrame(raf);
      clearTimeout(t);
    };
  }, [isOpen]);

  // Move focus in once the panel is in the DOM: it mounts a frame after
  // isOpen flips, so an effect on isOpen alone found no panel and left focus
  // on the body. A child that already took focus (autoFocus) keeps it.
  useEffect(() => {
    if (!isOpen || !mounted) return;
    const node = panelRef.current;
    if (!node) return;
    returnChainOf.set(node, returnTo);
    if (node.contains(document.activeElement)) return;
    const target =
      (initialFocus ? node.querySelector<HTMLElement>(initialFocus) : null) ??
      node.querySelector<HTMLElement>(FOCUSABLE) ??
      node;
    target.focus();
  }, [isOpen, mounted, initialFocus, returnTo]);

  // Restore focus on close.
  useEffect(() => {
    if (!isOpen) return;
    return () => {
      returnTo.find((el) => el !== document.body && el.isConnected)?.focus?.();
      const now = document.activeElement;
      // Focus is on something real: not the body, not inside this dialog while
      // it fades out under aria-hidden.
      if (now && now !== document.body && now.isConnected && !now.closest('[aria-hidden="true"]')) return;
      // Opened with focus on the body (or its trigger is gone): don't drop
      // focus on the body, go to the dialog still open underneath, if any.
      openModalDialogs().at(-1)?.querySelector<HTMLElement>(FOCUSABLE)?.focus();
    };
  }, [isOpen, returnTo]);

  // Body-scroll-lock while any modal is open.
  useEffect(() => {
    if (!mounted) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = prev;
    };
  }, [mounted]);

  // Esc-to-close + Tab focus trap. Only the topmost dialog owns the keyboard:
  // stopPropagation never reached the other open Modals' document listeners.
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' && e.key !== 'Tab') return;
      // The docked assistant sits beside an open drawer, not in it: its keys
      // are its own (Esc closes it, not the drawer; Tab is not pulled back).
      if (e.target instanceof Element && e.target.closest('[data-docked-panel]')) return;
      const node = panelRef.current;
      if (!node || openModalDialogs().at(-1) !== node) return;
      if (e.key === 'Escape') {
        e.stopImmediatePropagation();
        onCloseRef.current();
        return;
      }
      const items = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (el) => el.offsetParent !== null,
      );
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      // Focus outside the dialog (it opened with focus on the body) is pulled
      // back in rather than let Tab walk the page behind the backdrop.
      const inside = node.contains(document.activeElement);
      if (e.shiftKey && (document.activeElement === first || !inside)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (document.activeElement === last || !inside)) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKey, true);
    return () => document.removeEventListener('keydown', onKey, true);
  }, [isOpen]);

  const drawer = align === 'right';
  // A drawer ends where the docked assistant begins, so both stay readable.
  // Its edge follows a drag of the assistant's width without the transition.
  const { offset: dockOffset, resizing: dockResizing } = useDrawerDock(drawer && mounted);

  if (!mounted) return null;

  // Let an explicit width/height in `className` win over the size defaults
  // instead of emitting a conflicting utility whose winner is order-dependent.
  const sizeClass = /(?:^|\s)(max-w-|w-)/.test(className) ? '' : `w-full ${SIZE_CLASS[size]}`;
  const heightClass = drawer ? 'h-full' : /(?:^|\s)(max-h-|h-)\[/.test(className) ? '' : 'max-h-[88vh]';

  return (
    <div
      className={`fixed inset-0 z-50 ${drawer && !dockResizing ? 'transition-[right] duration-300' : ''}`}
      style={dockOffset ? { right: `${dockOffset}px` } : undefined}
      aria-hidden={!isOpen}
    >
      <div
        className={`absolute inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-200 ${
          entered ? 'opacity-100' : 'opacity-0'
        }`}
        onClick={disableBackdropClose ? undefined : onClose}
      />
      <div
        className={`absolute inset-0 flex pointer-events-none ${
          drawer ? 'justify-end' : `justify-center p-4 ${align === 'top' ? 'items-start pt-[12vh]' : 'items-center'}`
        }`}
      >
        <div
          ref={panelRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby={title && !hideHeader ? labelId : undefined}
          aria-label={title && !hideHeader ? undefined : ariaLabel}
          tabIndex={-1}
          onClick={(e) => e.stopPropagation()}
          className={`pointer-events-auto ${sizeClass} ${heightClass} flex flex-col
            bg-hubble-card border-hubble-border shadow-2xl
            outline-none transition-all duration-200 ease-out
            ${drawer ? 'border-l' : 'border rounded-surface'}
            ${drawer
              ? entered ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-4'
              : entered ? 'opacity-100 scale-100 translate-y-0' : 'opacity-0 scale-[0.98] translate-y-1'}
            ${className}`}
        >
          {!hideHeader && (
            <div className="flex items-center justify-between gap-4 h-14 px-5 border-b border-hubble-border shrink-0">
              <div className="min-w-0">
                {title && (
                  <h2 id={labelId} className="text-sm font-semibold text-primary truncate">
                    {title}
                  </h2>
                )}
                {subtitle && <p className="text-xs text-tertiary truncate">{subtitle}</p>}
              </div>
              <Button variant="ghost" size="sm" iconOnly leftIcon={X} onClick={onClose} aria-label="Close" />
            </div>
          )}

          <div className={contentClassName}>{children}</div>

          {footer && (
            <div className="flex items-center justify-end gap-2 px-5 h-14 border-t border-hubble-border shrink-0">
              {footer}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
