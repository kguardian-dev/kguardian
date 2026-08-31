import { useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { X } from 'lucide-react';
import { Button } from './Button';

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
  /** Override the content wrapper classes. Large modals that manage their own
   *  sticky header/toolbar + scroll region pass a flex-column here instead of
   *  the default single scroll body. */
  contentClassName?: string;
  /** Disable close-on-backdrop-click (e.g. destructive-in-progress). */
  disableBackdropClose?: boolean;
  /** Vertical placement. 'top' anchors near the top (command-palette style). */
  align?: 'center' | 'top';
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
  contentClassName = 'flex-1 min-h-0 overflow-y-auto',
  disableBackdropClose = false,
  align = 'center',
}: ModalProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const lastFocused = useRef<HTMLElement | null>(null);
  const labelId = useId();
  // Keep the node mounted through the exit transition.
  const [mounted, setMounted] = useState(isOpen);
  const [entered, setEntered] = useState(false);

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

  // Focus management: remember the trigger, move focus in, restore on close.
  useEffect(() => {
    if (!isOpen) return;
    lastFocused.current = document.activeElement as HTMLElement | null;
    const node = panelRef.current;
    if (node) {
      const first = node.querySelector<HTMLElement>(FOCUSABLE);
      (first ?? node).focus();
    }
    return () => lastFocused.current?.focus?.();
  }, [isOpen]);

  // Body-scroll-lock while any modal is open.
  useEffect(() => {
    if (!mounted) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = prev;
    };
  }, [mounted]);

  // Esc-to-close + Tab focus trap.
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== 'Tab') return;
      const node = panelRef.current;
      if (!node) return;
      const items = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (el) => el.offsetParent !== null,
      );
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKey, true);
    return () => document.removeEventListener('keydown', onKey, true);
  }, [isOpen, onClose]);

  if (!mounted) return null;

  // Let an explicit width/height in `className` win over the size defaults
  // instead of emitting a conflicting utility whose winner is order-dependent.
  const sizeClass = /(?:^|\s)(max-w-|w-)/.test(className) ? '' : `w-full ${SIZE_CLASS[size]}`;
  const heightClass = /(?:^|\s)(max-h-|h-)\[/.test(className) ? '' : 'max-h-[88vh]';

  return (
    <div className="fixed inset-0 z-50" aria-hidden={!isOpen}>
      <div
        className={`absolute inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-200 ${
          entered ? 'opacity-100' : 'opacity-0'
        }`}
        onClick={disableBackdropClose ? undefined : onClose}
      />
      <div
        className={`absolute inset-0 flex justify-center p-4 pointer-events-none ${
          align === 'top' ? 'items-start pt-[12vh]' : 'items-center'
        }`}
      >
        <div
          ref={panelRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby={title ? labelId : undefined}
          tabIndex={-1}
          onClick={(e) => e.stopPropagation()}
          className={`pointer-events-auto ${sizeClass} ${heightClass} flex flex-col
            bg-hubble-card border border-hubble-border rounded-surface shadow-2xl
            outline-none transition-all duration-200 ease-out
            ${entered ? 'opacity-100 scale-100 translate-y-0' : 'opacity-0 scale-[0.98] translate-y-1'}
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
