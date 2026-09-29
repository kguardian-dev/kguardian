import { createContext, useContext, useEffect, useMemo, useState, useSyncExternalStore } from 'react';
import { UI_DIMENSIONS } from '../constants/ui';

/**
 * What the docked AI assistant shares with the rest of the page. App provides
 * it; right-anchored drawers (ui/Modal) read it to open beside the assistant
 * instead of under it, and the assistant reads it to leave them room.
 */
export interface AssistantDock {
  /** Pixels the docked assistant takes at the right edge (its width, or the
   *  collapsed bar's); 0 when it is closed or open as a modal. The main
   *  column pads by the same amount. */
  width: number;
  /** The assistant's width is being dragged: followers skip their transition. */
  resizing: boolean;
  setResizing: (resizing: boolean) => void;
  /** A right-anchored drawer is open: the assistant leaves it room. */
  drawerOpen: boolean;
  /** Called by a drawer while it is mounted; returns the unregister. */
  registerDrawer: () => () => void;
}

const noop = () => {};
export const AssistantDockContext = createContext<AssistantDock>({
  width: 0,
  resizing: false,
  setResizing: noop,
  drawerOpen: false,
  registerDrawer: () => noop,
});

export const useAssistantDock = () => useContext(AssistantDockContext);

/** App's side: the context value for the docked width it already tracks. */
export function useAssistantDockState(width: number): AssistantDock {
  const [resizing, setResizing] = useState(false);
  const [drawers, setDrawers] = useState(0);
  const registerDrawer = useMemo(
    () => () => {
      setDrawers((n) => n + 1);
      return () => setDrawers((n) => n - 1);
    },
    [],
  );
  const drawerOpen = drawers > 0;
  return useMemo(
    () => ({ width, resizing, setResizing, drawerOpen, registerDrawer }),
    [width, resizing, drawerOpen, registerDrawer],
  );
}

/** The docked width for the layout the assistant reports (onLayoutChange). */
export function assistantDockWidth(isSidePanel: boolean, isCollapsed: boolean, width: number): number {
  if (!isSidePanel) return 0;
  return isCollapsed ? UI_DIMENSIONS.AI_PANEL_COLLAPSED_WIDTH : width;
}

/** The narrowest a drawer beside the assistant gets: max(280px, 20vw). */
export function drawerMinWidth(viewportWidth: number): number {
  return Math.max(280, Math.round(viewportWidth * 0.2));
}

/** The widest the docked assistant may be while a drawer is open beside it. */
export function assistantMaxBesideDrawer(viewportWidth: number): number {
  return Math.max(0, viewportWidth - drawerMinWidth(viewportWidth));
}

function subscribeResize(onChange: () => void) {
  window.addEventListener('resize', onChange);
  return () => window.removeEventListener('resize', onChange);
}

/** window.innerWidth, kept live. */
export function useViewportWidth(): number {
  return useSyncExternalStore(subscribeResize, () => window.innerWidth, () => 1280);
}

/**
 * A right-anchored drawer's side of the dock: registers the drawer while it
 * is mounted and returns its right offset, the docked assistant's width. The
 * drawer shrinks into what is left; the assistant never leaves it less than
 * drawerMinWidth, so the drawer never ends up underneath it.
 */
export function useDrawerDock(isDrawer: boolean): { offset: number; resizing: boolean } {
  const { width, resizing, registerDrawer } = useAssistantDock();
  const vw = useViewportWidth();
  useEffect(() => (isDrawer ? registerDrawer() : undefined), [isDrawer, registerDrawer]);
  // Also clamped here, for the frame before the assistant has re-measured.
  const offset = isDrawer ? Math.min(width, assistantMaxBesideDrawer(vw)) : 0;
  return { offset, resizing: isDrawer && resizing };
}
