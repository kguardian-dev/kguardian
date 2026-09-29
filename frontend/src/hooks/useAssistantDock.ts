import { createContext, useContext } from 'react';
import { useMediaQuery } from './useMediaQuery';
import { UI_DIMENSIONS } from '../constants/ui';

/**
 * Pixels the docked AI assistant takes at the right edge of the window (its
 * width, or the collapsed bar's), 0 when it is closed or open as a modal.
 * App provides it; the main column already pads by the same amount.
 */
export const AssistantDockContext = createContext(0);

/** The docked width for the layout the assistant reports (onLayoutChange). */
export function assistantDockWidth(isSidePanel: boolean, isCollapsed: boolean, width: number): number {
  if (!isSidePanel) return 0;
  return isCollapsed ? UI_DIMENSIONS.AI_PANEL_COLLAPSED_WIDTH : width;
}

/** Below this a drawer beside the assistant is too cramped to read. */
export const DRAWER_MIN_WIDTH_PX = 400;

/**
 * Right offset for a right-anchored drawer, so it opens beside the docked
 * assistant instead of under it and gives up width to it. 0 when nothing is
 * docked, or when the assistant leaves the drawer less than
 * DRAWER_MIN_WIDTH_PX: the drawer then overlays the window edge as before.
 */
export function useDrawerDockOffset(isDrawer: boolean): number {
  const dock = useContext(AssistantDockContext);
  const noRoom = useMediaQuery(`(max-width: ${dock + DRAWER_MIN_WIDTH_PX - 1}px)`);
  return isDrawer && dock > 0 && !noRoom ? dock : 0;
}
