/**
 * UI Constants
 *
 * Centralized constants for UI dimensions, timing, and constraints
 */

// Layout dimensions
export const UI_DIMENSIONS = {
  // Header and footer
  HEADER_HEIGHT: 73,
  FOOTER_HEIGHT: 34,

  // AI Assistant Panel
  AI_PANEL_DEFAULT_WIDTH: 448, // max-w-md
  AI_PANEL_COLLAPSED_WIDTH: 48,
  AI_PANEL_MIN_WIDTH: 300,
  AI_PANEL_MAX_WIDTH_RATIO: 0.8, // 80% of window width

  // Data Table
  TABLE_DEFAULT_HEIGHT: 320, // h-80
  TABLE_MIN_HEIGHT: 100,
  TABLE_MAX_HEIGHT_RATIO: 0.8, // 80% of available height
} as const;

// Animation durations (in milliseconds)
export const UI_TIMING = {
  RESIZE_DEBOUNCE: 100,
  FIT_VIEW_DELAY: 100,
  FIT_VIEW_DURATION: 400,
  TRANSITION_DURATION: 300,
} as const;

// Z-index layers
export const Z_INDEX = {
  BACKDROP: 40,
  MODAL: 50,
  SIDE_PANEL: 50,
  TOOLTIP: 60,
} as const;
