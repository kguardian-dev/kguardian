// Where the AI assistant opens. Docked to the right by default so the map
// stays usable while you ask about it; the modal is one click away and the
// last choice is remembered per browser.

export type AssistantViewMode = 'modal' | 'side-panel';

export const DEFAULT_VIEW_MODE: AssistantViewMode = 'side-panel';
const VIEW_MODE_KEY = 'kguardian.ai-assistant.view-mode';

export function readStoredViewMode(storage: Pick<Storage, 'getItem'> | null): AssistantViewMode {
  try {
    const v = storage?.getItem(VIEW_MODE_KEY);
    return v === 'modal' || v === 'side-panel' ? v : DEFAULT_VIEW_MODE;
  } catch {
    return DEFAULT_VIEW_MODE;
  }
}

export function storeViewMode(mode: AssistantViewMode): void {
  try {
    localStorage.setItem(VIEW_MODE_KEY, mode);
  } catch {
    /* storage blocked: the default still applies next time */
  }
}

export function initialViewMode(): AssistantViewMode {
  // Reading the `localStorage` global itself throws when site data is blocked.
  let storage: Storage | null = null;
  try { storage = typeof localStorage !== 'undefined' ? localStorage : null; } catch { /* storage blocked */ }
  return readStoredViewMode(storage);
}
