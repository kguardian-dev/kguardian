import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';

// Per-user application settings. Persisted to localStorage today; when SSO
// lands the storage key is namespaced per user id and can be backed by a
// server-side store (see AuthContext). Keep this the single source of truth for
// user preferences so new settings don't scatter across components again.
export interface AppSettings {
  /** Preferred namespace to open on. null = auto (first namespace with pods). */
  defaultNamespace: string | null;
  /** Graph defaults — persisted so the view survives reloads. */
  showExternalNodes: boolean;
  /** Show DaemonSet / host-network peers (node-exporter, CNI, CSI agents) on
   *  the map. Off by default: since node-IP traffic is recorded they appear
   *  as peers of nearly every pod and drown the workload picture. Policy
   *  generation ignores this — those peers stay in the generated rules. */
  showDaemonSetNodes: boolean;
  showTraffic: boolean;
  layoutDirection: 'LR' | 'TB';
}

const DEFAULT_SETTINGS: AppSettings = {
  defaultNamespace: null,
  showExternalNodes: true,
  showDaemonSetNodes: false,
  showTraffic: true,
  layoutDirection: 'LR',
};

const STORAGE_KEY = 'kg-settings';

function loadSettings(): AppSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_SETTINGS;
    // Merge over defaults so a new field is never undefined on an old profile.
    return { ...DEFAULT_SETTINGS, ...(JSON.parse(raw) as Partial<AppSettings>) };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

type BooleanSettingKey = { [K in keyof AppSettings]: AppSettings[K] extends boolean ? K : never }[keyof AppSettings];

interface SettingsContextValue {
  settings: AppSettings;
  updateSettings: (patch: Partial<AppSettings>) => void;
  /** Flip a boolean setting from its CURRENT value (functional update), so a
   *  toggle fired from an effect or a stale closure cannot double-flip. */
  toggleSetting: (key: BooleanSettingKey) => void;
  resetSettings: () => void;
}

const SettingsContext = createContext<SettingsContextValue | undefined>(undefined);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<AppSettings>(loadSettings);

  const persist = useCallback((next: AppSettings) => {
    setSettings(next);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // Storage unavailable (private mode / quota) — keep the in-memory value.
    }
  }, []);

  const updateSettings = useCallback(
    (patch: Partial<AppSettings>) => setSettings((prev) => {
      const next = { ...prev, ...patch };
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(next)); } catch { /* ignore */ }
      return next;
    }),
    [],
  );

  const toggleSetting = useCallback(
    (key: BooleanSettingKey) => setSettings((prev) => {
      const next = { ...prev, [key]: !prev[key] };
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(next)); } catch { /* ignore */ }
      return next;
    }),
    [],
  );

  const resetSettings = useCallback(() => persist(DEFAULT_SETTINGS), [persist]);

  return (
    <SettingsContext.Provider value={{ settings, updateSettings, toggleSetting, resetSettings }}>
      {children}
    </SettingsContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useSettings(): SettingsContextValue {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error('useSettings must be used within a SettingsProvider');
  return ctx;
}
