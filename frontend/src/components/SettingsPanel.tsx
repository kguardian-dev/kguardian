import { X } from 'lucide-react';
import { useSettings } from '../contexts/SettingsContext';
import { useCluster } from '../contexts/ClusterContext';
import { Button } from './ui/Button';

interface SettingsPanelProps {
  isOpen: boolean;
  onClose: () => void;
  namespaces: string[];
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${checked ? 'bg-hubble-accent' : 'bg-hubble-border'}`}
    >
      <span className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform ${checked ? 'translate-x-4' : ''}`} />
    </button>
  );
}

function Row({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-3">
      <div className="min-w-0">
        <div className="text-sm text-primary">{label}</div>
        {hint && <div className="text-xs text-tertiary mt-0.5">{hint}</div>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

export function SettingsPanel({ isOpen, onClose, namespaces }: SettingsPanelProps) {
  const { settings, updateSettings, resetSettings } = useSettings();
  const { activeCluster } = useCluster();
  if (!isOpen) return null;

  const selectCls =
    'h-8 rounded-control border border-hubble-border bg-hubble-darker text-primary text-sm px-2 focus:outline-none focus:border-hubble-accent';

  return (
    <>
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40" onClick={onClose} />
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
        <div
          className="w-full max-w-lg bg-hubble-card border border-hubble-border rounded-control shadow-2xl pointer-events-auto flex flex-col max-h-[85vh]"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="flex items-center justify-between h-14 px-5 border-b border-hubble-border shrink-0">
            <div>
              <h2 className="text-sm font-semibold text-primary">Settings</h2>
              <p className="text-xs text-tertiary">Preferences are saved to this browser</p>
            </div>
            <Button variant="ghost" size="sm" iconOnly leftIcon={X} onClick={onClose} aria-label="Close settings" />
          </div>

          <div className="overflow-y-auto px-5 py-2">
            <div className="pt-3 pb-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-tertiary">Workspace</div>
            <div className="divide-y divide-hubble-border">
              <Row label="Active cluster" hint="Switch clusters from the rail">
                <span className="text-sm text-secondary">{activeCluster.name}</span>
              </Row>
              <Row label="Default namespace" hint="Namespace to open on">
                <select
                  className={selectCls}
                  value={settings.defaultNamespace ?? ''}
                  onChange={(e) => updateSettings({ defaultNamespace: e.target.value || null })}
                >
                  <option value="">Auto (first with pods)</option>
                  {namespaces.map((ns) => (
                    <option key={ns} value={ns}>{ns}</option>
                  ))}
                </select>
              </Row>
            </div>

            <div className="pt-4 pb-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-tertiary">Graph defaults</div>
            <div className="divide-y divide-hubble-border">
              <Row label="Show external endpoints" hint="Internet / cross-cluster traffic nodes">
                <Toggle checked={settings.showExternalNodes} onChange={(v) => updateSettings({ showExternalNodes: v })} />
              </Row>
              <Row label="Show traffic edges">
                <Toggle checked={settings.showTraffic} onChange={(v) => updateSettings({ showTraffic: v })} />
              </Row>
              <Row label="Layout direction">
                <select
                  className={selectCls}
                  value={settings.layoutDirection}
                  onChange={(e) => updateSettings({ layoutDirection: e.target.value as 'LR' | 'TB' })}
                >
                  <option value="LR">Left → Right</option>
                  <option value="TB">Top → Bottom</option>
                </select>
              </Row>
            </div>
          </div>

          <div className="flex items-center justify-between gap-2 px-5 h-14 border-t border-hubble-border shrink-0">
            <Button variant="ghost" size="sm" onClick={resetSettings}>Reset to defaults</Button>
            <Button variant="primary" size="sm" onClick={onClose}>Done</Button>
          </div>
        </div>
      </div>
    </>
  );
}
