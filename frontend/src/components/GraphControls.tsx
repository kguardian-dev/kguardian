import { ArrowDown, ArrowRight, Eye, EyeOff, Layers } from 'lucide-react';

// The Network Map toolbar (top-right). Extracted from NetworkGraph so the
// toggles can be rendered and tested without ReactFlow/ELK.

export interface GraphControlsProps {
  showTraffic: boolean;
  onToggleTraffic: () => void;
  showExternalNodes: boolean;
  onToggleExternalNodes: () => void;
  /** Visible external nodes (after the DaemonSets filter). */
  externalCount: number;
  showDaemonSetNodes: boolean;
  onToggleDaemonSetNodes: () => void;
  /** DaemonSet / host-network peers: shown when the toggle is on, hidden otherwise. */
  daemonSetCount: number;
  layoutDirection: 'LR' | 'TB';
  onToggleLayoutDirection: () => void;
}

const base = 'flex items-center gap-2 h-8 px-3 rounded-control border text-xs font-medium transition-colors';
const off = 'bg-hubble-card border-hubble-border text-tertiary hover:border-hubble-border-strong hover:text-secondary';

// Each toggle owns a hue so the three read apart at a glance:
// Traffic = brand indigo, External = amber, DaemonSets = teal (hubble-info).
export const TRAFFIC_ACTIVE = 'bg-hubble-accent/15 border-hubble-accent/50 text-hubble-accent hover:bg-hubble-accent/25';
export const EXTERNAL_ACTIVE = 'bg-hubble-warning/15 border-hubble-warning/50 text-hubble-warning hover:bg-hubble-warning/25';
export const DAEMONSET_ACTIVE = 'bg-hubble-info/15 border-hubble-info/50 text-hubble-info hover:bg-hubble-info/25';

export const DAEMONSET_TOGGLE_TOOLTIP = 'Show DaemonSet and host-network peers such as node-exporter, CNI and CSI agents';

export function GraphControls({
  showTraffic,
  onToggleTraffic,
  showExternalNodes,
  onToggleExternalNodes,
  externalCount,
  showDaemonSetNodes,
  onToggleDaemonSetNodes,
  daemonSetCount,
  layoutDirection,
  onToggleLayoutDirection,
}: GraphControlsProps) {
  return (
    <div className="flex gap-2">
      <button
        onClick={onToggleTraffic}
        className={`${base} ${showTraffic ? TRAFFIC_ACTIVE : off}`}
        title={showTraffic ? 'Hide traffic edges' : 'Show traffic edges'}
      >
        {showTraffic ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
        Traffic
      </button>
      {showTraffic && (
        <button
          onClick={onToggleExternalNodes}
          className={`${base} ${showExternalNodes ? EXTERNAL_ACTIVE : off}`}
          title={showExternalNodes ? 'Hide external namespace nodes' : 'Show external namespace nodes'}
        >
          {showExternalNodes ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
          External{externalCount > 0 ? ` (${externalCount})` : ''}
        </button>
      )}
      {showTraffic && showExternalNodes && (
        <button
          onClick={onToggleDaemonSetNodes}
          aria-pressed={showDaemonSetNodes}
          className={`${base} ${showDaemonSetNodes ? DAEMONSET_ACTIVE : off}`}
          title={DAEMONSET_TOGGLE_TOOLTIP}
        >
          {showDaemonSetNodes ? <Layers className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5 text-hubble-info" />}
          DaemonSets
          {daemonSetCount > 0 && ' '}
          {daemonSetCount > 0 && (
            // The hidden-count hint keeps the toggle's hue even while off, so
            // the user can see what the teal toggle is holding back.
            <span className={showDaemonSetNodes ? '' : 'text-hubble-info'}>
              ({daemonSetCount}{showDaemonSetNodes ? '' : ' hidden'})
            </span>
          )}
        </button>
      )}
      {showTraffic && (
        <button
          onClick={onToggleLayoutDirection}
          className={`${base} bg-hubble-card border-hubble-border text-secondary hover:border-hubble-border-strong hover:text-primary`}
          title={`Switch to ${layoutDirection === 'LR' ? 'vertical' : 'horizontal'} layout`}
        >
          {layoutDirection === 'LR' ? <ArrowRight className="w-3.5 h-3.5" /> : <ArrowDown className="w-3.5 h-3.5" />}
          Layout
        </button>
      )}
    </div>
  );
}
