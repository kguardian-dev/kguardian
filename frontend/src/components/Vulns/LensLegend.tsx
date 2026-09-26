import { Loader2 } from 'lucide-react';
import type { MapLens } from '../../types';
import { LENS_FINDINGS_CAP, LENS_IMAGE_CAP, type MapLensState } from '../../hooks/useMapLens';
import { vulnErrorKind, vulnErrorMessage } from '../../services/vulnApi';

const KEYS: Record<Exclude<MapLens, 'traffic'>, Array<{ cls: string; text: string; meaning: string }>> = {
  vulns: [
    { cls: 'bg-tier-p0/15 text-tier-p0 border-tier-p0/30', text: 'P0', meaning: 'act now' },
    { cls: 'bg-tier-p1/15 text-tier-p1 border-tier-p1/30', text: 'P1', meaning: 'schedule' },
    { cls: 'bg-hubble-border/30 text-secondary border-hubble-border', text: 'no P0/P1', meaning: 'reported, nothing urgent' },
    { cls: 'text-tertiary border-dashed border-hubble-border-strong', text: 'no data', meaning: 'unknown, not clean' },
    { cls: 'text-tertiary border-dashed border-hubble-border-strong', text: 'tier ?', meaning: 'Broker has no tiers' },
  ],
  supply: [
    { cls: 'bg-state-enforcing/15 text-state-enforcing border-state-enforcing/30', text: 'SBOM verified', meaning: 'signed attestation' },
    { cls: 'bg-hubble-border/30 text-secondary border-hubble-border', text: 'SBOM', meaning: 'present, unverified' },
    { cls: 'text-tertiary border-dashed border-hubble-border-strong', text: 'no SBOM', meaning: 'unknown' },
  ],
  coverage: [
    { cls: 'bg-state-enforcing/15 text-state-enforcing border-state-enforcing/30', text: '% seen', meaning: 'posture ok' },
    { cls: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30', text: '% seen', meaning: 'warn' },
    { cls: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30', text: '% seen', meaning: 'risk' },
    { cls: 'text-tertiary border-dashed border-hubble-border-strong', text: 'no profile', meaning: 'unknown' },
  ],
};

const NOTE: Record<Exclude<MapLens, 'traffic'>, string> = {
  vulns: "The Broker's tiers. A shared image carries its worst workload's tier. Unknown in-use and exposure rank as in use and exposed.",
  supply: 'Image signatures are not checked yet; nothing is shown as signed.',
  coverage: "Share of the workload profile's dimensions that have data.",
};

/** The map legend for a non-traffic lens, with its loading / error / capped state. */
export function LensLegend({ lens, state }: { lens: Exclude<MapLens, 'traffic'>; state: MapLensState }) {
  const kind = state.error ? vulnErrorKind(state.error) : null;
  return (
    <div className="max-w-[20rem] rounded-surface border border-hubble-border bg-hubble-card/95 backdrop-blur-sm px-3 py-2 text-[11px] text-secondary space-y-1.5" data-testid="lens-legend">
      <div className="flex flex-wrap gap-x-3 gap-y-1">
        {KEYS[lens].map((k) => (
          <span key={`${k.text}-${k.meaning}`} className="inline-flex items-center gap-1">
            <span className={`rounded border px-1 font-mono text-[10px] font-semibold leading-4 ${k.cls}`}>{k.text}</span>
            {k.meaning}
          </span>
        ))}
      </div>
      <p className="hidden sm:block text-tertiary">{NOTE[lens]}</p>
      {state.loading && (
        <p className="flex items-center gap-1 text-tertiary"><Loader2 className="w-3 h-3 animate-spin" aria-hidden />Reading…</p>
      )}
      {state.error != null && (
        <p role="alert" className="text-severity-critical">
          {kind === 'auth' ? 'Broker token required: ' : ''}{vulnErrorMessage(state.error)} Cards show unknown.
        </p>
      )}
      {state.truncated && !state.loading && (
        <p className="text-severity-medium">
          Capped: {lens === 'vulns' ? `the first ${LENS_IMAGE_CAP} images and ${LENS_FINDINGS_CAP} P0/P1 findings per image` : lens === 'supply' ? `the first ${LENS_IMAGE_CAP} images` : 'the first 500 workloads'} were read; badges cover only what was read.
        </p>
      )}
    </div>
  );
}
