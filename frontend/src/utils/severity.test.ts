import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import {
  RISK_TIERS,
  SEVERITIES,
  SEVERITY_BADGE_CLASS,
  SEVERITY_DOT_CLASS,
  SEVERITY_TEXT_CLASS,
  TIER_BADGE_CLASS,
  TIER_SEVERITY,
  worstSeverity,
} from './severity';

// The palette is only worth having if (a) every mapping lands on the
// dedicated tokens, (b) those tokens exist in BOTH themes, and (c) the values
// are readable. These read index.css itself, so a token renamed or dropped in
// one theme fails here instead of rendering as transparent text.

const css = readFileSync(fileURLToPath(new URL('../index.css', import.meta.url)), 'utf8');

/** Custom properties declared in the first block whose selector matches. */
function block(selector: RegExp): Record<string, string> {
  const m = css.match(new RegExp(`${selector.source}\\s*\\{([^}]*)\\}`));
  if (!m) throw new Error(`no block for ${selector}`);
  const out: Record<string, string> = {};
  for (const [, k, v] of m[1].matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) out[k] = v.trim();
  return out;
}

const dark = block(/:root,\s*:root\.dark/);
const light = block(/:root\.light/);
const theme = block(/@theme/);

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const v = parseInt(hex.slice(i, i + 2), 16) / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(a: string, b: string): number {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}
/** `fg` at `alpha` over `bg` — the tinted pill fill. */
function over(fg: string, bg: string, alpha: number): string {
  const ch = (h: string, i: number) => parseInt(h.slice(i, i + 2), 16);
  return '#' + [1, 3, 5].map((i) => Math.round(ch(fg, i) * alpha + ch(bg, i) * (1 - alpha)).toString(16).padStart(2, '0')).join('');
}

const SEV_VARS = ['--theme-sev-critical', '--theme-sev-high', '--theme-sev-medium', '--theme-sev-low'];
/** Control-lifecycle pill tokens (StatePill, NetworkPill). */
const STATE_VARS = ['--theme-state-enforcing', '--theme-state-audit'];
const ALL_VARS = [...SEV_VARS, ...STATE_VARS];

describe('severity tokens', () => {
  test.each(ALL_VARS)('%s is defined in both themes', (v) => {
    expect(dark[v]).toMatch(/^#[0-9A-Fa-f]{6}$/);
    expect(light[v]).toMatch(/^#[0-9A-Fa-f]{6}$/);
  });

  test('audit has its own token, not the brand accent', () => {
    expect(theme['--color-state-audit']).toBe('var(--theme-state-audit)');
    const accent = theme['--color-hubble-accent'].toLowerCase();
    expect(dark['--theme-state-audit'].toLowerCase()).not.toBe(accent);
  });

  test('medium is not the brand indigo, critical is not the enforcing green', () => {
    const accent = theme['--color-hubble-accent'].toLowerCase();
    for (const t of [dark, light]) {
      expect(t['--theme-sev-medium'].toLowerCase()).not.toBe(accent);
      expect(t['--theme-sev-critical'].toLowerCase()).not.toBe(t['--theme-state-enforcing'].toLowerCase());
    }
  });

  test('the four severities are four distinct colours per theme', () => {
    for (const t of [dark, light]) {
      const vals = SEV_VARS.map((v) => t[v].toLowerCase());
      expect(new Set(vals).size).toBe(4);
    }
  });

  // WCAG AA for normal text is 4.5:1. Pill text sits on a 15% tint of itself
  // over the card, so check that too, not just the bare surface.
  test.each([
    ['dark', dark, dark['--theme-bg-card']],
    ['dark (page)', dark, dark['--theme-bg-dark']],
    ['light', light, light['--theme-bg-card']],
    ['light (page)', light, light['--theme-bg-dark']],
  ])('every severity and state token meets AA on the %s surface', (_name, t, surface) => {
    for (const v of ALL_VARS) {
      expect(contrast(t[v], surface), `${v} on ${surface}`).toBeGreaterThanOrEqual(4.5);
      expect(contrast(t[v], over(t[v], surface, 0.15)), `${v} on its pill`).toBeGreaterThanOrEqual(4.5);
    }
  });

  test('tier tokens alias the severity scale in @theme', () => {
    expect(theme['--color-tier-p0']).toBe('var(--theme-sev-critical)');
    expect(theme['--color-tier-p1']).toBe('var(--theme-sev-high)');
    expect(theme['--color-tier-p2']).toBe('var(--theme-sev-medium)');
    for (const s of SEVERITIES) expect(theme[`--color-severity-${s}`]).toBe(`var(--theme-sev-${s})`);
    expect(theme['--color-state-enforcing']).toBe('var(--theme-state-enforcing)');
  });
});

describe('severity class mapping', () => {
  test.each(SEVERITIES)('%s maps onto its own severity token only', (s) => {
    for (const cls of [SEVERITY_BADGE_CLASS[s], SEVERITY_TEXT_CLASS[s], SEVERITY_DOT_CLASS[s]]) {
      expect(cls).toContain(`severity-${s}`);
      expect(cls).not.toMatch(/hubble-(accent|error|warning|success)/);
      for (const other of SEVERITIES.filter((o) => o !== s)) expect(cls).not.toContain(`severity-${other}`);
    }
  });

  test.each(RISK_TIERS)('tier %s maps onto its tier token', (t) => {
    expect(TIER_BADGE_CLASS[t]).toContain(`tier-${t.toLowerCase()}`);
    expect(TIER_BADGE_CLASS[t]).not.toMatch(/hubble-/);
  });

  test('tiers are drawn in critical/high/medium', () => {
    expect(TIER_SEVERITY).toEqual({ P0: 'critical', P1: 'high', P2: 'medium' });
  });

  test('worstSeverity', () => {
    expect(worstSeverity([])).toBeNull();
    expect(worstSeverity(['low', 'medium', 'high'])).toBe('high');
    expect(worstSeverity(['medium', 'critical', 'low'])).toBe('critical');
  });
});
