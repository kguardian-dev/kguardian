import { readFileSync } from 'node:fs';
import { expect, test } from 'vitest';

// The accent as text was 2.3 to 2.6:1 on the dark surfaces (active rail item,
// palette icon, audit counts). text-accent-fg exists so those read at AA; this
// pins the token and its contrast on every surface it can sit on, per theme.
const css = readFileSync(new URL('./index.css', import.meta.url), 'utf8');

function block(selector: string): string {
  const start = css.indexOf(selector);
  if (start < 0) throw new Error(`${selector} not found`);
  return css.slice(start, css.indexOf('}', start));
}

function hex(scope: string, name: string): string {
  const m = scope.match(new RegExp(`${name}:\\s*(#[0-9A-Fa-f]{6})`));
  if (!m) throw new Error(`${name} has no hex value`);
  return m[1];
}

function luminance(color: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(color.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const SURFACES = ['--theme-bg-dark', '--theme-bg-darker', '--theme-bg-card', '--theme-bg-hover'];
const dark = block(':root,\n:root.dark');
const light = block(':root.light');

test('text-accent-fg is a theme token in both themes', () => {
  expect(css).toMatch(/--color-accent-fg:\s*var\(--theme-accent-fg\)/);
  expect(hex(dark, '--theme-accent-fg')).toBeTruthy();
  expect(hex(light, '--theme-accent-fg')).toBeTruthy();
});

test.each([
  ['dark', dark],
  ['light', light],
])('accent-fg reads at AA (4.5:1) as small text on every %s surface', (_, theme) => {
  const fg = hex(theme, '--theme-accent-fg');
  for (const surface of SURFACES) {
    expect(contrast(fg, hex(theme, surface)), `${fg} on ${surface}`).toBeGreaterThanOrEqual(4.5);
  }
});

test('the brand accent itself fails AA as text on the dark card, which is why the token exists', () => {
  expect(contrast(hex(css, '--color-hubble-accent'), hex(dark, '--theme-bg-card'))).toBeLessThan(4.5);
});
