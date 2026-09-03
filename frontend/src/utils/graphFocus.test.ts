import { describe, expect, test } from 'vitest';
import { shouldExitFocus } from './graphFocus';

describe('shouldExitFocus', () => {
  test('no focus → never exits', () => {
    expect(shouldExitFocus(null, ['a'], true)).toBe(false);
  });
  test('keeps a deep-linked focus while the graph has not loaded yet', () => {
    expect(shouldExitFocus('a', [], false)).toBe(false);
  });
  test('keeps focus while the node is present', () => {
    expect(shouldExitFocus('a', ['b', 'a'], true)).toBe(false);
  });
  test('exits once loaded and the node is gone (namespace switch, pod deleted)', () => {
    expect(shouldExitFocus('a', ['b'], true)).toBe(true);
    expect(shouldExitFocus('a', [], true)).toBe(true);
  });
});
