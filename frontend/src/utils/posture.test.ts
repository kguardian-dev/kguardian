import { describe, expect, it } from 'vitest';
import { driftGapsOf, driftNotEvaluatedText } from './posture';

describe('driftGapsOf', () => {
  it('uses notEvaluated when the broker sends it', () => {
    const g = driftGapsOf({ evaluated: [], notEvaluated: [{ type: 'unshippedExecutable', container: 'app', reason: 'coverage_unavailable' }], items: [] });
    expect(g).toEqual([{ type: 'unshippedExecutable', container: 'app', reason: 'coverage_unavailable' }]);
    expect(driftNotEvaluatedText('coverage_unavailable')).toContain('coverage function is missing');
  });
  it('derives v1.4 gaps from evaluated, and treats a missing evaluated as nothing evaluated', () => {
    expect(driftGapsOf({ evaluated: ['tagMoved'], items: [] }).map((g) => g.type)).toEqual(['imageChangedSinceExport', 'securityContextRegression']);
    const none = driftGapsOf({ items: [] } as never);
    expect(none.map((g) => g.type)).toEqual(['tagMoved', 'imageChangedSinceExport', 'securityContextRegression']);
    expect(none.every((g) => g.reason === 'not_reported')).toBe(true);
  });
  it('has nothing to say without a drift block (pre-v1.4 broker)', () => {
    expect(driftGapsOf(undefined)).toEqual([]);
  });
});
