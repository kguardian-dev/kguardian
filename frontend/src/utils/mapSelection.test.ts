import { describe, expect, test } from 'vitest';
import { paramsForSelection } from './mapSelection';

// Selecting a card focuses it as well as opening it. `paramsForSelection` is
// the one place that binds the two url params together, and App's `selectPod`
// calls exactly this — so breaking the rule here fails here, rather than
// leaving the graph quietly isolating the wrong workload.

describe('paramsForSelection', () => {
  test('a selection sets pod and focus to the same card', () => {
    expect(paramsForSelection('payments-api', 'payments')).toEqual({
      ns: 'payments', pod: 'payments-api', focus: 'payments-api',
    });
  });

  // Moving between cards must move the focus with the selection: leaving it
  // behind would isolate the map around a card the reader has already left.
  test('a different selection moves both', () => {
    expect(paramsForSelection('payments-worker', 'payments')).toEqual({
      ns: 'payments', pod: 'payments-worker', focus: 'payments-worker',
    });
  });

  // Clicking the canvas clears both: no card open, no isolated map.
  test('clearing the selection clears the focus too', () => {
    expect(paramsForSelection(null, 'payments')).toEqual({
      ns: 'payments', pod: undefined, focus: undefined,
    });
    expect(paramsForSelection(undefined, 'payments')).toEqual({
      ns: 'payments', pod: undefined, focus: undefined,
    });
  });

  // The namespace is carried through untouched; only the two bound params are
  // this function's business.
  test('the namespace passes through', () => {
    expect(paramsForSelection('a', undefined).ns).toBeUndefined();
    expect(paramsForSelection('a', 'media').ns).toBe('media');
  });
});
