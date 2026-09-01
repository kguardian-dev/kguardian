import { describe, it, expect } from 'vitest';
import { displaySyscallList } from './syscalls';

// The capture layer emits syscalls in observation order, which differs
// between pods and across refreshes. Every listing goes through
// displaySyscallList so the same workload always reads the same way —
// including the collapsed 10-chip preview, which must show a stable
// alphabetical prefix rather than an arbitrary capture-order subset.
describe('displaySyscallList', () => {
  it('sorts alphabetically regardless of capture order', () => {
    expect(displaySyscallList('write,open,close,read')).toEqual(['close', 'open', 'read', 'write']);
    expect(displaySyscallList('read,close,write,open')).toEqual(['close', 'open', 'read', 'write']);
  });

  it('trims entries and drops empties', () => {
    expect(displaySyscallList(' read , write ,, ,close')).toEqual(['close', 'read', 'write']);
  });

  it('de-duplicates repeated observations', () => {
    expect(displaySyscallList('read,write,read,read')).toEqual(['read', 'write']);
  });

  it('returns empty for an empty record', () => {
    expect(displaySyscallList('')).toEqual([]);
    expect(displaySyscallList(' , ,')).toEqual([]);
  });
});
