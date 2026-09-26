// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import AIAssistant from './AIAssistant';
import { DEFAULT_VIEW_MODE, readStoredViewMode } from '../utils/assistantViewMode';

describe('readStoredViewMode', () => {
  it('defaults to the docked side panel', () => {
    expect(DEFAULT_VIEW_MODE).toBe('side-panel');
    expect(readStoredViewMode(null)).toBe('side-panel');
    expect(readStoredViewMode({ getItem: () => null })).toBe('side-panel');
    expect(readStoredViewMode({ getItem: () => 'garbage' })).toBe('side-panel');
  });
  it('honours a remembered choice', () => {
    expect(readStoredViewMode({ getItem: () => 'modal' })).toBe('modal');
    expect(readStoredViewMode({ getItem: () => 'side-panel' })).toBe('side-panel');
  });
  it('survives a storage that throws', () => {
    expect(readStoredViewMode({ getItem: () => { throw new Error('blocked'); } })).toBe('side-panel');
  });
});

describe('AIAssistant opens docked', () => {
  beforeEach(() => {
    localStorage.clear();
  });
  // Unmount after every test, not only before the next one. The modal
  // flips to its entered state on a requestAnimationFrame; left mounted
  // after the last test, that update renders outside act() and React's
  // scheduler can run the commit after vitest has torn down jsdom,
  // failing the run with "window is not defined". Unmounting runs the
  // Modal's effect cleanup, which cancels the pending frames.
  afterEach(cleanup);

  it('reports the side-panel layout to the app on open and renders the docked chrome', () => {
    const onLayoutChange = vi.fn();
    render(<AIAssistant isOpen onClose={() => {}} onLayoutChange={onLayoutChange} namespace="default" podNames={[]} />);
    expect(onLayoutChange).toHaveBeenCalledWith(true, false, 448);
    // The modal's "Dock to side" control is absent; the docked panel's is present.
    expect(screen.queryByLabelText('Dock to side')).toBeNull();
    expect(screen.getByLabelText('Expand to center')).toBeTruthy();
  });

  it('opens as a modal when that was the last choice', () => {
    localStorage.setItem('kguardian.ai-assistant.view-mode', 'modal');
    const onLayoutChange = vi.fn();
    render(<AIAssistant isOpen onClose={() => {}} onLayoutChange={onLayoutChange} namespace="default" podNames={[]} />);
    expect(onLayoutChange).toHaveBeenCalledWith(false, false, 448);
    expect(screen.getByLabelText('Dock to side')).toBeTruthy();
  });
});
