// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { Tabs } from './Tabs';
import { tabPanelProps } from '../../utils/profileView';

afterEach(cleanup);

const TABS = [
  { id: 'a', label: 'Alpha' },
  { id: 'b', label: 'Beta' },
  { id: 'c', label: 'Gamma' },
] as const;
type Id = (typeof TABS)[number]['id'];

function Harness() {
  const [t, setT] = useState<Id>('a');
  return (
    <>
      <Tabs tabs={TABS} active={t} onChange={setT} label="Sections" idPrefix="x" />
      <div {...tabPanelProps('x', t)}>panel {t}</div>
    </>
  );
}

test('roving tabindex and arrow/Home/End keys move and activate', () => {
  render(<Harness />);
  const tabs = screen.getAllByRole('tab');
  expect(tabs.map((t) => t.tabIndex)).toEqual([0, -1, -1]);
  fireEvent.keyDown(tabs[0], { key: 'ArrowRight' });
  expect(screen.getByRole('tab', { name: 'Beta' }).getAttribute('aria-selected')).toBe('true');
  expect(document.activeElement).toBe(screen.getByRole('tab', { name: 'Beta' }));
  fireEvent.keyDown(document.activeElement!, { key: 'End' });
  expect(screen.getByRole('tabpanel').textContent).toBe('panel c');
  fireEvent.keyDown(document.activeElement!, { key: 'ArrowRight' });
  expect(screen.getByRole('tab', { name: 'Alpha' }).getAttribute('aria-selected')).toBe('true');
  fireEvent.keyDown(document.activeElement!, { key: 'ArrowLeft' });
  expect(screen.getByRole('tabpanel').getAttribute('aria-labelledby')).toBe('x-tab-c');
});
