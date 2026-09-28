// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { Position } from 'reactflow';
import type { ReactNode } from 'react';

// MAP-12: drop labels were clipped by the cards they ran into because a
// default edge label is drawn under the nodes. The label renderer needs the
// live React Flow DOM, so it is stubbed to render in place here.
vi.mock('reactflow', async (orig) => ({
  ...(await orig<typeof import('reactflow')>()),
  EdgeLabelRenderer: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

import TrafficEdge, { DROP_LABEL_Z_INDEX } from './TrafficEdge';

afterEach(cleanup);

const edge = (label: string, isDrop: boolean) =>
  render(
    <svg>
      <TrafficEdge
        id="a::b"
        source="a"
        target="b"
        sourceX={0}
        sourceY={0}
        targetX={200}
        targetY={0}
        sourcePosition={Position.Right}
        targetPosition={Position.Left}
        data={{ label, isDrop }}
        style={{ stroke: '#EF4444' }}
      />
    </svg>,
  );

test('a drop label is red and lifted above unselected cards', () => {
  const { getByTestId } = edge('6379/TCP (1 drop)', true);
  const label = getByTestId('traffic-edge-label');
  expect(label.textContent).toBe('6379/TCP (1 drop)');
  expect(label.style.zIndex).toBe(String(DROP_LABEL_Z_INDEX));
  expect(label.getAttribute('class')).toContain('text-hubble-error');
  // Above a card at rest (0), below the one card that is open (1000).
  expect(DROP_LABEL_Z_INDEX).toBeGreaterThan(0);
  expect(DROP_LABEL_Z_INDEX).toBeLessThan(1000);
});

test('an allowed label keeps the default layering and tone', () => {
  const { getByTestId } = edge('HTTPS', false);
  const label = getByTestId('traffic-edge-label');
  expect(label.style.zIndex).toBe('');
  expect(label.getAttribute('class')).not.toContain('text-hubble-error');
  expect(label.getAttribute('data-drop')).toBeNull();
});

test('the edge path is drawn', () => {
  const { container } = edge('HTTPS', false);
  expect(container.querySelector('path.react-flow__edge-path')).not.toBeNull();
});
