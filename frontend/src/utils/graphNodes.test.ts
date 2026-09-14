import { describe, expect, test } from 'vitest';
import type { Node } from 'reactflow';
import { UNPLACED, mergeNodeData, placeNodes, pruneNodes } from './graphNodes';

// Fix #1: the 5 s compute poll rebuilds every node object with new gauge
// data. That must repaint the cards and NEVER move them — a card the user
// dragged has to stay where it was dropped until the layout itself changes.

const node = (id: string, data: Record<string, unknown> = {}, selected = false): Node => ({
  id, type: 'podNode', position: { x: 0, y: 0 }, data, selected,
});

describe('placeNodes (a layout result)', () => {
  test('hidden until ELK has placed at least one of the current nodes', () => {
    expect(placeNodes([node('a')], new Map())).toEqual([]);
    expect(placeNodes([], new Map([['a', { x: 1, y: 1 }]]))).toEqual([]);
  });
  test('places every node; an unplaced one is parked off-canvas', () => {
    const out = placeNodes([node('a'), node('b')], new Map([['a', { x: 10, y: 20 }]]));
    expect(out.map((n) => n.position)).toEqual([{ x: 10, y: 20 }, UNPLACED]);
  });
});

describe('pruneNodes (a layout-signature change)', () => {
  test('namespace switch: a wholly new id set blanks the graph until ELK lands', () => {
    const laid = placeNodes([node('payments-api')], new Map([['payments-api', { x: 1, y: 1 }]]));
    expect(pruneNodes(laid, new Set(['batch-etl']))).toEqual([]);
  });
  test('expansion toggle / node added: surviving cards keep their (dragged) positions', () => {
    let laid = placeNodes([node('a'), node('b')], new Map([['a', { x: 1, y: 1 }], ['b', { x: 2, y: 2 }]]));
    laid = laid.map((n) => (n.id === 'a' ? { ...n, position: { x: 99, y: 99 } } : n));
    const pruned = pruneNodes(laid, new Set(['a', 'b', 'c']));
    expect(pruned).toBe(laid);
    expect(pruned[0].position).toEqual({ x: 99, y: 99 });
    expect(pruneNodes(laid, new Set(['a'])).map((n) => n.id)).toEqual(['a']);
  });
});

describe('mergeNodeData (a data tick)', () => {
  test('drag a node, tick 5 s with fresh data: position unchanged, data replaced', () => {
    // Layout lands.
    let nodes = placeNodes([node('a', { cpu: 1 }), node('b', { cpu: 1 })], new Map([['a', { x: 10, y: 20 }], ['b', { x: 300, y: 20 }]]));
    // The user drags card "a" (what React Flow's onNodesChange applies).
    nodes = nodes.map((n) => (n.id === 'a' ? { ...n, position: { x: 555, y: 444 }, dragging: false } : n));
    // 5 s later the compute poll rebuilt every node object with new gauges.
    const tick = [node('a', { cpu: 2 }), node('b', { cpu: 2 })];
    const merged = mergeNodeData(nodes, tick);
    expect(merged.find((n) => n.id === 'a')!.position).toEqual({ x: 555, y: 444 });
    expect(merged.find((n) => n.id === 'b')!.position).toEqual({ x: 300, y: 20 });
    expect(merged.map((n) => n.data)).toEqual([{ cpu: 2 }, { cpu: 2 }]);
  });
  test('selection travels with the tick; identical data returns prev itself', () => {
    const data = { cpu: 1 };
    const laid = placeNodes([node('a', data)], new Map([['a', { x: 1, y: 2 }]]));
    expect(mergeNodeData(laid, [node('a', data)])).toBe(laid);
    const selected = mergeNodeData(laid, [node('a', data, true)]);
    expect(selected).not.toBe(laid);
    expect(selected[0].selected).toBe(true);
    expect(selected[0].position).toEqual({ x: 1, y: 2 });
  });
  test('never adds or removes nodes — that is a layout change, handled by placeNodes', () => {
    const laid = placeNodes([node('a'), node('b')], new Map([['a', { x: 1, y: 1 }], ['b', { x: 2, y: 2 }]]));
    const merged = mergeNodeData(laid, [node('a', { cpu: 9 }), node('c')]);
    expect(merged.map((n) => n.id)).toEqual(['a', 'b']);
    expect(merged[0].data).toEqual({ cpu: 9 });
    expect(mergeNodeData([], [node('a')])).toEqual([]);
  });
});

import { isRectInView, layoutIntent, layoutSignatureOf, type LayoutParts } from './graphNodes';

const parts = (nodes: Record<string, string>, edges: string[] = ['a>b'], direction = 'LR'): LayoutParts => ({
  direction,
  nodes: new Map(Object.entries(nodes)),
  edges,
});

describe('layoutIntent (what the viewport does after a layout)', () => {
  test('first layout and any change to the node set or edges refit', () => {
    expect(layoutIntent(null, parts({ a: '00', b: '00' }))).toEqual({ kind: 'refit' });
    expect(layoutIntent(parts({ a: '00', b: '00' }), parts({ a: '00', b: '00', c: '00' }))).toEqual({ kind: 'refit' });
    expect(layoutIntent(parts({ a: '00', b: '00' }), parts({ a: '00', c: '00' }))).toEqual({ kind: 'refit' });
    expect(layoutIntent(parts({ a: '00', b: '00' }), parts({ a: '00', b: '00' }, ['a>b', 'b>a']))).toEqual({ kind: 'refit' });
    expect(layoutIntent(parts({ a: '00', b: '00' }), parts({ a: '00', b: '00' }, ['a>b'], 'TB'))).toEqual({ kind: 'refit' });
  });

  test('opening one card is laid out in place and names that card', () => {
    expect(layoutIntent(parts({ a: '00', b: '00' }), parts({ a: '10', b: '00' }))).toEqual({ kind: 'in-place', toggledId: 'a' });
  });

  // Selection drives expansion, so moving between cards closes one and opens
  // another in the SAME pass. The card to follow is the one that opened: it is
  // what the user asked for and the only one that can have grown out of view.
  // Counting the closing card too would make "more than one changed" the
  // normal case and leave the viewport following nothing.
  test('moving the selection follows the card that opened, not the one that closed', () => {
    expect(layoutIntent(parts({ a: '10', b: '00' }), parts({ a: '00', b: '10' }))).toEqual({ kind: 'in-place', toggledId: 'b' });
  });

  // Deselecting closes the open card and opens none. There is nothing to pan
  // to — the user just dismissed it — so the viewport stays put.
  test('closing the last open card leaves no card to pan to', () => {
    expect(layoutIntent(parts({ a: '10', b: '00' }), parts({ a: '00', b: '00' }))).toEqual({ kind: 'in-place', toggledId: null });
  });

  test('gauges arriving on a poll tick are in place with no card to pan to', () => {
    expect(layoutIntent(parts({ a: '00', b: '00' }), parts({ a: '01', b: '01' }))).toEqual({ kind: 'in-place', toggledId: null });
  });

  // Two cards open at once cannot happen under selection-driven expansion, but
  // the rule must still degrade to "follow nothing" rather than pick arbitrarily.
  test('two cards opening at once: in place, no single target', () => {
    expect(layoutIntent(parts({ a: '00', b: '00' }), parts({ a: '10', b: '10' }))).toEqual({ kind: 'in-place', toggledId: null });
  });

  test('signature is stable for equal parts and differs on any change', () => {
    const p = parts({ a: '00', b: '10' });
    expect(layoutSignatureOf(p)).toBe(layoutSignatureOf(parts({ a: '00', b: '10' })));
    expect(layoutSignatureOf(p)).not.toBe(layoutSignatureOf(parts({ a: '00', b: '00' })));
  });
});

describe('isRectInView', () => {
  const pane = { width: 1000, height: 600 };
  test('a card inside the pane at zoom 1 is visible', () => {
    expect(isRectInView({ x: 100, y: 100, width: 240, height: 100 }, { x: 0, y: 0, zoom: 1 }, pane)).toBe(true);
  });
  test('a card that grew past the bottom edge is not', () => {
    expect(isRectInView({ x: 100, y: 550, width: 240, height: 180 }, { x: 0, y: 0, zoom: 1 }, pane)).toBe(false);
  });
  test('panning and zoom are applied', () => {
    // At zoom 0.5 the card at flow (1500, 100) lands at screen (750 + x, 50 + y).
    expect(isRectInView({ x: 1500, y: 100, width: 240, height: 100 }, { x: 0, y: 0, zoom: 0.5 }, pane)).toBe(true);
    expect(isRectInView({ x: 1500, y: 100, width: 240, height: 100 }, { x: -800, y: 0, zoom: 0.5 }, pane)).toBe(false);
  });
});

import { keepOnMap } from './graphNodes';

describe('keepOnMap (Traffic filter)', () => {
  const gauges = (c: string | undefined) => c === 'gauges';
  test('filter off: everything stays', () => {
    expect(keepOnMap({ id: 'a' }, false, null, gauges)).toBe(true);
  });
  test('filter on: pods with flows stay, silent pods without gauges go', () => {
    expect(keepOnMap({ id: 'a', traffic: [{}] }, true, null, gauges)).toBe(true);
    expect(keepOnMap({ id: 'a', traffic: [] }, true, null, gauges)).toBe(false);
  });
  test('a pod with compute gauges stays even with no flows (excluded namespaces)', () => {
    expect(keepOnMap({ id: 'kg', traffic: [], compute: 'gauges' }, true, null, gauges)).toBe(true);
    expect(keepOnMap({ id: 'kg', traffic: [], compute: 'off' }, true, null, gauges)).toBe(false);
  });
  test('a pod on a contention edge stays', () => {
    expect(keepOnMap({ id: 'v', traffic: [] }, true, new Set(['v']), gauges)).toBe(true);
  });
});

import { mergeLayoutIntent } from './graphNodes';

describe('mergeLayoutIntent (a layout still in flight)', () => {
  test('an unconsumed refit survives a gauge tick that arrives before ELK lands', () => {
    expect(mergeLayoutIntent({ kind: 'refit' }, { kind: 'in-place', toggledId: null })).toEqual({ kind: 'refit' });
    expect(mergeLayoutIntent({ kind: 'refit' }, { kind: 'in-place', toggledId: 'a' })).toEqual({ kind: 'refit' });
  });
  test('once consumed, the newer intent stands', () => {
    expect(mergeLayoutIntent(null, { kind: 'in-place', toggledId: 'a' })).toEqual({ kind: 'in-place', toggledId: 'a' });
    expect(mergeLayoutIntent(null, { kind: 'refit' })).toEqual({ kind: 'refit' });
  });
  test('an in-place intent is replaced by a later refit', () => {
    expect(mergeLayoutIntent({ kind: 'in-place', toggledId: 'a' }, { kind: 'refit' })).toEqual({ kind: 'refit' });
  });
});
