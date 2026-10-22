import { describe, expect, it } from 'vitest';
import cytoscape, { type ElementDefinition } from 'cytoscape';
import { syncElements, type SyncState } from './topology-map';

function state(over: Partial<SyncState> = {}): SyncState {
  return {
    saved: {},
    session: {},
    expandedKeys: new Set<string>(),
    laidOut: false,
    ...over,
  };
}

function node(id: string, over: Record<string, unknown> = {}): ElementDefinition {
  return {
    data: {
      id,
      kind: 'device',
      label: id,
      status: 'up',
      colour: '#4ade80',
      ring: '#3b4654',
      ringWidth: 2,
      ...over,
    },
  };
}

function edge(
  id: string,
  source: string,
  target: string,
  over: Record<string, unknown> = {},
  classes?: string,
): ElementDefinition {
  return {
    data: {
      id,
      source,
      target,
      kind: 'tunnel',
      label: id,
      colour: '#4ade80',
      ...over,
    },
    classes,
  };
}

describe('syncElements', () => {
  it('applies saved positions on the first sync instead of laying out', () => {
    const cy = cytoscape({ headless: true });
    const laidOut = syncElements(cy, [node('dev-a'), node('dev-b')], state({
      saved: { 'dev-a': { x: 10, y: 20 }, 'dev-b': { x: 40, y: 60 } },
    }));
    expect(laidOut).toBe(true);
    expect(cy.getElementById('dev-a').position()).toEqual({ x: 10, y: 20 });
    expect(cy.getElementById('dev-b').position()).toEqual({ x: 40, y: 60 });
    cy.destroy();
  });

  it('updates data on a poll without moving a node the operator dragged', () => {
    const cy = cytoscape({ headless: true });
    const initial = [node('dev-a'), node('dev-b'), edge('edge-1', 'dev-a', 'dev-b')];
    const first = state({ saved: { 'dev-a': { x: 10, y: 20 }, 'dev-b': { x: 80, y: 90 } } });
    syncElements(cy, initial, first);
    cy.getElementById('dev-a').position({ x: 123, y: 45 });

    const polled = [
      node('dev-a', { status: 'down', label: 'A renamed' }),
      node('dev-b'),
      edge('edge-1', 'dev-a', 'dev-b', { status: 'down' }),
    ];
    const laidOut = syncElements(cy, polled, { ...first, laidOut: true });

    expect(laidOut).toBe(true);
    expect(cy.getElementById('dev-a').position()).toEqual({ x: 123, y: 45 });
    expect(cy.getElementById('dev-a').data('label')).toBe('A renamed');
    expect(cy.getElementById('edge-1').data('status')).toBe('down');
    cy.destroy();
  });

  it('detaches children before removing a site compound and keeps their positions', () => {
    const cy = cytoscape({ headless: true });
    const asSite = [
      { data: { id: 'site-1', kind: 'site', label: 'Site' }, grabbable: false },
      node('dev-a', { parent: 'site-1' }),
    ];
    const first = state({ saved: { 'dev-a': { x: 30, y: 40 } } });
    syncElements(cy, asSite, first);
    expect(cy.getElementById('dev-a').parent().first().id()).toBe('site-1');

    syncElements(cy, [node('dev-a')], { ...first, laidOut: true });

    const device = cy.getElementById('dev-a');
    expect(device.nonempty()).toBe(true);
    expect(device.parent().nonempty()).toBe(false);
    expect(device.position()).toEqual({ x: 30, y: 40 });
    cy.destroy();
  });

  it('moves an existing edge when its endpoints are re-assigned', () => {
    const cy = cytoscape({ headless: true });
    const first = state({
      saved: {
        'dev-a': { x: 0, y: 0 },
        'dev-b': { x: 50, y: 0 },
        'dev-c': { x: 0, y: 50 },
      },
    });
    syncElements(cy, [node('dev-a'), node('dev-b'), edge('edge-1', 'dev-a', 'dev-b')], first);
    expect(cy.getElementById('edge-1').target().id()).toBe('dev-b');

    syncElements(
      cy,
      [node('dev-a'), node('dev-b'), node('dev-c'), edge('edge-1', 'dev-a', 'dev-c')],
      { ...first, laidOut: true },
    );

    const moved = cy.getElementById('edge-1');
    expect(moved.source().id()).toBe('dev-a');
    expect(moved.target().id()).toBe('dev-c');
    cy.destroy();
  });

  it('keeps an expanded bundle open across reconciles and shows new members', () => {
    const cy = cytoscape({ headless: true });
    const first = state({
      saved: {
        'dev-a': { x: 0, y: 0 },
        'dev-b': { x: 100, y: 0 },
      },
      expandedKeys: new Set(['bundle-tunnel|dev-a|dev-b']),
    });
    const bundle = (members: string): ElementDefinition => ({
      data: {
        id: 'bundle-tunnel|dev-a|dev-b',
        source: 'dev-a',
        target: 'dev-b',
        kind: 'tunnel',
        label: '2 tunnels',
        colour: '#4ade80',
        bundleKey: 'bundle-tunnel|dev-a|dev-b',
        members,
      },
      classes: 'bundle',
    });
    syncElements(
      cy,
      [
        node('dev-a'),
        node('dev-b'),
        bundle('edge-1,edge-2'),
        edge('edge-1', 'dev-a', 'dev-b', {}, 'sublane'),
        edge('edge-2', 'dev-a', 'dev-b', {}, 'sublane'),
      ],
      first,
    );
    expect(cy.getElementById('bundle-tunnel|dev-a|dev-b').hasClass('expanded')).toBe(true);
    expect(cy.getElementById('edge-1').hasClass('shown')).toBe(true);

    // A poll adds a third member; the open bundle must reveal it too.
    syncElements(
      cy,
      [
        node('dev-a'),
        node('dev-b'),
        bundle('edge-1,edge-2,edge-3'),
        edge('edge-1', 'dev-a', 'dev-b', {}, 'sublane'),
        edge('edge-2', 'dev-a', 'dev-b', {}, 'sublane'),
        edge('edge-3', 'dev-a', 'dev-b', {}, 'sublane'),
      ],
      { ...first, laidOut: true },
    );
    expect(cy.getElementById('edge-3').hasClass('shown')).toBe(true);
    cy.destroy();
  });

  it('unhides the last member when a group shrinks below two', () => {
    const cy = cytoscape({ headless: true });
    const first = state({ saved: { 'dev-a': { x: 0, y: 0 }, 'dev-b': { x: 100, y: 0 } } });
    syncElements(
      cy,
      [
        node('dev-a'),
        node('dev-b'),
        edge('edge-1', 'dev-a', 'dev-b', {}, 'sublane'),
        edge('edge-2', 'dev-a', 'dev-b', {}, 'sublane'),
      ],
      first,
    );
    expect(cy.getElementById('edge-1').hasClass('sublane')).toBe(true);

    syncElements(
      cy,
      [node('dev-a'), node('dev-b'), edge('edge-1', 'dev-a', 'dev-b')],
      { ...first, laidOut: true },
    );
    const last = cy.getElementById('edge-1');
    expect(last.nonempty()).toBe(true);
    expect(last.hasClass('sublane')).toBe(false);
    expect(last.hasClass('shown')).toBe(false);
    cy.destroy();
  });
});
