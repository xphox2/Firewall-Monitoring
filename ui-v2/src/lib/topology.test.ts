import { describe, expect, it } from 'vitest';
import { bundleEdges, linkColour, linkState, normalizePositions, type BundleableEdge } from './topology';

describe('linkState', () => {
  it('classifies healthy link states', () => {
    for (const value of ['up', 'UP', 'online', 'active', 'ok', 'healthy', 'established']) {
      expect(linkState(value)).toBe('up');
    }
  });

  it('classifies failure states', () => {
    for (const value of ['down', 'offline', 'failed', 'error', 'critical']) {
      expect(linkState(value)).toBe('down');
    }
  });

  it('treats unknown/stale/empty as neither up nor down', () => {
    for (const value of ['', null, undefined, 'unknown', 'stale', 'pending', 'backup']) {
      expect(linkState(value)).toBe('unknown');
    }
  });

  it('maps states to legend colours', () => {
    expect(linkColour('up')).toBe('#4ade80');
    expect(linkColour('down')).toBe('#f87171');
    expect(linkColour('stale')).toBe('#94a3b8');
  });
});

describe('bundleEdges', () => {
  const edge = (over: Partial<BundleableEdge>) => ({
    id: '1',
    source: 'dev-a',
    target: 'dev-b',
    kind: 'tunnel' as const,
    status: 'up',
    ...over,
  });

  it('draws a single edge directly instead of a one-item bundle', () => {
    const [result] = bundleEdges([edge({ id: 't1' })], true);
    expect(result.id).toBe('t1');
    expect(result.bundle).toBeUndefined();
    expect(result.members).toBeUndefined();
  });

  it('groups parallel tunnels and marks the members as sublanes', () => {
    const result = bundleEdges(
      [edge({ id: 't1' }), edge({ id: 't2' })],
      true,
    );
    const bundle = result.find((item) => item.bundle);
    const sublanes = result.filter((item) => item.sublane);
    expect(bundle?.id).toBe('bundle-tunnel|dev-a|dev-b');
    expect(bundle?.label).toBe('2 tunnels');
    expect(bundle?.members).toEqual(['edge-t1', 'edge-t2']);
    expect(sublanes.map((item) => item.id).sort()).toEqual(['t1', 't2']);
  });

  it('never merges a link bundle with a tunnel bundle on the same pair', () => {
    const result = bundleEdges(
      [
        edge({ id: 't1' }),
        edge({ id: 't2' }),
        edge({ id: 'c1', kind: 'connection', connectionId: 10 }),
        edge({ id: 'c2', kind: 'connection', connectionId: 11 }),
      ],
      true,
    );
    const bundles = result.filter((item) => item.bundle);
    expect(bundles.map((item) => item.label).sort()).toEqual(['2 links', '2 tunnels']);
    expect(new Set(bundles.map((item) => item.id)).size).toBe(2);
  });

  it('groups by unordered pair and uses the first edge as the carrier direction', () => {
    const result = bundleEdges(
      [edge({ id: 't1', source: 'dev-b', target: 'dev-a' }), edge({ id: 't2' })],
      true,
    );
    const bundle = result.find((item) => item.bundle);
    expect(bundle?.id).toBe('bundle-tunnel|dev-a|dev-b');
    expect(bundle?.source).toBe('dev-b');
    expect(bundle?.target).toBe('dev-a');
  });

  it('is down if any member is down, else up if any is up', () => {
    const down = bundleEdges(
      [edge({ id: 't1', status: 'down' }), edge({ id: 't2', status: 'up' })],
      true,
    ).find((item) => item.bundle);
    expect(down?.status).toBe('down');

    const up = bundleEdges(
      [edge({ id: 't1', status: 'unknown' }), edge({ id: 't2', status: 'up' })],
      true,
    ).find((item) => item.bundle);
    expect(up?.status).toBe('up');
  });

  it('keeps the original status when every member is unknown', () => {
    const bundle = bundleEdges(
      [edge({ id: 't1', status: 'stale' }), edge({ id: 't2', status: 'pending' })],
      true,
    ).find((item) => item.bundle);
    expect(bundle?.status).toBe('stale');
  });

  it('keeps connection ids on members but never on the carrier', () => {
    const result = bundleEdges(
      [
        edge({ id: 'c1', kind: 'connection', connectionId: 10 }),
        edge({ id: 'c2', kind: 'connection', connectionId: 11 }),
      ],
      true,
    );
    const bundle = result.find((item) => item.bundle);
    expect(bundle?.connectionId).toBeUndefined();
    expect(result.filter((item) => item.sublane).map((item) => item.connectionId)).toEqual([
      10, 11,
    ]);
  });

  it('returns every edge untouched when bundling is off', () => {
    const input = [edge({ id: 't1' }), edge({ id: 't2' })];
    const result = bundleEdges(input, false);
    expect(result).toHaveLength(2);
    expect(result.every((item) => !item.bundle && !item.sublane)).toBe(true);
  });
});

describe('normalizePositions', () => {
  it('keeps finite x/y points and drops everything else', () => {
    expect(
      normalizePositions({
        'dev-1': { x: 12.5, y: -4 },
        'dev-2': { x: '12', y: 4 },
        'dev-3': { x: Number.NaN, y: 4 },
        'dev-4': null,
        'dev-5': [10, 20],
      }),
    ).toEqual({ 'dev-1': { x: 12.5, y: -4 } });
  });

  it('returns an empty map for malformed payloads', () => {
    for (const value of [null, undefined, 'nope', 42, []]) {
      expect(normalizePositions(value)).toEqual({});
    }
  });
});
