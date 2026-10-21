import { describe, expect, it } from 'vitest';
import { mergeFeed, type NocFeedPayload } from './noc';

const FEED: NocFeedPayload = {
  alerts: [
    { id: 1, at: '2026-10-20T10:00:00Z', type: 'CPU_HIGH', severity: 'warning' },
    { id: 2, at: '2026-10-20T10:05:00Z', type: 'LINK_DOWN', severity: 'critical' },
  ],
  detections: [{ id: 3, at: '2026-10-20T10:02:00Z', type: 'port_scan', severity: 'warning' }],
  silenced: [{ id: 4, last_seen: '2026-10-20T10:10:00Z', type: 'FLOW_DIGEST' }],
};

describe('mergeFeed', () => {
  it('merges all lists newest-first', () => {
    expect(mergeFeed(FEED, 'all', 20).map((r) => r.item.id)).toEqual([4, 2, 3, 1]);
  });

  it('filters by kind', () => {
    expect(mergeFeed(FEED, 'alerts', 20).map((r) => r.item.id)).toEqual([2, 1]);
    expect(mergeFeed(FEED, 'detections', 20).map((r) => r.item.id)).toEqual([3]);
    expect(mergeFeed(FEED, 'silenced', 20).map((r) => r.item.id)).toEqual([4]);
  });

  it('caps the number of rows', () => {
    expect(mergeFeed(FEED, 'all', 2).map((r) => r.item.id)).toEqual([4, 2]);
    expect(mergeFeed(FEED, 'all', 0)).toEqual([]);
  });

  it('prefers last_seen over at for ordering', () => {
    const rows = mergeFeed(
      {
        alerts: [
          { id: 1, at: '2026-10-20T10:00:00Z', last_seen: '2026-10-20T10:30:00Z' },
          { id: 2, at: '2026-10-20T10:20:00Z' },
        ],
      },
      'all',
      10,
    );
    expect(rows.map((r) => r.item.id)).toEqual([1, 2]);
  });

  it('handles empty/null payloads', () => {
    expect(mergeFeed(null, 'all', 10)).toEqual([]);
    expect(mergeFeed({}, 'all', 10)).toEqual([]);
  });
});
