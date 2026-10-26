import { describe, expect, it } from 'vitest';
import {
  EMPTY_ALERT_FILTERS,
  alertState,
  buildAlertBulkFilterQuery,
  buildAlertQuery,
  bulkFilterCanScopeBySite,
  compactBucket,
  pageRange,
  trendBars,
} from './alerts';

describe('buildAlertBulkFilterQuery', () => {
  it('always sends the acknowledgement state', () => {
    // The queue decides it: the open tab is acknowledged=false, the history
    // tab acknowledged=true. The server requires at least one filter, and
    // this one is always present.
    const open = new URLSearchParams(buildAlertBulkFilterQuery(EMPTY_ALERT_FILTERS, false));
    expect(open.get('acknowledged')).toBe('false');
    const history = new URLSearchParams(buildAlertBulkFilterQuery(EMPTY_ALERT_FILTERS, true));
    expect(history.get('acknowledged')).toBe('true');
  });

  it('sends the filters the server accepts', () => {
    const q = new URLSearchParams(
      buildAlertBulkFilterQuery(
        { deviceId: '7', siteId: '', severity: 'critical', alertType: 'CPU_HIGH', includeSnoozed: false },
        false,
      ),
    );
    expect(q.get('device_id')).toBe('7');
    expect(q.get('severity')).toBe('critical');
    expect(q.get('alert_type')).toBe('CPU_HIGH');
  });

  it('NEVER sends site_id — the server ignores it', () => {
    // The bulk-by-filter endpoint accepts device_id, alert_type, severity
    // and acknowledged ONLY. A site_id in the query would be ignored, and
    // the action would reach alerts outside the site on screen.
    const q = new URLSearchParams(
      buildAlertBulkFilterQuery(
        { deviceId: '', siteId: '4', severity: '', alertType: '', includeSnoozed: false },
        false,
      ),
    );
    expect(q.has('site_id')).toBe(false);
  });
});

describe('bulkFilterCanScopeBySite', () => {
  it('is true when no site filter is active', () => {
    expect(bulkFilterCanScopeBySite(EMPTY_ALERT_FILTERS)).toBe(true);
  });

  it('is false when a site filter is active', () => {
    expect(bulkFilterCanScopeBySite({ ...EMPTY_ALERT_FILTERS, siteId: '4' })).toBe(false);
  });
});

describe('buildAlertQuery', () => {
  it('always sends acknowledgement, limit and offset', () => {
    const q = new URLSearchParams(buildAlertQuery({ acknowledged: false, filters: EMPTY_ALERT_FILTERS, offset: 0 }));
    expect(q.get('acknowledged')).toBe('false');
    expect(q.get('limit')).toBe('50');
    expect(q.get('offset')).toBe('0');
    expect(q.has('include_snoozed')).toBe(false);
  });

  it('adds only the filters that are set', () => {
    const q = new URLSearchParams(
      buildAlertQuery({
        acknowledged: true,
        offset: 100,
        limit: 25,
        filters: {
          deviceId: '7',
          siteId: 'unassigned',
          severity: 'critical',
          alertType: 'CPU_HIGH',
          includeSnoozed: true,
        },
      }),
    );
    expect(q.get('device_id')).toBe('7');
    expect(q.get('site_id')).toBe('unassigned');
    expect(q.get('severity')).toBe('critical');
    expect(q.get('alert_type')).toBe('CPU_HIGH');
    expect(q.get('include_snoozed')).toBe('true');
    expect(q.get('offset')).toBe('100');
    expect(q.get('limit')).toBe('25');
  });

  it('never emits a negative offset', () => {
    expect(new URLSearchParams(buildAlertQuery({ acknowledged: false, filters: EMPTY_ALERT_FILTERS, offset: -10 })).get('offset')).toBe('0');
  });
});

describe('alertState', () => {
  const NOW = Date.parse('2026-10-20T12:00:00Z');

  it('orders resolved > acknowledged > snoozed > open', () => {
    expect(alertState({ resolved_at: '2026-10-20T11:00:00Z', acknowledged: true }, NOW)).toBe('resolved');
    expect(alertState({ acknowledged: true, snoozed_until: '2026-10-20T18:00:00Z' }, NOW)).toBe('acknowledged');
    expect(alertState({ snoozed_until: '2026-10-20T18:00:00Z' }, NOW)).toBe('snoozed');
    expect(alertState({}, NOW)).toBe('open');
  });

  it('does not treat an expired snooze as snoozed', () => {
    expect(alertState({ snoozed_until: '2026-10-20T10:00:00Z' }, NOW)).toBe('open');
  });
});

describe('pageRange', () => {
  it('reports the visible window', () => {
    expect(pageRange(0, 50, 123)).toBe('1–50 of 123');
    expect(pageRange(100, 23, 123)).toBe('101–123 of 123');
    expect(pageRange(0, 0, 0)).toBe('0 of 0');
  });
});

describe('bucket labels', () => {
  it('compacts time and date buckets', () => {
    expect(compactBucket('2026-10-20 14:00')).toBe('14:00');
    expect(compactBucket('2026-10-20T14:00:00Z')).toBe('14:00');
    expect(compactBucket('2026-10-20')).toBe('10-20');
    expect(compactBucket('nonsense')).toBe('nonsense');
  });

  it('aggregates multi-day windows by day instead of showing repeated hours', () => {
    const buckets = [
      { bucket: '2026-10-19 22:00', count: 2 },
      { bucket: '2026-10-19 23:00', count: 3 },
      { bucket: '2026-10-20 00:00', count: 4 },
    ];
    expect(trendBars(buckets, 12, true)).toEqual([
      { label: '10-19', count: 5 },
      { label: '10-20', count: 4 },
    ]);
  });

  it('keeps only the last N trend buckets', () => {
    const buckets = Array.from({ length: 20 }, (_, i) => ({ bucket: `2026-10-20 ${String(i).padStart(2, '0')}:00`, count: i }));
    const bars = trendBars(buckets, 12);
    expect(bars).toHaveLength(12);
    expect(bars[0]?.label).toBe('08:00');
    expect(bars[11]?.count).toBe(19);
  });
});
