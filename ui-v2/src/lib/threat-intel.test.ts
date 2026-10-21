import { describe, expect, it } from 'vitest';
import {
  EMPTY_INDICATOR_FILTERS,
  buildIndicatorQuery,
  feedState,
  lookupVerdict,
} from './threat-intel';

describe('lookupVerdict', () => {
  it('flags a known-bad IP and lists the scopes', () => {
    const v = lookupVerdict({
      query: '203.0.113.9',
      kind: 'ip',
      country: 'US',
      known_bad: true,
      threats: [
        { scope: 'ip', category: 'c2', severity: 'critical' },
        { scope: 'asn', category: 'scanner', severity: 'warning' },
      ],
    });
    expect(v.tone).toBe('crit');
    expect(v.label).toBe('KNOWN-BAD');
    expect(v.detail).toContain('ip:c2');
    expect(v.detail).toContain('asn:scanner');
  });

  it('handles an ASN-only match', () => {
    const v = lookupVerdict({
      query: 'AS64500',
      kind: 'asn',
      known_bad: true,
      threat: { scope: 'asn', category: 'hosting' },
    });
    expect(v.tone).toBe('crit');
    expect(v.detail).toContain('asn:hosting');
  });

  it('warns when an IP has no geo/ASN enrichment', () => {
    expect(lookupVerdict({ query: '198.51.100.7', kind: 'ip', known_bad: false })).toMatchObject({
      tone: 'warn',
    });
  });

  it('reports clean when enriched and not listed', () => {
    expect(
      lookupVerdict({
        query: '198.51.100.7',
        kind: 'ip',
        country: 'US',
        asn: 64500,
        known_bad: false,
        threats: [],
      }),
    ).toMatchObject({ tone: 'ok', label: 'Not listed' });
  });
});

describe('feedState', () => {
  it('reports disabled before any error', () => {
    expect(feedState({ source: 'x', enabled: false, last_error: 'old' }).label).toBe('disabled');
  });

  it('reports error, never-synced and ok in order', () => {
    expect(feedState({ source: 'x', last_error: 'boom' })).toMatchObject({
      label: 'error',
      tone: 'crit',
    });
    expect(feedState({ source: 'x' })).toMatchObject({ label: 'never synced', tone: 'warn' });
    expect(
      feedState({ source: 'x', last_sync_at: new Date().toISOString(), entry_count: 5 }),
    ).toMatchObject({ label: 'ok', tone: 'ok' });
  });
});

describe('buildIndicatorQuery', () => {
  it('always sends paging and only set filters', () => {
    const q = new URLSearchParams(buildIndicatorQuery(EMPTY_INDICATOR_FILTERS, 0));
    expect(q.get('limit')).toBe('50');
    expect(q.get('offset')).toBe('0');
    expect(q.has('q')).toBe(false);
    expect(q.has('active')).toBe(false);
  });

  it('encodes every filter', () => {
    const q = new URLSearchParams(
      buildIndicatorQuery(
        {
          q: ' 203.0.113.0/24 ',
          source: 'manual',
          category: 'scanner',
          severity: 'critical',
          activeOnly: true,
        },
        100,
        25,
      ),
    );
    expect(q.get('q')).toBe('203.0.113.0/24');
    expect(q.get('source')).toBe('manual');
    expect(q.get('category')).toBe('scanner');
    expect(q.get('severity')).toBe('critical');
    expect(q.get('active')).toBe('true');
    expect(q.get('offset')).toBe('100');
    expect(q.get('limit')).toBe('25');
  });

  it('never emits a negative offset', () => {
    expect(
      new URLSearchParams(buildIndicatorQuery(EMPTY_INDICATOR_FILTERS, -10)).get('offset'),
    ).toBe('0');
  });
});
