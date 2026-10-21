import { describe, expect, it } from 'vitest';
import {
  actionLabel,
  activityLabel,
  classLabel,
  directionLabel,
  eventBytesSeries,
  eventHitsSeries,
  severityLabel,
  timeBucketSeries,
} from './events';

describe('event labels', () => {
  it('maps classes/actions/activities/directions', () => {
    expect(classLabel(4001)).toBe('Network');
    expect(classLabel(2004)).toBe('Finding');
    expect(activityLabel(1)).toBe('Open');
    expect(activityLabel(44)).toBe('Tunnel stats');
    expect(actionLabel(1)).toBe('Allow');
    expect(actionLabel(2)).toBe('Deny');
    expect(directionLabel(2)).toBe('Outbound');
    expect(severityLabel(5)).toBe('Medium');
    expect(severityLabel(9)).toBe('Critical');
  });

  it('falls back to the raw value for unknown ids', () => {
    expect(classLabel(9999)).toBe('9999');
    expect(actionLabel(null)).toBe('—');
    expect(severityLabel(undefined)).toBe('—');
  });
});

describe('eventBytesSeries', () => {
  it('sums both directions and converts to bits per second', () => {
    const { timestamps, values } = eventBytesSeries(
      [{ hour: '2026-10-20 14:00', bytes_in: 1_000_000, bytes_out: 2_000_000 }],
      3600,
    );
    expect(timestamps).toEqual([Date.parse('2026-10-20T14:00:00Z')]);
    expect(values[0]).toBeCloseTo((3_000_000 * 8) / 3600);
  });

  it('accepts day buckets and sorts them', () => {
    const { timestamps } = eventBytesSeries(
      [
        { day: '2026-10-20', bytes_in: 10 },
        { day: '2026-10-19', bytes_in: 10 },
      ],
      86_400,
    );
    expect(timestamps).toEqual([
      Date.parse('2026-10-19T00:00:00Z'),
      Date.parse('2026-10-20T00:00:00Z'),
    ]);
  });

  it('skips unparseable buckets and yields zero bps for an unknown width', () => {
    const { timestamps, values } = eventBytesSeries(
      [{ hour: 'nope', bytes_in: 5 }, { hour: '2026-10-20 14:00', bytes_in: 5 }],
      0,
    );
    expect(timestamps).toHaveLength(1);
    expect(values).toEqual([0]);
  });
});

describe('timeBucketSeries', () => {
  it('maps generic stats buckets and sorts them', () => {
    const { timestamps, values } = timeBucketSeries([
      { bucket: '2026-10-20 15:00', count: 5 },
      { bucket: '2026-10-20 14:00', count: 2 },
      { bucket: 'junk', count: 99 },
    ]);
    expect(timestamps).toEqual([
      Date.parse('2026-10-20T14:00:00Z'),
      Date.parse('2026-10-20T15:00:00Z'),
    ]);
    expect(values).toEqual([2, 5]);
  });

  it('handles empty input', () => {
    expect(timeBucketSeries(undefined)).toEqual({ timestamps: [], values: [] });
  });
});

describe('eventHitsSeries', () => {
  it('maps hits in bucket order', () => {
    const { timestamps, values } = eventHitsSeries([
      { hour: '2026-10-20 15:00', hits: 4 },
      { hour: '2026-10-20 14:00', hits: 2 },
    ]);
    expect(timestamps).toEqual([
      Date.parse('2026-10-20T14:00:00Z'),
      Date.parse('2026-10-20T15:00:00Z'),
    ]);
    expect(values).toEqual([2, 4]);
  });

  it('handles empty input', () => {
    expect(eventHitsSeries(undefined)).toEqual({ timestamps: [], values: [] });
  });
});
