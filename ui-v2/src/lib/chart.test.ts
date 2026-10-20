import { describe, expect, it } from 'vitest';
import {
  bucketSeconds,
  counterDeltasToBps,
  formatAxisValue,
  formatBitsPerSecond,
  formatValue,
  numOrNull,
  toBitsPerSecond,
} from './chart';

describe('bucketSeconds', () => {
  it('uses the median gap and ignores a short series', () => {
    expect(bucketSeconds([0])).toBe(0);
    expect(bucketSeconds([0, 60_000, 120_000])).toBe(60);
    // One long gap must not skew the bucket size.
    expect(bucketSeconds([0, 60_000, 120_000, 3_600_000])).toBe(60);
  });
});

describe('toBitsPerSecond', () => {
  it('converts per-bucket bytes to a rate and keeps gaps', () => {
    expect(toBitsPerSecond([750, 0, null], 60)).toEqual([100, 0, null]);
  });

  it('returns nulls rather than Infinity when the span is unknown', () => {
    expect(toBitsPerSecond([100], 0)).toEqual([null]);
  });
});

describe('counterDeltasToBps', () => {
  it('diffs cumulative counters over the actual interval', () => {
    // 100 bytes in 60s = (100*8)/60 bps; the first point has no predecessor.
    const out = counterDeltasToBps([1000, 1100, 1200], [0, 60_000, 120_000]);
    expect(out[0]).toBeNull();
    expect(out[1]).toBeCloseTo(13.333, 2);
    expect(out[2]).toBeCloseTo(13.333, 2);
  });

  it('clamps a counter reset to zero instead of a negative spike', () => {
    const out = counterDeltasToBps([5000, 10], [0, 60_000]);
    expect(out[1]).toBe(0);
  });

  it('keeps gaps as null and ignores non-positive intervals', () => {
    expect(counterDeltasToBps([1, null, 3], [0, 60_000, 120_000])).toEqual([null, null, null]);
    expect(counterDeltasToBps([1, 2], [0, 0])).toEqual([null, null]);
  });
});

describe('formatters', () => {
  it('scales bit rates', () => {
    expect(formatBitsPerSecond(999)).toBe('999 bps');
    expect(formatBitsPerSecond(1500)).toBe('1.5 Kbps');
    expect(formatBitsPerSecond(2_500_000)).toBe('2.5 Mbps');
    expect(formatBitsPerSecond(10_000_000_000)).toBe('10.0 Gbps');
  });

  it('formats axis ticks per chart kind', () => {
    expect(formatAxisValue(42.4, 'percent')).toBe('42%');
    expect(formatAxisValue(1_500_000, 'bps')).toBe('2M');
    expect(formatAxisValue(1_500_000, 'bytes')).toBe('2MB');
  });

  it('formats the legend value and treats null as a dash', () => {
    expect(formatValue(null, 'percent')).toBe('—');
    expect(formatValue(12.34, 'percent')).toBe('12.3%');
    expect(formatValue(2048, 'bytes')).toBe('2KB');
  });
});

describe('numOrNull', () => {
  it('coerces numbers and strings but not blanks', () => {
    expect(numOrNull(3)).toBe(3);
    expect(numOrNull('3.5')).toBe(3.5);
    expect(numOrNull(null)).toBeNull();
    expect(numOrNull('')).toBeNull();
    expect(numOrNull('nope')).toBeNull();
  });
});
