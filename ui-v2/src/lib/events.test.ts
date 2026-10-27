import { describe, expect, it } from 'vitest';
import { secDayCountSeries } from './events';

describe('secDayCountSeries', () => {
  it('parses the day as UTC midnight', () => {
    const out = secDayCountSeries([{ day: '2026-10-26', count: 7 }]);
    expect(out.timestamps).toHaveLength(1);
    expect(out.timestamps[0]).toBe(Date.parse('2026-10-26T00:00:00Z') / 1000);
    expect(out.values).toEqual([7]);
  });

  it('sorts the points oldest-first', () => {
    const out = secDayCountSeries([
      { day: '2026-10-27', count: 2 },
      { day: '2026-10-25', count: 1 },
      { day: '2026-10-26', count: 3 },
    ]);
    expect(out.values).toEqual([1, 3, 2]);
  });

  it('skips a row with an unparseable day', () => {
    const out = secDayCountSeries([
      { day: 'not-a-day', count: 1 },
      { day: '2026-10-26', count: 5 },
    ]);
    expect(out.timestamps).toHaveLength(1);
    expect(out.values).toEqual([5]);
  });

  it('handles no rows', () => {
    expect(secDayCountSeries(undefined)).toEqual({ timestamps: [], values: [] });
  });
});
